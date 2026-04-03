/*
 * sudo-logger: I/O plugin for sudo that ships session recordings to a
 * remote log server via a local shipper daemon.
 *
 * Architecture:
 *   plugin_open()  → connects to sudo-shipper (Unix socket), sends SESSION_START,
 *                    waits for SESSION_READY, starts background monitor thread.
 *   log_ttyin/out  → called by sudo for every I/O chunk; forwards to shipper.
 *   plugin_close() → stops monitor thread, sends SESSION_END, closes socket.
 *
 * Freeze behaviour:
 *   The background monitor thread polls ACK state every 150 ms.  If no fresh
 *   ACK has arrived within ACK_TIMEOUT_SECS, it writes the freeze banner to
 *   /dev/tty.  The actual process freeze is performed by sudo-shipper via
 *   cgroup.freeze=1 on the kernel side — the plugin only shows the banner.
 *
 * Build:  see Makefile (or rpm/sudo-logger-client.spec)
 * Install: copy .so to /usr/libexec/sudo/, add Plugin line to /etc/sudo.conf
 */

#include <sudo_plugin.h>

#include <arpa/inet.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <syslog.h>

/* CLONE_NEWCGROUP: enter a new cgroup namespace (Linux 4.6+, <sched.h>/_GNU_SOURCE).
 * Defined here directly to avoid pulling in _GNU_SOURCE globally, which can
 * conflict with sudo_plugin.h and other system headers. */
#ifndef CLONE_NEWCGROUP
#define CLONE_NEWCGROUP 0x02000000
#endif

/* ---------- tunables ---------- */
#define SHIPPER_SOCK_PATH    "/run/sudo-logger/plugin.sock"
#define ACK_TIMEOUT_SECS     2
#define ACK_REFRESH_SECS     0      /* re-query shipper on every check */
#define ACK_QUERY_TIMEOUT_MS 100    /* max wait for ACK_RESPONSE */

/* ---------- wire protocol (shared with Go) ---------- */
#define MSG_SESSION_START  0x01
#define MSG_CHUNK          0x02
#define MSG_SESSION_END    0x03
#define MSG_ACK_QUERY      0x05
#define MSG_ACK_RESPONSE   0x06
#define MSG_SESSION_READY  0x07
#define MSG_SESSION_ERROR  0x08

#define STREAM_STDIN   0x00
#define STREAM_STDOUT  0x01
#define STREAM_STDERR  0x02
#define STREAM_TTYIN   0x03
#define STREAM_TTYOUT  0x04

/* ---------- freeze warning written to /dev/tty ---------- */
#define FREEZE_MSG \
    "\r\n\033[41;97;1m[ SUDO-LOGGER: log server unreachable — input frozen ]\033[0m\r\n" \
    "\033[33mWaiting for log server to come back...\033[0m\r\n"
#define UNFREEZE_MSG \
    "\r\n\033[42;97;1m[ SUDO-LOGGER: log server reconnected — input resumed ]\033[0m\r\n"
#define BLOCKED_HDR \
    "\r\n\033[41;97;1m[ SUDO-LOGGER: cannot reach log server — sudo blocked ]\033[0m\r\n" \
    "\033[33m"
#define BLOCKED_TAIL \
    "\033[0m\r\n"
#define TERMINATE_MSG \
    "\r\n\033[41;97;1m[ SUDO-LOGGER: shipper lost — session terminated ]\033[0m\r\n"

/* ---------- plugin globals ---------- */
static sudo_printf_t g_printf;
static int           g_shipper_fd = -1;
static int           g_tty_fd     = -1;
static char          g_session_id[320];
static uint64_t      g_seq        = 0;

/* ACK cache */
static time_t g_last_ack_time  = 0;  /* when we last received a valid ACK */
static time_t g_last_ack_query = 0;  /* when we last queried the shipper */

/* Background monitor thread */
static _Atomic int    g_monitor_stop  = 0;
static _Atomic int    g_shipper_dead  = 0;  /* set when socket drops; triggers session termination */
static int            g_monitor_started = 0;
static pthread_t      g_monitor_thread;
static pthread_mutex_t g_ack_mu       = PTHREAD_MUTEX_INITIALIZER;

/* ---------- helpers ---------- */

static int64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (int64_t)ts.tv_sec * 1000000000LL + (int64_t)ts.tv_nsec;
}

static time_t now_sec(void)
{
    return time(NULL);
}

/*
 * Write a framed message to fd.
 * Frame: [1 byte type][4 bytes payload-length BE][payload]
 */
static int send_msg(int fd, uint8_t type, const void *payload, uint32_t plen)
{
    if (fd < 0)
        return -1;

    uint8_t hdr[5];
    hdr[0] = type;
    uint32_t be = htobe32(plen);
    memcpy(hdr + 1, &be, 4);

    struct iovec iov[2];
    iov[0].iov_base = hdr;
    iov[0].iov_len  = 5;

    if (plen > 0) {
        iov[1].iov_base = (void *)payload;
        iov[1].iov_len  = plen;
        if (writev(fd, iov, 2) < 0) {
            if (errno == EPIPE || errno == ECONNRESET)
                atomic_store(&g_shipper_dead, 1);
            return -1;
        }
        return 0;
    }
    if (write(fd, hdr, 5) < 0) {
        if (errno == EPIPE || errno == ECONNRESET)
            atomic_store(&g_shipper_dead, 1);
        return -1;
    }
    return 0;
}

/*
 * Read exactly n bytes from fd. Returns -1 on error/EOF.
 */
static int read_exact(int fd, void *buf, size_t n)
{
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, (char *)buf + got, n - got);
        if (r <= 0) {
            if (r == 0)  /* EOF: peer closed connection */
                atomic_store(&g_shipper_dead, 1);
            return -1;
        }
        got += (size_t)r;
    }
    return 0;
}

/*
 * Connect to shipper Unix socket. Returns fd or -1.
 */
static int connect_shipper(void)
{
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SHIPPER_SOCK_PATH, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/*
 * Query shipper for ACK state. Updates g_last_ack_time if fresh ACK found.
 * Uses a short select() timeout to avoid blocking the terminal.
 */
static void refresh_ack_cache(void)
{
    if (g_shipper_fd < 0)
        return;

    if (send_msg(g_shipper_fd, MSG_ACK_QUERY, NULL, 0) < 0)
        return;

    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(g_shipper_fd, &rfds);
    struct timeval tv = {
        .tv_sec  = 0,
        .tv_usec = ACK_QUERY_TIMEOUT_MS * 1000,
    };

    if (select(g_shipper_fd + 1, &rfds, NULL, NULL, &tv) <= 0)
        return;

    uint8_t hdr[5];
    if (read_exact(g_shipper_fd, hdr, 5) < 0)
        return;
    if (hdr[0] != MSG_ACK_RESPONSE)
        return;

    uint32_t plen;
    memcpy(&plen, hdr + 1, 4);
    plen = be32toh(plen);
    if (plen < 16) {
        /* Drain undersized payload to keep the socket in sync. */
        uint8_t drain[16];
        if (plen > 0)
            read_exact(g_shipper_fd, drain, plen);
        return;
    }

    /* Payload: [8 bytes last_ack_ts_ns BE][8 bytes last_seq BE] */
    uint8_t payload[16];
    if (read_exact(g_shipper_fd, payload, 16) < 0)
        return;
    /* Drain any extra bytes beyond the 16 we consumed. */
    for (uint32_t rem = plen - 16; rem > 0; ) {
        uint8_t discard[64];
        uint32_t n = rem < (uint32_t)sizeof(discard) ? rem : (uint32_t)sizeof(discard);
        if (read_exact(g_shipper_fd, discard, (size_t)n) < 0)
            return;
        rem -= n;
    }

    int64_t last_ack_ts_ns;
    memcpy(&last_ack_ts_ns, payload, 8);
    last_ack_ts_ns = (int64_t)be64toh((uint64_t)last_ack_ts_ns);

    /* ts=0 means shipper explicitly reports dead connection — force stale.
     * Any positive value means server is alive; update the cache. */
    if (last_ack_ts_ns > 0) {
        g_last_ack_time = (time_t)(last_ack_ts_ns / 1000000000LL);
    } else {
        g_last_ack_time = 0;
    }
    g_last_ack_query = now_sec();
}

/*
 * Returns 1 if ACK is fresh enough to allow input, 0 to freeze.
 */
static int ack_is_fresh(void)
{
    time_t now = now_sec();

    if (now - g_last_ack_query >= ACK_REFRESH_SECS)
        refresh_ack_cache();

    /* g_last_ack_time == 0 means shipper signalled dead connection */
    if (g_last_ack_time == 0)
        return 0;

    return (now - g_last_ack_time) <= ACK_TIMEOUT_SECS;
}


/*
 * Thread-safe wrapper around ack_is_fresh().
 * Both log_ttyin and the monitor thread call this; the mutex ensures
 * the shared shipper socket is not used concurrently.
 */
static int ack_is_fresh_locked(void)
{
    pthread_mutex_lock(&g_ack_mu);
    int fresh = ack_is_fresh();
    pthread_mutex_unlock(&g_ack_mu);
    return fresh;
}

/*
 * Background monitor thread.
 *
 * Polls ACK state every 150 ms.  On freeze, sets g_frozen (which makes
 * log_ttyin drop keyboard input) and writes the freeze banner directly to
 * the tty.
 *
 * We deliberately do NOT send SIGSTOP.  SIGSTOP triggers the kernel's job-
 * control machinery: the shell receives SIGCHLD with CLD_STOPPED, prints
 * "[1]+ Stopped", and reclaims the terminal — making g_tty_fd inaccessible
 * for writes and forcing the user to use "fg" to see anything.
 *
 * Instead we rely on the shipper's cgroup freeze (cgroup.freeze = 1), which
 * suspends the process without changing its job-control state.  The session
 * stays in the foreground, and the banner can be written immediately.
 */
static void *monitor_thread_fn(void *arg)
{
    (void)arg;

    int was_frozen = 0;

    while (!g_monitor_stop) {
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 150000000L };
        nanosleep(&ts, NULL);

        if (g_monitor_stop)
            break;

        int fresh = ack_is_fresh_locked();

        /* Shipper socket dropped — terminate the session immediately.
         * kill(getpid(), SIGTERM) sends SIGTERM to sudo, which cleans up
         * and sends SIGHUP to the child (bash), ending the session. */
        if (atomic_load(&g_shipper_dead)) {
            if (g_tty_fd >= 0)
                write(g_tty_fd, TERMINATE_MSG, sizeof(TERMINATE_MSG) - 1);
            kill(getpid(), SIGTERM);
            return NULL;
        }

        if (!fresh && !was_frozen) {
            if (g_tty_fd >= 0)
                write(g_tty_fd, FREEZE_MSG, sizeof(FREEZE_MSG) - 1);
            was_frozen = 1;
        } else if (fresh && was_frozen) {
            if (g_tty_fd >= 0)
                write(g_tty_fd, UNFREEZE_MSG, sizeof(UNFREEZE_MSG) - 1);
            was_frozen = 0;
        }

        /*
         * Terminal-reclaim: while the session is frozen, sudo may hand the
         * terminal foreground to the child (bash) via tcsetpgrp() — e.g. when
         * the user does "fg" after being placed in background by a previous
         * SIGSTOP.  Since the child cgroup is frozen, Ctrl+C/Z signals sent to
         * the child's pgrp are queued but never delivered, leaving the user
         * completely trapped.
         *
         * Fix: every 150 ms when frozen, check whether a child has become the
         * terminal foreground.  If so, reclaim the terminal back to sudo's
         * pgrp.  Block SIGTTOU in this thread only (pthread_sigmask is
         * per-thread) so the tcsetpgrp() call does not stop the sudo process.
         */
        if (!fresh && g_tty_fd >= 0) {
            pid_t fg_pgrp  = tcgetpgrp(g_tty_fd);
            pid_t our_pgrp = getpgrp();
            if (fg_pgrp > 0 && fg_pgrp != (pid_t)-1 && fg_pgrp != our_pgrp) {
                sigset_t block, old;
                sigemptyset(&block);
                sigaddset(&block, SIGTTOU);
                pthread_sigmask(SIG_BLOCK, &block, &old);
                if (tcsetpgrp(g_tty_fd, our_pgrp) == 0)
                    write(g_tty_fd, FREEZE_MSG, sizeof(FREEZE_MSG) - 1);
                pthread_sigmask(SIG_SETMASK, &old, NULL);
            }
        }
    }

    return NULL;
}

/*
 * Build and send a CHUNK message.
 * Payload: [8 seq BE][8 ts_ns BE][1 stream][4 datalen BE][data]
 */
static void ship_chunk(uint8_t stream, const char *data, unsigned int dlen)
{
    if (g_shipper_fd < 0 || dlen == 0)
        return;

    size_t plen = 8 + 8 + 1 + 4 + dlen;
    uint8_t *p = malloc(plen);
    if (!p)
        return;

    uint64_t seq_be = htobe64(++g_seq);
    int64_t  ts_be  = (int64_t)htobe64((uint64_t)now_ns());
    uint32_t dl_be  = htobe32(dlen);

    memcpy(p,      &seq_be, 8);
    memcpy(p + 8,  &ts_be,  8);
    p[16] = stream;
    memcpy(p + 17, &dl_be,  4);
    memcpy(p + 21, data,    dlen);

    send_msg(g_shipper_fd, MSG_CHUNK, p, (uint32_t)plen);
    free(p);
}

/* ---------- helpers ---------- */

/*
 * json_escape_into — writes a JSON-escaped copy of src into buf[0..bufsz-1].
 * Result is always NUL-terminated.
 */
static void json_escape_into(char *buf, size_t bufsz, const char *src)
{
    size_t pos = 0;
    for (const char *p = src; *p && pos + 2 < bufsz; p++) {
        unsigned char c = (unsigned char)*p;
        if (c == '\\' || c == '"') {
            buf[pos++] = '\\';
            buf[pos++] = (char)c;
        } else if (c < 0x20) {
            if (pos + 6 < bufsz)
                pos += (size_t)snprintf(buf + pos, bufsz - pos, "\\u%04x", c);
        } else {
            buf[pos++] = (char)c;
        }
    }
    if (pos < bufsz) buf[pos] = '\0';
}

/*
 * build_cmdline_json — writes a JSON-safe, space-joined argv string into buf.
 *
 * Characters that are illegal inside a JSON string (backslash, double-quote,
 * and ASCII control characters) are escaped.  The result is NUL-terminated
 * and truncated to fit within bufsz bytes (including the NUL).
 */
static void build_cmdline_json(char *buf, size_t bufsz,
                               int argc, char * const argv[])
{
    if (bufsz == 0)
        return;

    size_t pos = 0;
    for (int i = 0; i < argc && pos + 1 < bufsz; i++) {
        if (i > 0 && pos + 1 < bufsz)
            buf[pos++] = ' ';

        for (const char *p = argv[i]; *p && pos + 2 < bufsz; p++) {
            unsigned char c = (unsigned char)*p;
            if (c == '\\' || c == '"') {
                buf[pos++] = '\\';
                buf[pos++] = (char)c;
            } else if (c < 0x20) {
                /* Escape control characters as \uXXXX — needs 6 bytes */
                if (pos + 6 < bufsz) {
                    pos += (size_t)snprintf(buf + pos, bufsz - pos,
                                            "\\u%04x", c);
                }
            } else {
                buf[pos++] = (char)c;
            }
        }
    }
    buf[pos] = '\0';
}

/* ---------- plugin API ---------- */

/*
 * plugin_open — called once per sudo invocation before the command runs.
 *
 * Responsibilities:
 *   1. Open /dev/tty for banner output (non-blocking; failure is non-fatal).
 *   2. Build a unique session ID from host + user + pid + nanosecond timestamp.
 *   3. Connect to sudo-shipper via Unix socket and send SESSION_START.
 *   4. Block until shipper replies SESSION_READY (server reachable) or
 *      SESSION_ERROR (server unreachable) — sudo is blocked during this wait.
 *   5. Start the background monitor thread that polls ACK state every 150 ms
 *      and writes freeze/unfreeze banners to /dev/tty.
 *
 * Returns 1 on success, -1 on any error (blocks the sudo command).
 *
 * Thread safety: called in the sudo main thread before any child is forked;
 *   no concurrent access to globals at this point.
 */
static int plugin_open(unsigned int        version,
                       sudo_conv_t         conversation,
                       sudo_printf_t       sudo_plugin_printf,
                       char * const        settings[],
                       char * const        user_info[],
                       char * const        command_info[],
                       int                 argc,
                       char * const        argv[],
                       char * const        user_env[],
                       char * const        plugin_options[],
                       const char        **errstr)
{
    (void)version; (void)conversation;
    (void)user_env; (void)plugin_options;

    g_printf  = sudo_plugin_printf;
    g_seq     = 0;
    g_last_ack_time  = 0;
    g_last_ack_query = 0;
    atomic_store(&g_shipper_dead, 0);

    g_tty_fd = open("/dev/tty", O_WRONLY | O_NOCTTY | O_CLOEXEC);

    const char *user    = "unknown";
    const char *host    = "unknown";
    const char *raw_cwd = "/";   /* user_info[cwd] = the invoking user's cwd */
    for (int i = 0; user_info[i] != NULL; i++) {
        if      (strncmp(user_info[i], "user=", 5) == 0)
            user = user_info[i] + 5;
        else if (strncmp(user_info[i], "host=", 5) == 0)
            host = user_info[i] + 5;
        else if (strncmp(user_info[i], "cwd=",  4) == 0)
            raw_cwd = user_info[i] + 4;
    }

    /* ── Extract metadata from command_info[] ─────────────────────────── */
    const char *raw_resolved = "";
    int         runas_uid    = 0;
    int         runas_gid    = 0;
    for (int i = 0; command_info[i] != NULL; i++) {
        if      (strncmp(command_info[i], "command=",   8) == 0)
            raw_resolved = command_info[i] + 8;
        else if (strncmp(command_info[i], "runas_uid=", 10) == 0)
            runas_uid = (int)strtol(command_info[i] + 10, NULL, 10);
        else if (strncmp(command_info[i], "runas_gid=", 10) == 0)
            runas_gid = (int)strtol(command_info[i] + 10, NULL, 10);
    }

    /* ── Extract metadata from settings[] ───────────────────────────────
     * runas_user is only present when -u was given; defaults to "root".
     * Boolean flags are accumulated into a comma-separated string.        */
    const char *runas_user = "root";
    char        flags[128] = "";
    for (int i = 0; settings[i] != NULL; i++) {
        if      (strncmp(settings[i], "runas_user=",  11) == 0)
            runas_user = settings[i] + 11;
        else if (strcmp(settings[i],  "login_shell=true")          == 0)
            strncat(flags, "login_shell,",   sizeof(flags) - strlen(flags) - 1);
        else if (strcmp(settings[i],  "preserve_environment=true") == 0)
            strncat(flags, "preserve_env,",  sizeof(flags) - strlen(flags) - 1);
        else if (strcmp(settings[i],  "implied_shell=true")        == 0)
            strncat(flags, "implied_shell,", sizeof(flags) - strlen(flags) - 1);
    }
    /* Strip trailing comma */
    size_t flen = strlen(flags);
    if (flen > 0 && flags[flen - 1] == ',')
        flags[flen - 1] = '\0';

    /* JSON-escape fields that may contain backslashes, quotes, or spaces */
    char resolved_j[512];
    char cwd_j[512];
    char runas_user_j[128];
    json_escape_into(resolved_j,   sizeof(resolved_j),   raw_resolved);
    json_escape_into(cwd_j,        sizeof(cwd_j),        raw_cwd);
    json_escape_into(runas_user_j, sizeof(runas_user_j), runas_user);

    char cmd[256];
    if (argc > 0)
        build_cmdline_json(cmd, sizeof(cmd), argc, argv);
    else
        strncpy(cmd, "unknown", sizeof(cmd));

    /* Add 4 random bytes so two simultaneous sudo invocations from the same
     * user on the same host within the same nanosecond still get distinct IDs. */
    uint8_t rnd[4] = {0};
    int rfd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (rfd >= 0) {
        (void)read(rfd, rnd, sizeof(rnd));
        close(rfd);
    }
    snprintf(g_session_id, sizeof(g_session_id),
             "%s-%s-%d-%lld-%02x%02x%02x%02x",
             host, user, (int)getpid(), (long long)now_ns(),
             rnd[0], rnd[1], rnd[2], rnd[3]);

    g_shipper_fd = connect_shipper();
    if (g_shipper_fd < 0) {
        *errstr = "sudo-logger: cannot connect to shipper daemon "
                  "(is sudo-shipper running?)";
        return -1;
    }

    /* Prevent sudo from hanging indefinitely if the shipper stalls during
     * the TLS handshake with the remote server.  30 s is generous; the
     * shipper normally responds within a few hundred milliseconds. */
    struct timeval rcv_timeout = { .tv_sec = 30, .tv_usec = 0 };
    setsockopt(g_shipper_fd, SOL_SOCKET, SO_RCVTIMEO,
               &rcv_timeout, sizeof(rcv_timeout));

    char payload[2048];
    int plen = snprintf(payload, sizeof(payload),
        "{\"session_id\":\"%s\",\"user\":\"%s\",\"host\":\"%s\","
        "\"command\":\"%s\","
        "\"resolved_command\":\"%s\",\"runas_user\":\"%s\","
        "\"runas_uid\":%d,\"runas_gid\":%d,"
        "\"cwd\":\"%s\",\"flags\":\"%s\","
        "\"ts\":%lld,\"pid\":%d}",
        g_session_id, user, host, cmd,
        resolved_j, runas_user_j,
        runas_uid, runas_gid,
        cwd_j, flags,
        (long long)now_sec(), (int)getpid());

    /* snprintf returns the number of bytes that *would* have been written,
     * which may exceed sizeof(payload) if the input was truncated.
     * Cap to the actual number of bytes written to avoid over-reading the
     * stack buffer in send_msg/writev. */
    if (plen < 0)
        plen = 0;
    else if (plen >= (int)sizeof(payload))
        plen = (int)sizeof(payload) - 1;

    send_msg(g_shipper_fd, MSG_SESSION_START, payload, (uint32_t)plen);

    /* Wait for shipper to confirm server connection before allowing sudo */
    uint8_t hdr[5];
    if (read_exact(g_shipper_fd, hdr, 5) < 0) {
        *errstr = "sudo-logger: no response from shipper";
        return -1;
    }

    if (hdr[0] == MSG_SESSION_ERROR) {
        /* Read error message for logging, then block sudo */
        uint32_t elen;
        memcpy(&elen, hdr + 1, 4);
        elen = be32toh(elen);
        if (elen > 0 && elen < 512) {
            char errbuf[512] = {0};
            read_exact(g_shipper_fd, errbuf, elen);
            if (g_tty_fd >= 0) {
                write(g_tty_fd, BLOCKED_HDR,  sizeof(BLOCKED_HDR)  - 1);
                write(g_tty_fd, errbuf, elen);
                write(g_tty_fd, BLOCKED_TAIL, sizeof(BLOCKED_TAIL) - 1);
            } else {
                g_printf(SUDO_CONV_ERROR_MSG,
                    "sudo-logger: cannot reach log server: %s\n", errbuf);
            }
        }
        *errstr = "sudo-logger: log server unreachable — sudo blocked";
        return -1;
    }

    if (hdr[0] != MSG_SESSION_READY) {
        *errstr = "sudo-logger: unexpected response from shipper";
        return -1;
    }

    g_last_ack_query = now_sec();
    /* Seed ack time so the freeze window starts from now */
    g_last_ack_time = now_sec();

    /* Isolate the session in a cgroup namespace so child processes cannot
     * escape the session freeze by migrating to a cgroup outside our
     * delegated subtree — even if they hold CAP_SYS_ADMIN.
     *
     * After unshare(CLONE_NEWCGROUP), /sys/fs/cgroup appears to all children
     * of this process as a private tree rooted at the session cgroup that the
     * shipper just placed us in (SESSION_READY is the synchronisation point).
     * An attempt to write a PID to /sys/fs/cgroup/../../escape/cgroup.procs
     * resolves only within that subtree and fails with ENOENT.
     *
     * The shipper itself remains in the host cgroup namespace and continues
     * to read and write cgroup.freeze / cgroup.procs via the full host path.
     * The existing socket connection (g_shipper_fd) is unaffected: sockets
     * are not part of the cgroup namespace.
     *
     * CAP_SYS_ADMIN is required; sudo always runs with full capabilities.
     * Non-fatal: if the call fails the session continues without namespace
     * isolation and a warning is written to syslog. */
    if (syscall(SYS_unshare, CLONE_NEWCGROUP) != 0) {
        syslog(LOG_WARNING,
               "sudo-logger: cgroup namespace isolation failed (%s) -- "
               "session proceeds without cgroup namespace protection",
               strerror(errno));
    }

    /* Start background monitor thread. */
    g_monitor_stop  = 0;
    g_monitor_started = (pthread_create(&g_monitor_thread, NULL,
                                        monitor_thread_fn, NULL) == 0);

    return 1;
}

/*
 * plugin_close — called by sudo when the session ends (command exits or
 *   is killed).
 *
 * Stops the monitor thread (pthread_join guarantees it has exited before
 * g_tty_fd is closed — no race on the tty fd), sends SESSION_END with the
 * exit code, and closes the shipper socket and /dev/tty.
 */
static void plugin_close(int exit_status, int error)
{
    (void)error;

    /* Stop the background monitor thread before closing the shipper socket. */
    if (g_monitor_started) {
        g_monitor_stop = 1;
        pthread_join(g_monitor_thread, NULL);
        g_monitor_started = 0;
    }

    if (g_shipper_fd >= 0) {
        uint8_t payload[12];
        uint64_t seq_be  = htobe64(g_seq);
        int32_t  code_be = (int32_t)htobe32((uint32_t)exit_status);
        memcpy(payload,     &seq_be,  8);
        memcpy(payload + 8, &code_be, 4);
        send_msg(g_shipper_fd, MSG_SESSION_END, payload, 12);
        close(g_shipper_fd);
        g_shipper_fd = -1;
    }

    if (g_tty_fd >= 0) {
        close(g_tty_fd);
        g_tty_fd = -1;
    }
}

/*
 * log_ttyin — called for every byte typed by the user (terminal → child).
 *
 * Always returns 1 (pass the input through to the child).  Freeze enforcement
 * is handled entirely by cgroup.freeze in sudo-shipper.  Returning 0 would
 * permanently disable this hook rather than drop a single byte, and caused
 * sudo to send SIGHUP to the session on the first keypress.
 *
 * Input typed during a freeze is buffered in the pty; bash cannot process it
 * until the cgroup unfreezes.
 */
static int log_ttyin(const char *buf, unsigned int len, const char **errstr)
{
    (void)errstr;
    if (atomic_load(&g_shipper_dead))
        return 0;
    ship_chunk(STREAM_TTYIN, buf, len);
    return 1;
}

/* log_ttyout — called for every byte written to the terminal by the child. */
static int log_ttyout(const char *buf, unsigned int len, const char **errstr)
{
    (void)errstr;
    if (atomic_load(&g_shipper_dead))
        return 0;
    ship_chunk(STREAM_TTYOUT, buf, len);
    return 1;
}

/* log_stdin — called for non-tty standard input (piped commands, heredocs). */
static int log_stdin(const char *buf, unsigned int len, const char **errstr)
{
    (void)errstr;
    if (atomic_load(&g_shipper_dead))
        return 0;
    ship_chunk(STREAM_STDIN, buf, len);
    return 1;
}

/* log_stdout — called for non-tty standard output. */
static int log_stdout(const char *buf, unsigned int len, const char **errstr)
{
    (void)errstr;
    if (atomic_load(&g_shipper_dead))
        return 0;
    ship_chunk(STREAM_STDOUT, buf, len);
    return 1;
}

/* log_stderr — called for standard error output. */
static int log_stderr(const char *buf, unsigned int len, const char **errstr)
{
    (void)errstr;
    if (atomic_load(&g_shipper_dead))
        return 0;
    ship_chunk(STREAM_STDERR, buf, len);
    return 1;
}

/* show_version — called by "sudo -V"; prints the plugin version. */
static int show_version(int verbose)
{
    (void)verbose;
    g_printf(SUDO_CONV_INFO_MSG, "sudo-logger plugin v1.0\n");
    return 1;
}

/* ---------- exported plugin struct ---------- */

__attribute__((visibility("default")))
struct io_plugin sudo_logger_plugin = {
    .type         = SUDO_IO_PLUGIN,
    .version      = SUDO_API_VERSION,
    .open         = plugin_open,
    .close        = plugin_close,
    .show_version = show_version,
    .log_ttyin    = log_ttyin,
    .log_ttyout   = log_ttyout,
    .log_stdin    = log_stdin,
    .log_stdout   = log_stdout,
    .log_stderr   = log_stderr,
};
