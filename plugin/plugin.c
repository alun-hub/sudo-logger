/*
 * sudo-logger: I/O plugin for sudo that ships session recordings to a
 * remote log server via a local agent daemon.
 *
 * Architecture:
 *   plugin_open()  → connects to sudo-logger-agent (Unix socket), sends SESSION_START,
 *                    waits for SESSION_READY, starts background monitor thread.
 *   log_ttyin/out  → called by sudo for every I/O chunk; forwards to agent.
 *   plugin_close() → stops monitor thread, sends SESSION_END, closes socket.
 *
 * Freeze behaviour:
 *   The background monitor thread polls ACK state every 150 ms.  If no fresh
 *   ACK has arrived within ACK_TIMEOUT_SECS, it writes the freeze banner to
 *   /dev/tty.  The actual process freeze is performed by sudo-logger-agent via
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
#include <sys/un.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>

/* Set by the Makefile/RPM spec via -DPLUGIN_VERSION="X.Y.Z"; falls back to
 * "dev" for ad-hoc builds (e.g. `gcc plugin.c` outside the build system). */
#ifndef PLUGIN_VERSION
#define PLUGIN_VERSION "dev"
#endif
#include <sys/syscall.h>
#include <syslog.h>

/* CLONE_NEWCGROUP: enter a new cgroup namespace (Linux 4.6+, <sched.h>/_GNU_SOURCE).
 * Defined here directly to avoid pulling in _GNU_SOURCE globally, which can
 * conflict with sudo_plugin.h and other system headers. */
#ifndef CLONE_NEWCGROUP
#define CLONE_NEWCGROUP 0x02000000
#endif

/* ---------- tunables ---------- */
#define AGENT_SOCK_PATH    "/run/sudo-logger/plugin.sock"
#define ACK_TIMEOUT_SECS     2
#define ACK_REFRESH_SECS     0      /* re-query agent on every check */
#define ACK_QUERY_TIMEOUT_MS 100    /* max wait for ACK_RESPONSE */
/* Sanity cap on any single message payload read from the agent. Normal
 * traffic (ACK responses, control messages) is a few bytes; this only
 * guards against a malformed/hostile peer declaring an absurd length. */
#define MAX_MSG_PAYLOAD       (1u * 1024 * 1024)
/* Sanity cap on a single I/O chunk handed to us by sudo. sudo's own PTY/pipe
 * buffers are far smaller than this; guards ship_chunk()'s length arithmetic
 * against a bogus dlen on platforms where size_t is 32-bit. */
#define MAX_CHUNK_LEN         (16u * 1024 * 1024)

/* ---------- wire protocol (shared with Go) ---------- */
#define MSG_SESSION_START  0x01
#define MSG_CHUNK          0x02
#define MSG_SESSION_END    0x03
#define MSG_ACK_QUERY      0x05
#define MSG_ACK_RESPONSE   0x06
#define MSG_SESSION_READY  0x07
#define MSG_SESSION_ERROR  0x08
#define MSG_SESSION_DENIED 0x0c
#define MSG_FREEZE_TIMEOUT 0x0d
#define MSG_SESSION_CHALLENGE 0x14
#define MSG_SESSION_CHALLENGE_RESPONSE 0x15
#define MSG_SESSION_EXPIRED 0x16
#define MSG_SESSION_WARNING 0x17
#define MSG_RESIZE         0x1b /* plugin→agent→server: terminal resize; payload = ts_ns(8BE)+cols(2BE)+rows(2BE) */

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
#define DENIED_HDR \
    "\r\n\033[41;97;1m[ SUDO-LOGGER: ACCESS BLOCKED BY SECURITY POLICY ]\033[0m\r\n" \
    "\033[33m"
#define BLOCKED_TAIL \
    "\033[0m\r\n"
#define TERMINATE_MSG \
    "\r\n\033[41;97;1m[ SUDO-LOGGER: agent lost — session terminated ]\033[0m\r\n"
#define TIMEOUT_MSG \
    "\r\n\033[41;97;1m[ SUDO-LOGGER: gave up waiting for log server — session terminated ]\033[0m\r\n"
#define EXPIRED_MSG \
    "\r\n\033[43;30;1m[ SUDO-LOGGER: approval window expired — session terminated ]\033[0m\r\n"
#define WARN_MSG_START \
    "\r\n\033[43;30;1m[ SUDO-LOGGER: approval window expires in "
#define WARN_MSG_END \
    " seconds ]\033[0m\r\n"

/* ---------- plugin globals ---------- */
static sudo_printf_t g_printf;
static int           g_agent_fd = -1;
static int           g_tty_fd     = -1;
static char          g_tty_path[64] = "";  /* actual device path, e.g. /dev/pts/3 */
static char          g_session_id[320];
static uint64_t      g_seq        = 0;

/* ACK cache */
static time_t g_last_ack_time  = 0;  /* when we last received a valid ACK */
static time_t g_last_ack_query = 0;  /* when we last queried the agent */

/* Terminal dimensions — updated by TIOCGWINSZ polling in the monitor thread.
 * Ownership handoff: written once by the main thread in plugin_open() before
 * the monitor thread is started, then owned exclusively by the monitor
 * thread afterwards. No concurrent access; no lock needed. */
static int g_term_cols = 0;
static int g_term_rows = 0;

/* Background monitor thread */
static _Atomic int    g_monitor_stop   = 0;
static _Atomic int    g_agent_dead   = 0;  /* set when socket drops; triggers session termination */
static _Atomic int    g_freeze_timeout = 0;  /* set when agent sends MSG_FREEZE_TIMEOUT */
static _Atomic int    g_session_expired = 0; /* set when agent sends MSG_SESSION_EXPIRED */
static int            g_monitor_started = 0;
static pthread_t      g_monitor_thread;
static pthread_mutex_t g_ack_mu       = PTHREAD_MUTEX_INITIALIZER;
/* Serialises concurrent writes to g_agent_fd (main thread vs monitor thread). */
static pthread_mutex_t g_send_mu      = PTHREAD_MUTEX_INITIALIZER;

/* ---------- helpers ---------- */

/*
 * Write exactly n bytes to fd, retrying on EINTR and partial writes.
 */
static int write_all(int fd, const void *buf, size_t n)
{
    size_t sent = 0;
    while (sent < n) {
        ssize_t w = write(fd, (const char *)buf + sent, n - sent);
        if (w < 0) {
            if (errno == EINTR) continue;
            if (errno == EPIPE || errno == ECONNRESET)
                atomic_store(&g_agent_dead, 1);
            return -1;
        }
        sent += (size_t)w;
    }
    return 0;
}

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

    if (write_all(fd, hdr, 5) < 0)
        return -1;
    if (plen > 0 && write_all(fd, payload, plen) < 0)
        return -1;
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
                atomic_store(&g_agent_dead, 1);
            return -1;
        }
        got += (size_t)r;
    }
    return 0;
}

/*
 * Read and discard exactly n bytes from fd, in bounded chunks.
 * Used to keep the framed wire protocol in sync when a message's payload
 * is not needed, or exceeds a fixed-size stack buffer.
 */
static int drain_payload(int fd, uint32_t n)
{
    uint8_t discard[64];
    while (n > 0) {
        uint32_t chunk = n < (uint32_t)sizeof(discard) ? n : (uint32_t)sizeof(discard);
        if (read_exact(fd, discard, chunk) < 0)
            return -1;
        n -= chunk;
    }
    return 0;
}

static void safe_write_tty(int fd, const char *buf, size_t len)
{
    size_t i = 0;
    while (i < len) {
        if (buf[i] == 0x1b) { // ESC
            if (i + 1 < len && buf[i+1] == '[') {
                size_t j = i + 2;
                while (j < len && ((buf[j] >= '0' && buf[j] <= '9') || buf[j] == ';')) {
                    j++;
                }
                if (j < len && buf[j] == 'm') {
                    write(fd, &buf[i], j - i + 1);
                    i = j + 1;
                    continue;
                }
            }
            write(fd, "^[", 2);
            i++;
        } else {
            write(fd, &buf[i], 1);
            i++;
        }
    }
}

static void sanitize_id_part(char *dst, const char *src, size_t maxlen)
{
    if (maxlen == 0) return;
    size_t i = 0;
    for (i = 0; src[i] != '\0' && i < maxlen - 1; i++) {
        char c = src[i];
        if ((c >= 'a' && c <= 'z') ||
            (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') ||
            c == '.' || c == '_' || c == '-') {
            dst[i] = c;
        } else {
            dst[i] = '-';
        }
    }
    dst[i] = '\0';
}

/*
 * Connect to agent Unix socket. Returns fd or -1.
 */
static int connect_agent(void)
{
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, AGENT_SOCK_PATH, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

#ifdef __linux__
    struct ucred cred;
    socklen_t len = sizeof(struct ucred);
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) < 0) {
        close(fd);
        return -1;
    }
    if (cred.uid != 0) {
        close(fd);
        return -1;
    }
#endif

    return fd;
}

/*
 * Query agent for ACK state. Updates g_last_ack_time if fresh ACK found.
 * Uses a short select() timeout to avoid blocking the terminal.
 */
static void refresh_ack_cache(void)
{
    if (g_agent_fd < 0)
        return;

    /*
     * Drain all pending unsolicited messages from the agent before sending
     * ACK_QUERY.  Must loop until the socket has no more data; a single drain
     * would leave subsequent messages in the buffer and cause the ACK_RESPONSE
     * read below to misparse the stream.
     */
    {
        fd_set rfds;
        struct timeval tv;
        for (;;) {
            FD_ZERO(&rfds);
            FD_SET(g_agent_fd, &rfds);
            tv.tv_sec  = 0;
            tv.tv_usec = 0;
            if (select(g_agent_fd + 1, &rfds, NULL, NULL, &tv) <= 0)
                break;
            uint8_t hdr[5];
            if (read_exact(g_agent_fd, hdr, 5) != 0)
                return;
            uint32_t plen;
            memcpy(&plen, hdr + 1, 4);
            plen = be32toh(plen);
            if (plen > MAX_MSG_PAYLOAD) {
                /* Malformed/hostile length — the framed stream can no
                 * longer be trusted; stop trying to parse it. */
                atomic_store(&g_agent_dead, 1);
                return;
            }
            if (hdr[0] == MSG_FREEZE_TIMEOUT)
                atomic_store(&g_freeze_timeout, 1);
            if (hdr[0] == MSG_SESSION_EXPIRED)
                atomic_store(&g_session_expired, 1);

            if (hdr[0] == MSG_SESSION_WARNING) {
                if (g_tty_fd >= 0) {
                    write(g_tty_fd, WARN_MSG_START, sizeof(WARN_MSG_START) - 1);
                    for (uint32_t rem = plen; rem > 0; ) {
                        uint8_t buf[64];
                        uint32_t n = rem < (uint32_t)sizeof(buf) ? rem : (uint32_t)sizeof(buf);
                        if (read_exact(g_agent_fd, buf, n) < 0) return;
                        safe_write_tty(g_tty_fd, (const char *)buf, n);
                        rem -= n;
                    }
                    write(g_tty_fd, WARN_MSG_END, sizeof(WARN_MSG_END) - 1);
                } else {
                    /* No tty — drain payload to keep protocol stream in sync. */
                    for (uint32_t rem = plen; rem > 0; ) {
                        uint8_t discard[64];
                        uint32_t n = rem < (uint32_t)sizeof(discard) ? rem : (uint32_t)sizeof(discard);
                        if (read_exact(g_agent_fd, discard, n) < 0) return;
                        rem -= n;
                    }
                }
                continue;
            }

            for (uint32_t rem = plen; rem > 0; ) {
                uint8_t drain[64];
                uint32_t n = rem < (uint32_t)sizeof(drain)
                             ? rem : (uint32_t)sizeof(drain);
                if (read_exact(g_agent_fd, drain, n) < 0)
                    return;
                rem -= n;
            }
        }
    }

    pthread_mutex_lock(&g_send_mu);
    int _rc = send_msg(g_agent_fd, MSG_ACK_QUERY, NULL, 0);
    pthread_mutex_unlock(&g_send_mu);
    if (_rc < 0)
        return;

    struct timespec deadline;
    clock_gettime(CLOCK_MONOTONIC, &deadline);
    deadline.tv_nsec += ACK_QUERY_TIMEOUT_MS * 1000000;
    if (deadline.tv_nsec >= 1000000000) {
        deadline.tv_sec += deadline.tv_nsec / 1000000000;
        deadline.tv_nsec %= 1000000000;
    }

    uint8_t hdr[5];
    uint32_t plen = 0;
    for (;;) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);

        long long diff_us = (long long)(deadline.tv_sec - now.tv_sec) * 1000000LL +
                            (deadline.tv_nsec - now.tv_nsec) / 1000LL;
        if (diff_us <= 0) {
            /* Timeout reached */
            return;
        }

        struct timeval tv;
        tv.tv_sec  = diff_us / 1000000LL;
        tv.tv_usec = diff_us % 1000000LL;

        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(g_agent_fd, &rfds);

        int s = select(g_agent_fd + 1, &rfds, NULL, NULL, &tv);
        if (s <= 0) {
            /* Timeout or select error */
            return;
        }

        if (read_exact(g_agent_fd, hdr, 5) < 0)
            return;

        memcpy(&plen, hdr + 1, 4);
        plen = be32toh(plen);
        if (plen > MAX_MSG_PAYLOAD) {
            atomic_store(&g_agent_dead, 1);
            return;
        }

        if (hdr[0] == MSG_ACK_RESPONSE) {
            break;
        }

        /* Process non-ACK_RESPONSE frame */
        if (hdr[0] == MSG_FREEZE_TIMEOUT)
            atomic_store(&g_freeze_timeout, 1);
        if (hdr[0] == MSG_SESSION_EXPIRED)
            atomic_store(&g_session_expired, 1);

        if (hdr[0] == MSG_SESSION_WARNING) {
            if (g_tty_fd >= 0) {
                write(g_tty_fd, WARN_MSG_START, sizeof(WARN_MSG_START) - 1);
                for (uint32_t rem = plen; rem > 0; ) {
                    uint8_t buf[64];
                    uint32_t n = rem < (uint32_t)sizeof(buf) ? rem : (uint32_t)sizeof(buf);
                    if (read_exact(g_agent_fd, buf, n) < 0) return;
                    safe_write_tty(g_tty_fd, (const char *)buf, n);
                    rem -= n;
                }
                write(g_tty_fd, WARN_MSG_END, sizeof(WARN_MSG_END) - 1);
            } else {
                for (uint32_t rem = plen; rem > 0; ) {
                    uint8_t discard[64];
                    uint32_t n = rem < (uint32_t)sizeof(discard) ? rem : (uint32_t)sizeof(discard);
                    if (read_exact(g_agent_fd, discard, n) < 0) return;
                    rem -= n;
                }
            }
            continue;
        }

        /* Drain payload for any other message type */
        for (uint32_t rem = plen; rem > 0; ) {
            uint8_t drain[64];
            uint32_t n = rem < (uint32_t)sizeof(drain) ? rem : (uint32_t)sizeof(drain);
            if (read_exact(g_agent_fd, drain, n) < 0)
                return;
            rem -= n;
        }
    }
    if (plen < 16) {
        /* Drain undersized payload to keep the socket in sync. */
        uint8_t drain[16];
        if (plen > 0)
            read_exact(g_agent_fd, drain, plen);
        return;
    }

    /* Payload: [8 bytes last_ack_ts_ns BE][8 bytes last_seq BE] */
    uint8_t payload[16];
    if (read_exact(g_agent_fd, payload, 16) < 0)
        return;
    /* Drain any extra bytes beyond the 16 we consumed. */
    for (uint32_t rem = plen - 16; rem > 0; ) {
        uint8_t discard[64];
        uint32_t n = rem < (uint32_t)sizeof(discard) ? rem : (uint32_t)sizeof(discard);
        if (read_exact(g_agent_fd, discard, (size_t)n) < 0)
            return;
        rem -= n;
    }

    int64_t last_ack_ts_ns;
    memcpy(&last_ack_ts_ns, payload, 8);
    last_ack_ts_ns = (int64_t)be64toh((uint64_t)last_ack_ts_ns);

    /* ts=0 means agent explicitly reports dead connection — force stale.
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

    /* ACK_REFRESH_SECS is 0 by design (re-query on every check), so this
     * condition is always true and g_last_ack_query only records the time
     * of the last query for diagnostics — it does not throttle anything. */
    if (now - g_last_ack_query >= ACK_REFRESH_SECS)
        refresh_ack_cache();

    /* g_last_ack_time == 0 means agent signalled dead connection */
    if (g_last_ack_time == 0)
        return 0;

    return (now - g_last_ack_time) <= ACK_TIMEOUT_SECS;
}


/*
 * Thread-safe wrapper around ack_is_fresh().
 * The monitor thread calls this; the mutex ensures
 * the shared agent socket is not used concurrently.
 */
static int ack_is_fresh_locked(void)
{
    pthread_mutex_lock(&g_ack_mu);
    int fresh = ack_is_fresh();
    pthread_mutex_unlock(&g_ack_mu);
    return fresh;
}

/*
 * unfreeze_session_cgroup — unfreeze the session cgroup and kill its processes.
 *
 * When the agent dies unexpectedly, cgroup.freeze=1 remains set.  PTY
 * hangup (SIGHUP) from sudo's exit is queued but never delivered to frozen
 * bash, leaving it permanently stuck.  This function:
 *   1. Writes 0 to cgroup.freeze so pending signals can be delivered.
 *   2. Writes 1 to cgroup.kill (Linux 5.14+) for instant cleanup if available.
 *
 * Path discovery: read /proc/self/cgroup to find sudo's current cgroup, then
 * derive the session sub-cgroup by appending g_session_id (or recognising
 * that sudo is still inside it when moveSudoOut has not yet been called).
 */
static void unfreeze_session_cgroup(void)
{
    if (!g_session_id[0])
        return;

    /* Find sudo's current cgroup v2 path ("0::<relpath>"). */
    FILE *f = fopen("/proc/self/cgroup", "r");
    if (!f)
        return;

    char line[512];
    char parent[512] = "";
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "0::/", 4) != 0)
            continue;
        char *nl = strchr(line, '\n');
        if (nl)
            *nl = '\0';
        if (snprintf(parent, sizeof(parent), "/sys/fs/cgroup%s", line + 3) >=
            (int)sizeof(parent))
            parent[0] = '\0';
        break;
    }
    fclose(f);
    if (!parent[0])
        return;

    /*
     * Two cases:
     *   A) sudo was moved to parent cgroup — parent ends with the agent's
     *      base dir, and g_session_id is a sub-directory of it.
     *   B) sudo is still in the session cgroup (moveSudoOut not yet called) —
     *      parent itself ends with g_session_id.
     */
    char session_cg[640];
    size_t plen  = strlen(parent);
    size_t idlen = strlen(g_session_id);
    if (plen >= idlen + 1 &&
        parent[plen - idlen - 1] == '/' &&
        strcmp(parent + plen - idlen, g_session_id) == 0) {
        /* Case B: sudo is inside the session cgroup. */
        if (snprintf(session_cg, sizeof(session_cg), "%s", parent) >=
            (int)sizeof(session_cg))
            return;
    } else {
        /* Case A: sudo was moved out; session cgroup is a sub-directory. */
        if (snprintf(session_cg, sizeof(session_cg), "%s/%s", parent,
                     g_session_id) >= (int)sizeof(session_cg))
            return;
    }

    /* Reject any path that escapes /sys/fs/cgroup/ — guards against a hostname
     * or username that contains path separators or ".." components. */
    if (strncmp(session_cg, "/sys/fs/cgroup/", 15) != 0 || strstr(session_cg, ".."))
        return;

    char path[680];
    int fd;

    /* Step 1: unfreeze so queued signals (SIGHUP, SIGTERM) can be delivered. */
    snprintf(path, sizeof(path), "%s/cgroup.freeze", session_cg);
    fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd >= 0) {
        (void)write(fd, "0\n", 2);
        close(fd);
    }

    /* Step 2: cgroup.kill (Linux 5.14+) — instant SIGKILL to all remainders. */
    snprintf(path, sizeof(path), "%s/cgroup.kill", session_cg);
    fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd >= 0) {
        (void)write(fd, "1\n", 2);
        close(fd);
    }
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
 * Instead we rely on the agent's cgroup freeze (cgroup.freeze = 1), which
 * suspends the process without changing its job-control state.  The session
 * stays in the foreground, and the banner can be written immediately.
 */
static void *monitor_thread_fn(void *arg)
{
    (void)arg;

    int was_frozen = 0;
    time_t last_reclaim = 0;

    while (!g_monitor_stop) {
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 150000000L };
        nanosleep(&ts, NULL);

        if (g_monitor_stop)
            break;

        int fresh = ack_is_fresh_locked();

        /* Agent socket dropped — terminate the session immediately. */
        if (atomic_load(&g_agent_dead)) {
            if (g_tty_fd >= 0) {
                if (atomic_load(&g_session_expired))
                    write(g_tty_fd, EXPIRED_MSG, sizeof(EXPIRED_MSG) - 1);
                else if (atomic_load(&g_freeze_timeout))
                    write(g_tty_fd, TIMEOUT_MSG, sizeof(TIMEOUT_MSG) - 1);
                else
                    write(g_tty_fd, TERMINATE_MSG, sizeof(TERMINATE_MSG) - 1);
            }
            unfreeze_session_cgroup();
            kill(-getpgrp(), SIGTERM);
            return NULL;
        }

        if (!fresh && !was_frozen) {
            was_frozen = 1;
        } else if (fresh && was_frozen) {
            if (g_tty_fd >= 0)
                write(g_tty_fd, UNFREEZE_MSG, sizeof(UNFREEZE_MSG) - 1);
            was_frozen = 0;
        }

        /* Detect terminal resize (SIGWINCH) by polling TIOCGWINSZ every tick.
         * When dimensions change, send MSG_RESIZE so the server writes an
         * asciinema "r" event into the cast file. */
        if (g_tty_fd >= 0 && g_agent_fd >= 0) {
            struct winsize ws;
            if (ioctl(g_tty_fd, TIOCGWINSZ, &ws) == 0 &&
                ws.ws_row > 0 && ws.ws_col > 0 &&
                (ws.ws_row != (unsigned short)g_term_rows ||
                 ws.ws_col != (unsigned short)g_term_cols)) {
                g_term_rows = (int)ws.ws_row;
                g_term_cols = (int)ws.ws_col;
                /* Payload: ts_ns(8BE) + cols(2BE) + rows(2BE) */
                uint8_t rbuf[12];
                int64_t ts_be  = (int64_t)htobe64((uint64_t)now_ns());
                uint16_t c_be  = htobe16((uint16_t)ws.ws_col);
                uint16_t r_be  = htobe16((uint16_t)ws.ws_row);
                memcpy(rbuf,     &ts_be, 8);
                memcpy(rbuf + 8, &c_be,  2);
                memcpy(rbuf + 10, &r_be, 2);
                pthread_mutex_lock(&g_send_mu);
                send_msg(g_agent_fd, MSG_RESIZE, rbuf, sizeof(rbuf));
                pthread_mutex_unlock(&g_send_mu);
            }
        }

        /*
         * Terminal-reclaim: while the session is frozen, sudo may hand the
         * terminal foreground to the child (bash) via tcsetpgrp() — e.g. when
         * the user does "fg" after being placed in background by a previous
         * SIGSTOP.  Since the child cgroup is frozen, Ctrl+C/Z signals sent to
         * the child's pgrp are queued but never delivered, leaving the user
         * completely trapped.
         *
         * Fix: check whether a child has become the terminal foreground.
         * If so, reclaim the terminal back to sudo's pgrp.  Use a 5-second
         * cooldown so we don't fight the user's "fg" command in a tight loop,
         * which causes SIGTTOU and stops the bash process.
         */
        if (!fresh && g_tty_fd >= 0) {
            time_t now = now_sec();
            if (now - last_reclaim >= 5) {
                pid_t fg_pgrp  = tcgetpgrp(g_tty_fd);
                pid_t our_pgrp = getpgrp();
                if (fg_pgrp > 0 && fg_pgrp != (pid_t)-1 && fg_pgrp != our_pgrp) {
                    sigset_t block, old;
                    sigemptyset(&block);
                    sigaddset(&block, SIGTTOU);
                    pthread_sigmask(SIG_BLOCK, &block, &old);
                    tcsetpgrp(g_tty_fd, our_pgrp);
                    pthread_sigmask(SIG_SETMASK, &old, NULL);
                    last_reclaim = now;
                }
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
    if (g_agent_fd < 0 || dlen == 0 || dlen > MAX_CHUNK_LEN)
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

    pthread_mutex_lock(&g_send_mu);
    send_msg(g_agent_fd, MSG_CHUNK, p, (uint32_t)plen);
    pthread_mutex_unlock(&g_send_mu);
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
            if (pos + 6 < bufsz) {
                int n = snprintf(buf + pos, bufsz - pos, "\\u%04x", c);
                if (n > 0 && (size_t)n < bufsz - pos)
                    pos += (size_t)n;
                else
                    break; /* Truncated or error */
            }
        } else {
            buf[pos++] = (char)c;
        }
    }
    if (pos < bufsz) buf[pos] = '\0';
}

/*
 * json_str_end — returns a pointer to the closing '"' of a JSON string value,
 * correctly skipping over backslash-escaped characters (including \").
 * p must point to the first character AFTER the opening '"'.
 * Returns NULL if no unescaped '"' is found before the NUL terminator.
 */
static const char *json_str_end(const char *p)
{
    while (*p) {
        if (*p == '\\') { p++; if (*p) p++; continue; }
        if (*p == '"')  { return p; }
        p++;
    }
    return NULL;
}

/*
 * json_unescape_into — decodes a JSON string value (between the outer quotes)
 * into dst, handling \n \r \t \\ \" and \uXXXX (BMP, emitted as UTF-8).
 * Returns the number of bytes written (not including the NUL terminator).
 * dst must have room for at least srclen+1 bytes.
 */
static size_t json_unescape_into(char *dst, size_t dstsz,
                                 const char *src, size_t srclen)
{
    size_t out = 0;
    for (size_t i = 0; i < srclen && out + 1 < dstsz; i++) {
        if (src[i] != '\\') { dst[out++] = src[i]; continue; }
        if (++i >= srclen)  break;
        switch (src[i]) {
        case 'n':  dst[out++] = '\n'; break;
        case 'r':  dst[out++] = '\r'; break;
        case 't':  dst[out++] = '\t'; break;
        case '\\': dst[out++] = '\\'; break;
        case '"':  dst[out++] = '"';  break;
        case 'u':
            if (i + 4 < srclen) {
                unsigned int cp = 0;
                const char *hex = src + i + 1;
                for (int k = 0; k < 4; k++) {
                    cp <<= 4;
                    char h = hex[k];
                    if      (h >= '0' && h <= '9') cp |= (unsigned)(h - '0');
                    else if (h >= 'a' && h <= 'f') cp |= (unsigned)(h - 'a' + 10);
                    else if (h >= 'A' && h <= 'F') cp |= (unsigned)(h - 'A' + 10);
                }
                i += 4;
                if (cp < 0x80) {
                    dst[out++] = (char)cp;
                } else if (cp < 0x800 && out + 2 < dstsz) {
                    dst[out++] = (char)(0xC0 | (cp >> 6));
                    dst[out++] = (char)(0x80 | (cp & 0x3F));
                } else if (out + 3 < dstsz) {
                    dst[out++] = (char)(0xE0 | (cp >> 12));
                    dst[out++] = (char)(0x80 | ((cp >> 6) & 0x3F));
                    dst[out++] = (char)(0x80 | (cp & 0x3F));
                }
            }
            break;
        default: dst[out++] = src[i]; break;
        }
    }
    dst[out] = '\0';
    return out;
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

    int truncated = 0;
    size_t pos = 0;
    int i;
    for (i = 0; i < argc && pos + 1 < bufsz; i++) {
        if (i > 0 && pos + 1 < bufsz)
            buf[pos++] = ' ';

        const char *p = argv[i];
        for (; *p && pos + 2 < bufsz; p++) {
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
        if (*p != '\0')
            truncated = 1;
    }
    if (i < argc)
        truncated = 1;
    buf[pos] = '\0';

    /* Mark truncation explicitly rather than silently dropping trailing
     * arguments — search/alerting on the "command" field must not be able
     * to mistake a cut-off command for the complete one. */
    if (truncated) {
        static const char marker[] = "...[truncated]";
        size_t mlen = sizeof(marker) - 1;
        if (mlen < bufsz) {
            size_t start = pos > mlen ? pos - mlen : 0;
            memcpy(buf + start, marker, mlen);
            buf[start + mlen] = '\0';
        }
    }
}

/* ---------- plugin API ---------- */

/*
 * plugin_open — called once per sudo invocation before the command runs.
 *
 * Responsibilities:
 *   1. Open /dev/tty for banner output (non-blocking; failure is non-fatal).
 *   2. Build a unique session ID from host + user + pid + nanosecond timestamp.
 *   3. Connect to sudo-logger-agent via Unix socket and send SESSION_START.
 *   4. Block until agent replies SESSION_READY (server reachable) or
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
    (void)version;
    (void)user_env;

    g_printf  = sudo_plugin_printf;
    g_seq     = 0;
    g_last_ack_time  = 0;
    g_last_ack_query = 0;
    atomic_store(&g_agent_dead, 0);

    g_tty_fd = open("/dev/tty", O_WRONLY | O_NOCTTY | O_CLOEXEC);
    if (g_tty_fd >= 0) {
        const char *tn = ttyname(g_tty_fd);
        if (tn)
            strncpy(g_tty_path, tn, sizeof(g_tty_path) - 1);
    }

    const char *user    = "unknown";
    const char *host    = "unknown";
    const char *raw_cwd = "/";   /* user_info[cwd] = the invoking user's cwd */
    int user_uid = -1;
    int user_gid = -1;
    for (int i = 0; user_info[i] != NULL; i++) {
        if      (strncmp(user_info[i], "user=", 5) == 0)
            user = user_info[i] + 5;
        else if (strncmp(user_info[i], "host=", 5) == 0)
            host = user_info[i] + 5;
        else if (strncmp(user_info[i], "cwd=",  4) == 0)
            raw_cwd = user_info[i] + 4;
        else if (strncmp(user_info[i], "uid=",  4) == 0)
            user_uid = (int)strtol(user_info[i] + 4, NULL, 10);
        else if (strncmp(user_info[i], "gid=",  4) == 0)
            user_gid = (int)strtol(user_info[i] + 4, NULL, 10);
    }

    /* ── Extract metadata from command_info[] ─────────────────────────── */
    const char *raw_resolved = "";
    int         runas_uid    = 0;
    int         runas_gid    = 0;
    int         term_cols    = 0;
    int         term_rows    = 0;
    for (int i = 0; command_info[i] != NULL; i++) {
        if      (strncmp(command_info[i], "command=",   8) == 0)
            raw_resolved = command_info[i] + 8;
        else if (strncmp(command_info[i], "runas_uid=", 10) == 0)
            runas_uid = (int)strtol(command_info[i] + 10, NULL, 10);
        else if (strncmp(command_info[i], "runas_gid=", 10) == 0)
            runas_gid = (int)strtol(command_info[i] + 10, NULL, 10);
        else if (strncmp(command_info[i], "cols=",      5) == 0)
            term_cols = (int)strtol(command_info[i] + 5,  NULL, 10);
        else if (strncmp(command_info[i], "lines=",     6) == 0)
            term_rows = (int)strtol(command_info[i] + 6,  NULL, 10);
    }

    /* If sudo didn't provide terminal dimensions (non-interactive or older sudo),
     * fall back to querying the PTY directly via TIOCGWINSZ. */
    if (g_tty_fd >= 0 && (term_rows <= 0 || term_cols <= 0)) {
        struct winsize ws;
        if (ioctl(g_tty_fd, TIOCGWINSZ, &ws) == 0) {
            if (term_rows <= 0 && ws.ws_row > 0) term_rows = (int)ws.ws_row;
            if (term_cols <= 0 && ws.ws_col > 0) term_cols = (int)ws.ws_col;
        }
    }
    g_term_rows = term_rows;
    g_term_cols = term_cols;

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

    /* ── Justification prompt ─────────────────────────────────────────────
     * Enabled via plugin option in /etc/sudo.conf:
     *   Plugin sudo_logger sudo_logger_plugin.so require_justification=1
     * Skipped automatically for non-interactive sessions (no TTY).        */
    /* ── JIT Approval ─────────────────────────────────────────────────────
     * We no longer prompt by default. We send an empty justification and
     * only prompt if the server challenges us. */
    char g_justification[512] = "";

    /* JSON-escape fields that may contain backslashes, quotes, or spaces */
    char resolved_j[512];
    char cwd_j[512];
    char runas_user_j[128];
    char user_j[128];
    char host_j[256];
    char ttypath_j[128];
    char justification_j[512];
    json_escape_into(resolved_j,      sizeof(resolved_j),      raw_resolved);
    json_escape_into(cwd_j,           sizeof(cwd_j),           raw_cwd);
    json_escape_into(runas_user_j,    sizeof(runas_user_j),    runas_user);
    json_escape_into(user_j,          sizeof(user_j),          user);
    json_escape_into(host_j,          sizeof(host_j),          host);
    json_escape_into(ttypath_j,       sizeof(ttypath_j),       g_tty_path);
    json_escape_into(justification_j, sizeof(justification_j), g_justification);

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
    char sanitized_host[128];
    char sanitized_user[128];
    sanitize_id_part(sanitized_host, host, sizeof(sanitized_host));
    sanitize_id_part(sanitized_user, user, sizeof(sanitized_user));
    snprintf(g_session_id, sizeof(g_session_id),
             "%s-%s-%d-%lld-%02x%02x%02x%02x",
             sanitized_host, sanitized_user, (int)getpid(), (long long)now_ns(),
             rnd[0], rnd[1], rnd[2], rnd[3]);

    char session_id_j[640];
    json_escape_into(session_id_j, sizeof(session_id_j), g_session_id);

    g_agent_fd = connect_agent();
    if (g_agent_fd < 0) {
        *errstr = "sudo-logger: cannot connect to agent daemon "
                  "(is sudo-logger-agent running?)";
        return -1;
    }

    /* Prevent sudo from hanging indefinitely if the agent stalls during
     * the TLS handshake with the remote server.  30 s is generous; the
     * agent normally responds within a few hundred milliseconds. */
    struct timeval rcv_timeout = { .tv_sec = 30, .tv_usec = 0 };
    setsockopt(g_agent_fd, SOL_SOCKET, SO_RCVTIMEO,
               &rcv_timeout, sizeof(rcv_timeout));

    char payload[16384];
    int plen = snprintf(payload, sizeof(payload),
        "{\"session_id\":\"%s\",\"user\":\"%s\",\"host\":\"%s\","
        "\"command\":\"%s\","
        "\"resolved_command\":\"%s\",\"runas_user\":\"%s\","
        "\"runas_uid\":%d,\"runas_gid\":%d,"
        "\"cwd\":\"%s\",\"flags\":\"%s\","
        "\"rows\":%d,\"cols\":%d,"
        "\"tty_path\":\"%s\","
        "\"user_uid\":%d,\"user_gid\":%d,"
        "\"ts\":%lld,\"pid\":%d,"
        "\"justification\":\"%s\"}",
        session_id_j, user_j, host_j, cmd,
        resolved_j, runas_user_j,
        runas_uid, runas_gid,
        cwd_j, flags,
        term_rows, term_cols,
        ttypath_j,
        user_uid, user_gid,
        (long long)now_sec(), (int)getpid(),
        justification_j);

    /* Prevent sending malformed/truncated JSON if the buffer was too small. */
    if (plen < 0 || plen >= (int)sizeof(payload)) {
        *errstr = "sudo-logger: session metadata too large (truncated)";
        close(g_agent_fd);
        g_agent_fd = -1;
        return -1;
    }

    send_msg(g_agent_fd, MSG_SESSION_START, payload, (uint32_t)plen);

    /* Wait for agent to confirm server connection before allowing sudo */
    uint8_t hdr[5];
read_agent:
    if (read_exact(g_agent_fd, hdr, 5) < 0) {
        *errstr = "sudo-logger: no response from agent";
        close(g_agent_fd);
        g_agent_fd = -1;
        return -1;
    }

    if (hdr[0] == MSG_SESSION_CHALLENGE) {
        /* Server requires a justification. Prompt the user now. */
        /* Challenge body is not consumed by the plugin (justification is
         * collected below via the conversation API) — drain it unconditionally
         * so the next read_agent iteration starts on a real header instead of
         * leftover challenge bytes. */
        uint32_t clen;
        memcpy(&clen, hdr + 1, 4);
        clen = be32toh(clen);
        if (clen > 0) {
            drain_payload(g_agent_fd, clen);
        }

        if (g_tty_fd >= 0 && conversation != NULL) {
            struct sudo_conv_message msgs[1];
            struct sudo_conv_reply   replies[1];
            memset(msgs,    0, sizeof(msgs));
            memset(replies, 0, sizeof(replies));

            msgs[0].msg_type = SUDO_CONV_PROMPT_ECHO_ON;
            msgs[0].msg      = "Reason for sudo: ";

            if (conversation(1, msgs, replies, NULL) == 0) {
                if (replies[0].reply && replies[0].reply[0] != '\0')
                    strncpy(g_justification, replies[0].reply, sizeof(g_justification) - 1);
            }
        }

        /* Send response back to agent */
        char resp_j[512];
        json_escape_into(resp_j, sizeof(resp_j), g_justification);

        char rpayload[1024];
        int rplen = snprintf(rpayload, sizeof(rpayload),
            "{\"justification\":\"%s\"}", resp_j);

        if (rplen > 0 && rplen < (int)sizeof(rpayload)) {
            send_msg(g_agent_fd, MSG_SESSION_CHALLENGE_RESPONSE, rpayload, (uint32_t)rplen);
        }

        /* The 30 s handshake timeout set before SESSION_START must not apply
         * to the JIT-approval wait: an approver can take much longer than
         * 30 s to act. Disable the receive timeout now; the initial
         * handshake (up to this point) is the only phase it should guard. */
        {
            struct timeval no_timeout = { .tv_sec = 0, .tv_usec = 0 };
            setsockopt(g_agent_fd, SOL_SOCKET, SO_RCVTIMEO,
                       &no_timeout, sizeof(no_timeout));
        }

        /* Inform the user their request has been submitted. */
        if (g_tty_fd >= 0) {
            {
                const char *m = "\r\n\033[33mApproval request submitted.\r\nYou will be notified when approved.\033[0m\r\n";
                write(g_tty_fd, m, strlen(m));
            }
        }

        goto read_agent;
    }

    if (hdr[0] == MSG_SESSION_DENIED) {
        /* Read the configurable block message and display it, then deny sudo */
        uint32_t dlen;
        memcpy(&dlen, hdr + 1, 4);
        dlen = be32toh(dlen);
        if (dlen >= 512) {
            /* Oversized payload — drain it */
            drain_payload(g_agent_fd, dlen);
            if (g_tty_fd >= 0) {
                write(g_tty_fd, DENIED_HDR,   sizeof(DENIED_HDR)   - 1);
                write(g_tty_fd, BLOCKED_TAIL, sizeof(BLOCKED_TAIL) - 1);
            } else {
                g_printf(SUDO_CONV_ERROR_MSG,
                    "sudo-logger: access blocked by security policy\n");
            }
        } else if (dlen > 0) {
            char msgbuf[512] = {0};
            read_exact(g_agent_fd, msgbuf, dlen);
            if (g_tty_fd >= 0) {
                write(g_tty_fd, DENIED_HDR,   sizeof(DENIED_HDR)   - 1);
                write(g_tty_fd, msgbuf, dlen);
                write(g_tty_fd, BLOCKED_TAIL, sizeof(BLOCKED_TAIL) - 1);
            } else {
                g_printf(SUDO_CONV_ERROR_MSG,
                    "sudo-logger: access blocked by security policy: %s\n", msgbuf);
            }
        } else {
            /* Empty payload */
            if (g_tty_fd >= 0) {
                write(g_tty_fd, DENIED_HDR,   sizeof(DENIED_HDR)   - 1);
                write(g_tty_fd, BLOCKED_TAIL, sizeof(BLOCKED_TAIL) - 1);
            } else {
                g_printf(SUDO_CONV_ERROR_MSG,
                    "sudo-logger: access blocked by security policy\n");
            }
        }
        /* _exit bypasses sudo's own error path so it cannot print
         * "sudo: error initializing I/O plugin" after our banner. */
        _exit(1);
    }

    if (hdr[0] == MSG_SESSION_ERROR) {
        /* Drain the payload (technical detail — logged by the agent, not
         * shown to the user; DNS errors etc. are not actionable at the
         * terminal and would only confuse the end user). */
        uint32_t elen;
        memcpy(&elen, hdr + 1, 4);
        elen = be32toh(elen);
        if (elen >= 512) {
            /* Oversized payload — drain it */
            drain_payload(g_agent_fd, elen);
        } else if (elen > 0) {
            char errbuf[512] = {0};
            read_exact(g_agent_fd, errbuf, elen);
        }
        if (g_tty_fd >= 0) {
            write(g_tty_fd, BLOCKED_HDR,  sizeof(BLOCKED_HDR)  - 1);
            write(g_tty_fd, BLOCKED_TAIL, sizeof(BLOCKED_TAIL) - 1);
        } else {
            g_printf(SUDO_CONV_ERROR_MSG,
                "sudo-logger: cannot reach log server — sudo blocked\n");
        }
        /* _exit bypasses sudo's own error path so it cannot print
         * "sudo: error initializing I/O plugin" after our banner. */
        _exit(1);
    }

    if (hdr[0] != MSG_SESSION_READY) {
        *errstr = "sudo-logger: unexpected response from agent";
        close(g_agent_fd);
        g_agent_fd = -1;
        return -1;
    }

    /* SESSION_READY may carry an optional JSON body with a "disclaimer" field —
     * an operator notice printed to the terminal before sudo proceeds. */
    {
        uint32_t rlen;
        memcpy(&rlen, hdr + 1, 4);
        rlen = be32toh(rlen);
        if (rlen >= 4096) {
            /* Oversized payload — drain it so the monitor thread's first
             * refresh_ack_cache() read starts on a real header instead of
             * leftover disclaimer bytes. */
            drain_payload(g_agent_fd, rlen);
        }
        if (rlen > 0 && rlen < 4096) {
            char rbuf[4096] = {0};
            if (read_exact(g_agent_fd, rbuf, rlen) == 0) {
                /* Print disclaimer before the session begins.
                 * The agent embeds ANSI colour codes and CRLF sequences;
                 * json_unescape_into decodes JSON escapes to raw bytes. */
                const char *dkey = "\"disclaimer\":\"";
                char *dp = strstr(rbuf, dkey);
                if (dp) {
                    dp += strlen(dkey);
                    const char *dend = json_str_end(dp);
                    if (dend && dend > dp) {
                        char decoded[4096] = {0};
                        size_t dlen = json_unescape_into(decoded, sizeof(decoded),
                                                         dp, (size_t)(dend - dp));
                        if (g_tty_fd >= 0) {
                            safe_write_tty(g_tty_fd, decoded, dlen);
                            write(g_tty_fd, "\r\n", 2);
                        } else {
                            g_printf(SUDO_CONV_INFO_MSG, "%s\n", decoded);
                        }
                    }
                }

            }
        }
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
     * agent just placed us in (SESSION_READY is the synchronisation point).
     * An attempt to write a PID to /sys/fs/cgroup/../../escape/cgroup.procs
     * resolves only within that subtree and fails with ENOENT.
     *
     * The agent itself remains in the host cgroup namespace and continues
     * to read and write cgroup.freeze / cgroup.procs via the full host path.
     * The existing socket connection (g_agent_fd) is unaffected: sockets
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
 * exit code, and closes the agent socket and /dev/tty.
 */
static void plugin_close(int exit_status, int error)
{
    (void)error;

    /* Stop the background monitor thread before closing the agent socket. */
    if (g_monitor_started) {
        atomic_store(&g_monitor_stop, 1);
        pthread_join(g_monitor_thread, NULL);
        g_monitor_started = 0;
    }

    if (g_agent_fd >= 0) {
        uint8_t payload[12];
        uint64_t seq_be  = htobe64(g_seq);
        int32_t  code_be = (int32_t)htobe32((uint32_t)exit_status);
        memcpy(payload,     &seq_be,  8);
        memcpy(payload + 8, &code_be, 4);
        send_msg(g_agent_fd, MSG_SESSION_END, payload, 12);
        close(g_agent_fd);
        g_agent_fd = -1;
    }

    if (g_tty_fd >= 0) {
        close(g_tty_fd);
        g_tty_fd = -1;
    }
}

/*
 * log_ttyin — called for every byte typed by the user (terminal → child).
 *
 * Returns 1 (pass the input through) under normal operation; returns 0 only
 * when the agent connection has died to prevent further I/O logging.  Freeze
 * enforcement is handled entirely by cgroup.freeze in sudo-logger-agent.  Returning
 * 0 during a freeze would permanently disable this hook rather than drop a
 * single byte, and caused sudo to send SIGHUP to the session on the first
 * keypress.
 *
 * Input typed during a freeze is buffered in the pty; bash cannot process it
 * until the cgroup unfreezes.
 */
static int log_ttyin(const char *buf, unsigned int len, const char **errstr)
{
    (void)errstr;
    if (atomic_load(&g_agent_dead))
        return 0;
    ship_chunk(STREAM_TTYIN, buf, len);
    return 1;
}

/* log_ttyout — called for every byte written to the terminal by the child. */
static int log_ttyout(const char *buf, unsigned int len, const char **errstr)
{
    (void)errstr;
    if (atomic_load(&g_agent_dead))
        return 0;
    ship_chunk(STREAM_TTYOUT, buf, len);
    return 1;
}

/* log_stdin — called for non-tty standard input (piped commands, heredocs). */
static int log_stdin(const char *buf, unsigned int len, const char **errstr)
{
    (void)errstr;
    if (atomic_load(&g_agent_dead))
        return 0;
    ship_chunk(STREAM_STDIN, buf, len);
    return 1;
}

/* log_stdout — called for non-tty standard output. */
static int log_stdout(const char *buf, unsigned int len, const char **errstr)
{
    (void)errstr;
    if (atomic_load(&g_agent_dead))
        return 0;
    ship_chunk(STREAM_STDOUT, buf, len);
    return 1;
}

/* log_stderr — called for standard error output. */
static int log_stderr(const char *buf, unsigned int len, const char **errstr)
{
    (void)errstr;
    if (atomic_load(&g_agent_dead))
        return 0;
    ship_chunk(STREAM_STDERR, buf, len);
    return 1;
}

/* show_version — called by "sudo -V"; prints the plugin version. */
static int show_version(int verbose)
{
    (void)verbose;
    if (g_printf != NULL) {
        g_printf(SUDO_CONV_INFO_MSG, "sudo-logger plugin v%s\n", PLUGIN_VERSION);
    } else {
        printf("sudo-logger plugin v%s\n", PLUGIN_VERSION);
    }
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
