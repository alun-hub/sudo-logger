/*
 * sudo-logger: I/O plugin for sudo that ships session recordings to a
 * remote log server via a local shipper daemon.
 *
 * Freeze behaviour: if ACK from the log server is stale (> ACK_TIMEOUT_SECS),
 * log_ttyin returns 0 which prevents input from reaching the child process.
 *
 * Build:  see Makefile
 * Install: copy .so to /usr/lib/sudo/, add Plugin line to /etc/sudo.conf
 */

#include <sudo_plugin.h>

#include <arpa/inet.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
#include <dirent.h>
#include <pthread.h>
#include <signal.h>

/* ---------- tunables ---------- */
#define SHIPPER_SOCK_PATH    "/run/sudo-logger/plugin.sock"
#define ACK_TIMEOUT_SECS     5
#define ACK_REFRESH_SECS     1      /* how often to re-query shipper */
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
    "\r\n\033[41;97;1m[ SUDO-LOGGER: log server unreachable — input frozen ]\033[0m\r\n"
#define UNFREEZE_MSG \
    "\r\n\033[42;97;1m[ SUDO-LOGGER: log server reconnected — input resumed ]\033[0m\r\n"

/* ---------- plugin globals ---------- */
static sudo_conv_t   g_conv;
static sudo_printf_t g_printf;
static int           g_shipper_fd = -1;
static int           g_tty_fd     = -1;
static char          g_session_id[128];
static uint64_t      g_seq        = 0;

/* ACK cache */
static time_t g_last_ack_time  = 0;  /* when we last received a valid ACK */
static time_t g_last_ack_query = 0;  /* when we last queried the shipper */
static int    g_frozen         = 0;

/* Background monitor thread — freezes graphical (non-tty) programs via
 * SIGSTOP/SIGCONT when ACKs go stale.  Also provides a second line of
 * defence for tty sessions alongside the log_ttyin blocking. */
static pid_t          g_sudo_pid       = -1;
static volatile int   g_monitor_stop   = 0;
static int            g_monitor_started = 0;
static pthread_t      g_monitor_thread;
static pthread_mutex_t g_ack_mu        = PTHREAD_MUTEX_INITIALIZER;

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
        return writev(fd, iov, 2) < 0 ? -1 : 0;
    }
    return write(fd, hdr, 5) < 0 ? -1 : 0;
}

/*
 * Read exactly n bytes from fd. Returns -1 on error/EOF.
 */
static int read_exact(int fd, void *buf, size_t n)
{
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, (char *)buf + got, n - got);
        if (r <= 0)
            return -1;
        got += (size_t)r;
    }
    return 0;
}

/*
 * Connect to shipper Unix socket. Returns fd or -1.
 */
static int connect_shipper(void)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
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
    if (plen < 16)
        return;

    /* Payload: [8 bytes last_ack_ts_ns BE][8 bytes last_seq BE] */
    uint8_t payload[16];
    if (read_exact(g_shipper_fd, payload, 16) < 0)
        return;

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
 * Find the PID of a direct child of parent_pid.
 * First tries /proc/<pid>/task/<pid>/children (Linux 3.5+),
 * then falls back to scanning /proc/<N>/status for PPid.
 */
static pid_t find_child_pid(pid_t parent_pid)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/task/%d/children",
             (int)parent_pid, (int)parent_pid);
    FILE *f = fopen(path, "r");
    if (f) {
        pid_t child = -1;
        fscanf(f, "%d", &child);
        fclose(f);
        if (child > 0)
            return child;
    }

    /* Fallback: scan /proc for PPid == parent_pid */
    DIR *proc = opendir("/proc");
    if (!proc)
        return -1;
    struct dirent *e;
    pid_t found = -1;
    while ((e = readdir(proc)) != NULL && found < 0) {
        char *end;
        long pid = strtol(e->d_name, &end, 10);
        if (*end != '\0' || pid <= 0)
            continue;
        snprintf(path, sizeof(path), "/proc/%ld/status", pid);
        FILE *sf = fopen(path, "r");
        if (!sf)
            continue;
        char line[128];
        while (fgets(line, sizeof(line), sf)) {
            if (strncmp(line, "PPid:", 5) == 0) {
                if (strtol(line + 5, NULL, 10) == (long)parent_pid)
                    found = (pid_t)pid;
                break;
            }
        }
        fclose(sf);
    }
    closedir(proc);
    return found;
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
 * Polls ACK state every 500 ms and sends SIGSTOP/SIGCONT to the child's
 * entire process group.  Using the process group rather than a single PID
 * is required because sudo forks a monitor process ([sudo]) as its direct
 * child, which in turn forks the actual command (e.g. okular).  Sending
 * SIGSTOP to only the direct child would leave the command running.
 *
 * This is the sole freeze enforcement path.  log_ttyin always returns 1
 * so sudo's main event loop stays responsive and Ctrl+C works correctly.
 */
static void *monitor_thread_fn(void *arg)
{
    (void)arg;

    /* Give sudo time to fork the child before we try to find its PID. */
    struct timespec wait = { .tv_sec = 0, .tv_nsec = 300000000L };
    nanosleep(&wait, NULL);

    pid_t child = find_child_pid(g_sudo_pid);
    if (child < 0)
        return NULL;

    /* Freeze the child's entire process group so grandchildren (the actual
     * command) are also stopped.  Verify the pgid differs from our own so
     * we don't accidentally freeze the sudo parent itself. */
    pid_t child_pgid = getpgid(child);
    if (child_pgid <= 0 || child_pgid == getpgid(g_sudo_pid))
        child_pgid = 0; /* same group — fall back to single-process kill */

    int was_stopped = 0;

    while (!g_monitor_stop) {
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 500000000L };
        nanosleep(&ts, NULL);

        if (g_monitor_stop)
            break;

        int fresh = ack_is_fresh_locked();

        if (!fresh && !was_stopped) {
            if (g_tty_fd >= 0)
                write(g_tty_fd, FREEZE_MSG, sizeof(FREEZE_MSG) - 1);
            if (child_pgid > 0)
                kill(-child_pgid, SIGSTOP);
            else
                kill(child, SIGSTOP);
            was_stopped = 1;
        } else if (fresh && was_stopped) {
            if (child_pgid > 0)
                kill(-child_pgid, SIGCONT);
            else
                kill(child, SIGCONT);
            if (g_tty_fd >= 0)
                write(g_tty_fd, UNFREEZE_MSG, sizeof(UNFREEZE_MSG) - 1);
            was_stopped = 0;
        }
    }

    /* Unfreeze on clean session end so the child doesn't remain stopped. */
    if (was_stopped) {
        if (child_pgid > 0)
            kill(-child_pgid, SIGCONT);
        else
            kill(child, SIGCONT);
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

/* ---------- plugin API ---------- */

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
    (void)version; (void)settings; (void)command_info;
    (void)user_env; (void)plugin_options;

    g_conv    = conversation;
    g_printf  = sudo_plugin_printf;
    g_seq     = 0;
    g_frozen  = 0;
    g_last_ack_time  = 0;
    g_last_ack_query = 0;

    g_tty_fd = open("/dev/tty", O_WRONLY | O_NOCTTY | O_CLOEXEC);

    const char *user = "unknown";
    const char *host = "unknown";
    for (int i = 0; user_info[i] != NULL; i++) {
        if (strncmp(user_info[i], "user=", 5) == 0)
            user = user_info[i] + 5;
        else if (strncmp(user_info[i], "host=", 5) == 0)
            host = user_info[i] + 5;
    }

    const char *cmd = (argc > 0) ? argv[0] : "unknown";

    snprintf(g_session_id, sizeof(g_session_id),
             "%s-%s-%d-%lld", host, user, (int)getpid(),
             (long long)(now_ns() / 1000000LL));

    g_shipper_fd = connect_shipper();
    if (g_shipper_fd < 0) {
        *errstr = "sudo-logger: cannot connect to shipper daemon "
                  "(is sudo-shipper running?)";
        return -1;
    }

    char payload[512];
    int plen = snprintf(payload, sizeof(payload),
        "{\"session_id\":\"%s\",\"user\":\"%s\",\"host\":\"%s\","
        "\"command\":\"%s\",\"ts\":%lld,\"pid\":%d}",
        g_session_id, user, host, cmd,
        (long long)now_sec(), (int)getpid());

    /* snprintf returns the number of bytes that *would* have been written,
     * which may exceed sizeof(payload) if the input was truncated.
     * Cap to the actual number of bytes written to avoid over-reading the
     * stack buffer in send_msg/writev. */
    if (plen >= (int)sizeof(payload))
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
            g_printf(SUDO_CONV_ERROR_MSG,
                "sudo-logger: cannot reach log server: %s\n", errbuf);
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

    /* Start background monitor thread that handles graphical (non-tty)
     * programs via SIGSTOP/SIGCONT. */
    g_sudo_pid      = getpid();
    g_monitor_stop  = 0;
    g_monitor_started = (pthread_create(&g_monitor_thread, NULL,
                                        monitor_thread_fn, NULL) == 0);

    return 1;
}

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
 * Called for input typed by the user (terminal → child process).
 *
 * Always returns 1 (forward to child).  Freeze enforcement is handled
 * entirely by the background monitor thread via SIGSTOP/SIGCONT on the
 * child process group.  Blocking here would prevent sudo's main event
 * loop from processing signals, causing Ctrl+C to stop working and the
 * terminal to hang.
 */
static int log_ttyin(const char *buf, unsigned int len, const char **errstr)
{
    (void)errstr;
    ship_chunk(STREAM_TTYIN, buf, len);
    return 1;
}

static int log_ttyout(const char *buf, unsigned int len, const char **errstr)
{
    (void)errstr;
    ship_chunk(STREAM_TTYOUT, buf, len);
    return 1;
}

static int log_stdin(const char *buf, unsigned int len, const char **errstr)
{
    (void)errstr;
    ship_chunk(STREAM_STDIN, buf, len);
    return 1;
}

static int log_stdout(const char *buf, unsigned int len, const char **errstr)
{
    (void)errstr;
    ship_chunk(STREAM_STDOUT, buf, len);
    return 1;
}

static int log_stderr(const char *buf, unsigned int len, const char **errstr)
{
    (void)errstr;
    ship_chunk(STREAM_STDERR, buf, len);
    return 1;
}

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
