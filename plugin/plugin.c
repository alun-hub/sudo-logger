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
        "\"command\":\"%s\",\"ts\":%lld}",
        g_session_id, user, host, cmd,
        (long long)now_sec());

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

    return 1;
}

static void plugin_close(int exit_status, int error)
{
    (void)error;

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
 * Return 1 to forward to child, 0 to swallow (freeze).
 */
static int log_ttyin(const char *buf, unsigned int len, const char **errstr)
{
    (void)errstr;

    ship_chunk(STREAM_TTYIN, buf, len);

    if (!ack_is_fresh()) {
        if (!g_frozen && g_tty_fd >= 0) {
            write(g_tty_fd, FREEZE_MSG, sizeof(FREEZE_MSG) - 1);
            g_frozen = 1;
        }
        /* Allow Ctrl+C (0x03) and Ctrl+\ (0x1c) through immediately
         * so the user can kill the frozen session. */
        for (unsigned int i = 0; i < len; i++) {
            if ((unsigned char)buf[i] == 0x03 || (unsigned char)buf[i] == 0x1c)
                return 1;
        }
        /* Block here until ACKs resume rather than returning 0.
         * Returning 0 causes sudo to send SIGTERM to the child process.
         * Blocking keeps the child alive while preventing unlogged input
         * from reaching it. When the network recovers we fall through
         * and return 1, forwarding the pending keystroke. */
        do {
            struct timespec ts = { .tv_sec = 0, .tv_nsec = 200000000L };
            nanosleep(&ts, NULL);
        } while (!ack_is_fresh());

        if (g_frozen) {
            if (g_tty_fd >= 0)
                write(g_tty_fd, UNFREEZE_MSG, sizeof(UNFREEZE_MSG) - 1);
            g_frozen = 0;
        }
    } else if (g_frozen) {
        if (g_tty_fd >= 0)
            write(g_tty_fd, UNFREEZE_MSG, sizeof(UNFREEZE_MSG) - 1);
        g_frozen = 0;
    }

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
