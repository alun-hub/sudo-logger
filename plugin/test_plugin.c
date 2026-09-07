/*
 * test_plugin.c — Unit tests for sudo-logger C plugin.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <pthread.h>
#include <stdatomic.h>

/* --- Mock State --- */
static int mock_agent_fd = 42;
static uint8_t mock_read_buf[4096];
static size_t  mock_read_pos = 0;
static size_t  mock_read_len = 0;

static uint8_t mock_write_buf[4096];
static size_t  mock_write_len = 0;

/* --- Mock Functions --- */
ssize_t real_read(int fd, void *buf, size_t count) { return read(fd, buf, count); }
ssize_t real_write(int fd, const void *buf, size_t count) { return write(fd, buf, count); }

int mock_socket(int domain, int type, int protocol) {
    (void)domain; (void)type; (void)protocol;
    return mock_agent_fd;
}

int mock_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    (void)sockfd; (void)addr; (void)addrlen;
    return 0;
}

int mock_close(int fd) {
    (void)fd;
    return 0;
}

ssize_t mock_read(int fd, void *buf, size_t count) {
    if (fd != mock_agent_fd) return real_read(fd, buf, count);

    if (mock_read_pos >= mock_read_len) return 0;

    size_t to_copy = count;
    if (to_copy > (mock_read_len - mock_read_pos))
        to_copy = mock_read_len - mock_read_pos;

    memcpy(buf, mock_read_buf + mock_read_pos, to_copy);
    mock_read_pos += to_copy;
    return (ssize_t)to_copy;
}

ssize_t mock_write(int fd, const void *buf, size_t count) {
    if (fd != mock_agent_fd && fd != 1 && fd != 2) return real_write(fd, buf, count);

    if (fd == mock_agent_fd) {
        if (mock_write_len + count > sizeof(mock_write_buf))
            count = sizeof(mock_write_buf) - mock_write_len;
        memcpy(mock_write_buf + mock_write_len, buf, count);
        mock_write_len += count;
    }
    return (ssize_t)count;
}

int mock_open(const char *pathname, int flags, ...) {
    (void)pathname; (void)flags;
    return 100; /* dummy fd for /dev/tty or /dev/urandom */
}

static uid_t mock_uid = 0;

int mock_getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen) {
    (void)sockfd;
    (void)level;
    (void)optname;
    if (optval && optlen && *optlen >= sizeof(struct ucred)) {
        struct ucred *cred = (struct ucred *)optval;
        cred->uid = mock_uid;
        cred->gid = 0;
        cred->pid = 1234;
        *optlen = sizeof(struct ucred);
        return 0;
    }
    return -1;
}

/* Omdirigera systemanrop i plugin.c */
#define socket     mock_socket
#define connect    mock_connect
#define close      mock_close
#define read       mock_read
#define write      mock_write
#define open       mock_open
#define getsockopt mock_getsockopt

/* Define TEST_MODE before including plugin.c */
#define TEST_MODE
#include "plugin.c"

/* --- Test cases --- */

void test_json_logic(void) {
    char buf[256];
    printf("Running test_json_logic...\n");
    json_escape_into(buf, sizeof(buf), "hello \"quote\"");
    assert(strcmp(buf, "hello \\\"quote\\\"") == 0);
}

void test_plugin_open_success(void) {
    printf("Running test_plugin_open_success...\n");

    /* Reset state */
    mock_write_len = 0;
    mock_read_pos = 0;

    /* Prepare mock response: MSG_SESSION_READY (0x07) with 0 payload length */
    mock_read_buf[0] = 0x07;
    uint32_t plen = 0;
    memcpy(mock_read_buf + 1, &plen, 4); /* Note: this should be BE, but plugin uses be32toh/htobe32 which is handled in plugin.c */
    /* Wait, the mock needs to provide BE bytes because plugin.c calls be32toh */
    uint32_t be_len = htobe32(0);
    memcpy(mock_read_buf + 1, &be_len, 4);
    mock_read_len = 5;

    char *settings[] = {NULL};
    char *user_info[] = {"user=alice", "host=myhost", NULL};
    char *command_info[] = {"command=/bin/ls", NULL};
    char *argv[] = {"ls", NULL};
    const char *errstr = NULL;

    int rc = plugin_open(SUDO_API_VERSION, NULL, NULL, settings, user_info, command_info, 1, argv, NULL, NULL, &errstr);

    assert(rc == 1);
    assert(g_agent_fd == mock_agent_fd);
    /* Verify that SESSION_START was written (0x01) */
    assert(mock_write_buf[0] == 0x01);
}

void test_ship_chunk(void) {
    printf("Running test_ship_chunk...\n");

    mock_write_len = 0;
    ship_chunk(STREAM_TTYOUT, "test data", 9);

    /* Verify MSG_CHUNK (0x02) was written */
    assert(mock_write_buf[0] == 0x02);
    /* Payload length should be 8+8+1+4+9 = 30 bytes. Header is 5 bytes. Total 35. */
    uint32_t written_plen;
    memcpy(&written_plen, mock_write_buf + 1, 4);
    written_plen = be32toh(written_plen);
    assert(written_plen == 30);

    /* Sequence number (first 8 bytes of payload) should be 1 */
    uint64_t seq;
    memcpy(&seq, mock_write_buf + 5, 8);
    assert(be64toh(seq) == 1);
}

void test_safe_write_tty(void) {
    printf("Running test_safe_write_tty...\n");

    // Test SGR code color code (should pass through)
    mock_write_len = 0;
    const char *color_str = "\x1b[31;1mHello\x1b[0m";
    size_t color_len = strlen(color_str);
    safe_write_tty(mock_agent_fd, color_str, color_len);
    assert(mock_write_len == color_len);
    assert(memcmp(mock_write_buf, color_str, color_len) == 0);

    // Test unsafe ESC code (should be escaped to literal ^[)
    mock_write_len = 0;
    safe_write_tty(mock_agent_fd, "Esc\x1b]8;;http://evil.com\x1b\\Evil", 31);
    assert(mock_write_len > 0);
    // Let's verify it contains "^["
    assert(strstr((char*)mock_write_buf, "^[") != NULL);

    // A hostile block_message: clear the screen, home the cursor and paint a
    // fake password prompt. block_message is free-form operator text that
    // reaches the terminal unvalidated, so the SESSION_DENIED path routes it
    // through here; no raw ESC byte may survive.
    mock_write_len = 0;
    const char *hostile = "\x1b[2J\x1b[H[sudo] password for root: ";
    safe_write_tty(mock_agent_fd, hostile, strlen(hostile));
    assert(mock_write_len > 0);
    for (size_t i = 0; i < mock_write_len; i++)
        assert(mock_write_buf[i] != 0x1b);
    assert(strstr((char*)mock_write_buf, "^[") != NULL);
}

/* Builds one framed message into the mock read buffer. */
static void queue_frame(uint8_t type, const uint8_t *payload, uint32_t plen) {
    size_t at = mock_read_len;
    mock_read_buf[at] = type;
    uint32_t be = htobe32(plen);
    memcpy(mock_read_buf + at + 1, &be, 4);
    if (plen > 0)
        memcpy(mock_read_buf + at + 5, payload, plen);
    mock_read_len = at + 5 + plen;
}

void test_handle_agent_frame(void) {
    printf("Running test_handle_agent_frame...\n");
    uint32_t ack_plen;

    /* ACK_RESPONSE: header consumed, payload deliberately left for the caller,
     * which is what lets refresh_ack_cache parse it itself. */
    mock_read_pos = mock_read_len = 0;
    atomic_store(&g_agent_dead, 0);
    uint8_t ack[16] = {0};
    queue_frame(MSG_ACK_RESPONSE, ack, sizeof(ack));
    ack_plen = 0;
    frame_result fr = handle_agent_frame(mock_agent_fd, &ack_plen);
    assert(fr == FRAME_ACK);
    assert(ack_plen == 16);
    assert(mock_read_pos == 5);   /* header only */

    /* A control message is consumed whole, leaving the stream on the next
     * header — the property the drain loop depends on. */
    mock_read_pos = mock_read_len = 0;
    atomic_store(&g_freeze_timeout, 0);
    uint8_t body[8] = {1,2,3,4,5,6,7,8};
    queue_frame(MSG_FREEZE_TIMEOUT, body, sizeof(body));
    queue_frame(MSG_ACK_RESPONSE, ack, sizeof(ack));
    fr = handle_agent_frame(mock_agent_fd, &ack_plen);
    assert(fr == FRAME_HANDLED);
    assert(atomic_load(&g_freeze_timeout) == 1);
    fr = handle_agent_frame(mock_agent_fd, &ack_plen);
    assert(fr == FRAME_ACK);

    /* SESSION_EXPIRED sets its flag and is likewise consumed. */
    mock_read_pos = mock_read_len = 0;
    atomic_store(&g_session_expired, 0);
    queue_frame(MSG_SESSION_EXPIRED, body, sizeof(body));
    fr = handle_agent_frame(mock_agent_fd, &ack_plen);
    assert(fr == FRAME_HANDLED);
    assert(atomic_load(&g_session_expired) == 1);

    /* A length past MAX_MSG_PAYLOAD means the framing can no longer be
     * trusted; the session must go down the dead-agent path. */
    mock_read_pos = mock_read_len = 0;
    atomic_store(&g_agent_dead, 0);
    mock_read_buf[0] = MSG_SESSION_WARNING;
    uint32_t huge = htobe32(MAX_MSG_PAYLOAD + 1);
    memcpy(mock_read_buf + 1, &huge, 4);
    mock_read_len = 5;
    fr = handle_agent_frame(mock_agent_fd, &ack_plen);
    assert(fr == FRAME_ERROR);
    assert(atomic_load(&g_agent_dead) == 1);

    /* A truncated header is an error, and read_exact marks the agent dead. */
    mock_read_pos = mock_read_len = 0;
    atomic_store(&g_agent_dead, 0);
    mock_read_buf[0] = MSG_FREEZE_TIMEOUT;
    mock_read_len = 3;   /* short header */
    fr = handle_agent_frame(mock_agent_fd, &ack_plen);
    assert(fr == FRAME_ERROR);
    assert(atomic_load(&g_agent_dead) == 1);

    atomic_store(&g_agent_dead, 0);
    atomic_store(&g_freeze_timeout, 0);
    atomic_store(&g_session_expired, 0);
}

void test_json_unescape_utf8(void) {
    printf("Running test_json_unescape_utf8...\n");
    char dst[64];
    size_t n;

    /* Surrogate pair -> one 4-byte UTF-8 sequence (U+1F600). Encoding the
     * halves separately would give two 3-byte sequences, which is not UTF-8. */
    const char *pair = "\\uD83D\\uDE00";
    n = json_unescape_into(dst, sizeof(dst), pair, strlen(pair));
    assert(n == 4);
    assert((unsigned char)dst[0] == 0xF0 && (unsigned char)dst[1] == 0x9F);
    assert((unsigned char)dst[2] == 0x98 && (unsigned char)dst[3] == 0x80);

    /* A lone high surrogate is not a code point; expect U+FFFD, not a
     * 3-byte encoding of the surrogate itself. */
    const char *lone = "\\uD83D";
    n = json_unescape_into(dst, sizeof(dst), lone, strlen(lone));
    assert(n == 3);
    assert((unsigned char)dst[0] == 0xEF && (unsigned char)dst[1] == 0xBF
           && (unsigned char)dst[2] == 0xBD);

    /* Two-byte code point stays two bytes when space is tight: the old code
     * fell through to the three-byte branch and emitted an overlong form. */
    char tight[3];   /* room for exactly 2 bytes + NUL */
    const char *eacute = "\\u00e9";
    n = json_unescape_into(tight, sizeof(tight), eacute, strlen(eacute));
    assert(n == 2);
    assert((unsigned char)tight[0] == 0xC3 && (unsigned char)tight[1] == 0xA9);

    /* Malformed escape: stop rather than build a code point from bad digits. */
    const char *bad = "ok\\uZZZZtail";
    n = json_unescape_into(dst, sizeof(dst), bad, strlen(bad));
    assert(strcmp(dst, "ok") == 0);

    /* Ordinary escapes still work. */
    const char *plain = "a\\nb\\tc";
    n = json_unescape_into(dst, sizeof(dst), plain, strlen(plain));
    assert(strcmp(dst, "a\nb\tc") == 0);
}

void test_build_cmdline_json_truncation(void) {
    printf("Running test_build_cmdline_json_truncation...\n");

    /* A control character whose \uXXXX escape cannot fit must stop the
     * build and be reported, not be dropped silently. Sized so the literal
     * text fits but the six-byte escape does not. */
    /* Sized so the control character is reached with room for a literal byte
     * (pos + 2 < bufsz) but not for its six-byte escape (pos + 6 >= bufsz) --
     * the only window in which the old code dropped it. */
    char small[20];
    char argbuf[] = "abcdefghijklmno\x01XYZ";
    char *argv_ctl[] = { argbuf };
    build_cmdline_json(small, sizeof(small), 1, argv_ctl);
    /* The old code emitted "abcdefghijklmnoXYZ": the control character gone,
     * the rest carried on, and nothing marked. */
    assert(strstr(small, "oXYZ") == NULL);
    assert(strstr(small, "...[truncated]") != NULL);

    /* Truncation is terminal: no later argument may be spliced on after it,
     * or the recorded command line would be one that was never run. */
    char argbuf2[] = "abcdefghijklmno\x01XYZ";
    char argbuf3[] = "SECOND";
    char *argv_two[] = { argbuf2, argbuf3 };
    char small2[20];
    build_cmdline_json(small2, sizeof(small2), 2, argv_two);
    assert(strstr(small2, "SECOND") == NULL);

    /* A command that fits is untouched and unmarked. */
    char roomy[128];
    char ok1[] = "systemctl";
    char ok2[] = "restart";
    char ok3[] = "nginx";
    char *argv_ok[] = { ok1, ok2, ok3 };
    build_cmdline_json(roomy, sizeof(roomy), 3, argv_ok);
    assert(strcmp(roomy, "systemctl restart nginx") == 0);
}

void test_sanitize_id_part(void) {
    printf("Running test_sanitize_id_part...\n");
    char dst[32];

    sanitize_id_part(dst, "user.name_1-2", sizeof(dst));
    assert(strcmp(dst, "user.name_1-2") == 0);

    sanitize_id_part(dst, "user/../../traversal", sizeof(dst));
    assert(strcmp(dst, "user-..-..-traversal") == 0);

    // Test maxlen limit
    sanitize_id_part(dst, "longusername12345", 5);
    assert(strcmp(dst, "long") == 0);

    // Test maxlen 0 safety
    char short_dst[4] = "abc";
    sanitize_id_part(short_dst, "xyz", 0);
    assert(strcmp(short_dst, "abc") == 0); // unchanged
}

void test_plugin_open_non_root_uid(void) {
    printf("Running test_plugin_open_non_root_uid...\n");

    mock_uid = 1000; // non-root
    mock_write_len = 0;
    mock_read_pos = 0;

    char *settings[] = {NULL};
    char *user_info[] = {"user=alice", "host=myhost", NULL};
    char *command_info[] = {"command=/bin/ls", NULL};
    char *argv[] = {"ls", NULL};
    const char *errstr = NULL;

    int rc = plugin_open(SUDO_API_VERSION, NULL, NULL, settings, user_info, command_info, 1, argv, NULL, NULL, &errstr);

    // Should fail (return -1 or 0/error) because connect_agent() returns -1
    assert(rc == -1 || rc == 0);
    mock_uid = 0; // reset
}

int main(void) {
    printf("--- STARTING C PLUGIN UNIT TESTS (WITH MOCKS) ---\n");

    test_json_logic();
    test_plugin_open_success();
    test_ship_chunk();
    test_safe_write_tty();
    test_handle_agent_frame();
    test_json_unescape_utf8();
    test_build_cmdline_json_truncation();
    test_sanitize_id_part();
    test_plugin_open_non_root_uid();

    printf("--- ALL C PLUGIN UNIT TESTS PASSED ---\n");
    return 0;
}
