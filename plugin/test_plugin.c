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
    test_sanitize_id_part();
    test_plugin_open_non_root_uid();

    printf("--- ALL C PLUGIN UNIT TESTS PASSED ---\n");
    return 0;
}
