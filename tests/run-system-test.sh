#!/bin/bash
# tests/run-system-test.sh — System integration test suite for sudo-logger.
set -euo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKI_DIR="$TEST_DIR/pki"
mkdir -p "$PKI_DIR"

REPLAY_AUTH_USER="replayuser"
REPLAY_AUTH_PWD="Repl4yT3stPwd"  # pragma: allowlist secret

# ── helpers ────────────────────────────────────────────────────────────────────

pass() { echo "✅ $1 PASSED"; }
fail() { echo "❌ $1 FAILED: ${2:-}"; exit 1; }

# restart_shipper starts a fresh shipper inside the client container.
restart_shipper() {
    podman exec sudo-client-test pkill -x sudo-shipper 2>/dev/null || true
    sleep 1
    podman exec -d sudo-client-test /usr/local/bin/sudo-shipper \
        -server=localhost:9876 \
        -socket=/run/sudo-logger/plugin.sock \
        -cert=/etc/sudo-logger/client.crt \
        -key=/etc/sudo-logger/client.key \
        -ca=/etc/sudo-logger/ca.crt \
        -verifykey=/etc/sudo-logger/ack-verify.key \
        -debug
    sleep 3
}

# ── PKI and image setup ────────────────────────────────────────────────────────

echo "==> Genererar test-PKI..."
openssl genrsa -out "$PKI_DIR/ca.key" 2048 2>/dev/null
openssl req -x509 -new -nodes -key "$PKI_DIR/ca.key" -sha256 -days 1 \
    -subj "/CN=Test CA" -out "$PKI_DIR/ca.crt" 2>/dev/null
openssl genrsa -out "$PKI_DIR/server.key" 2048 2>/dev/null
openssl req -new -key "$PKI_DIR/server.key" -subj "/CN=localhost" \
    -out "$PKI_DIR/server.csr" 2>/dev/null
openssl x509 -req -days 1 -in "$PKI_DIR/server.csr" \
    -CA "$PKI_DIR/ca.crt" -CAkey "$PKI_DIR/ca.key" -CAcreateserial \
    -extfile <(printf "subjectAltName=DNS:localhost") \
    -out "$PKI_DIR/server.crt" 2>/dev/null
openssl genrsa -out "$PKI_DIR/client.key" 2048 2>/dev/null
openssl req -new -key "$PKI_DIR/client.key" -subj "/CN=sudo-client" \
    -out "$PKI_DIR/client.csr" 2>/dev/null
openssl x509 -req -days 1 -in "$PKI_DIR/client.csr" \
    -CA "$PKI_DIR/ca.crt" -CAkey "$PKI_DIR/ca.key" -CAcreateserial \
    -out "$PKI_DIR/client.crt" 2>/dev/null
openssl genpkey -algorithm ed25519 -out "$PKI_DIR/ack-sign.key" 2>/dev/null
openssl pkey -in "$PKI_DIR/ack-sign.key" -pubout -out "$PKI_DIR/ack-verify.key" 2>/dev/null

cp "$TEST_DIR/../go/cmd/replay-server/risk-rules.yaml" "$PKI_DIR/"
chmod 644 "$PKI_DIR"/*

echo "==> Bygger bilder..."
cd "$TEST_DIR/.."
podman build -q -t sudo-logserver-test -f tests/Dockerfile.server .
podman build -q -t sudo-client-test -f tests/Dockerfile.client .

cleanup() {
    echo "==> Städar upp..."
    podman pod rm -f sudo-logger-pod 2>/dev/null || true
    podman volume rm sudologs-test 2>/dev/null || true
    rm -rf "$PKI_DIR"
}
trap cleanup EXIT

podman pod rm -f sudo-logger-pod 2>/dev/null || true
podman volume rm sudologs-test 2>/dev/null || true
podman pod create --name sudo-logger-pod -p 9876:9876

echo "==> Startar logserver..."
podman run -d --name sudo-logserver-test --pod sudo-logger-pod \
    -v "$PKI_DIR":/etc/sudo-logger:ro,Z \
    -v sudologs-test:/var/log/sudoreplay:Z \
    sudo-logserver-test \
    -listen=:9876 \
    -logdir=/var/log/sudoreplay \
    -cert=/etc/sudo-logger/server.crt \
    -key=/etc/sudo-logger/server.key \
    -ca=/etc/sudo-logger/ca.crt \
    -signkey=/etc/sudo-logger/ack-sign.key

echo "==> Startar klient..."
podman run -d --name sudo-client-test --pod sudo-logger-pod \
    -v "$PKI_DIR":/etc/sudo-logger:ro,Z \
    --cap-add=NET_ADMIN --privileged \
    sudo-client-test
sleep 5

# ── TEST 1: Happy Path ─────────────────────────────────────────────────────────
echo "==> TEST 1: Happy Path..."
TOKEN1="HAPPY_$(date +%s)"  # pragma: allowlist secret
podman exec sudo-client-test sudo sh -c "echo $TOKEN1" >/dev/null
sleep 3
podman exec sudo-logserver-test grep -r "$TOKEN1" /var/log/sudoreplay >/dev/null \
    || fail "TEST 1" "token not found in log"
pass "TEST 1"

# ── TEST 2: Socket UID check ───────────────────────────────────────────────────
echo "==> TEST 2: Socket UID-säkerhet..."
# Non-root must be denied at the OS level (socket is mode 0600 owned by root).
if podman exec -u testuser sudo-client-test \
        nc -U /run/sudo-logger/plugin.sock -z 2>/dev/null; then
    fail "TEST 2" "non-root connected to plugin socket"
fi
# Temporarily widen dir + socket so testuser can reach the socket,
# then send garbage — shipper must reject via SO_PEERCRED UID check.
podman exec sudo-client-test chmod 755 /run/sudo-logger
podman exec sudo-client-test chmod 666 /run/sudo-logger/plugin.sock
podman exec -u testuser sudo-client-test \
    sh -c "echo HELLO | nc -U /run/sudo-logger/plugin.sock" >/dev/null 2>&1 || true
sleep 1
podman exec sudo-client-test chmod 600 /run/sudo-logger/plugin.sock
podman exec sudo-client-test chmod 750 /run/sudo-logger
if podman logs sudo-client-test 2>&1 | grep -q "rejected non-root connection"; then
    pass "TEST 2"
else
    fail "TEST 2" "shipper did not log UID rejection"
fi

# ── TEST 3: Data Integrity (FIXED) ────────────────────────────────────────────
echo "==> TEST 3: Data Integrity..."
# Run a command that echoes a unique string; verify it appears in ttyout log.
TOKEN3="INTEGRITY_$(date +%s)"
podman exec sudo-client-test sudo sh -c "echo $TOKEN3" >/dev/null
sleep 3
podman exec sudo-logserver-test grep -r "$TOKEN3" /var/log/sudoreplay >/dev/null \
    || fail "TEST 3" "command output not captured in ttyout"
pass "TEST 3"

# ── TEST B: mTLS enforcement ───────────────────────────────────────────────────
echo "==> TEST B: mTLS-avvisning..."
# With TLS 1.3 + RequireAndVerifyClientCert, "Verify return code: 0 (ok)" in
# openssl output refers to the SERVER's cert, not whether the client was accepted.
# The server sends alert 116 (certificate_required) AFTER the handshake when
# the client presents no cert.  Check for that alert or a cert-related error.
#
# Guard: confirm a valid client cert IS accepted before testing rejection.
VALID_RESULT=$(echo Q | timeout 5 podman exec -i sudo-client-test \
    openssl s_client \
    -connect localhost:9876 \
    -cert /etc/sudo-logger/client.crt \
    -key /etc/sudo-logger/client.key \
    -CAfile /etc/sudo-logger/ca.crt \
    2>&1 || true)
if ! echo "$VALID_RESULT" | grep -q "Verify return code: 0"; then
    fail "TEST B" "valid client cert was rejected (test setup broken)"
fi
# Without a client cert the server must send a certificate_required alert.
NOCERT_RESULT=$(echo Q | timeout 5 podman exec -i sudo-client-test \
    openssl s_client \
    -connect localhost:9876 \
    -CAfile /etc/sudo-logger/ca.crt \
    2>&1 || true)
if ! echo "$NOCERT_RESULT" | grep -qiE "(alert|certificate.required|peer did not return|handshake failure)"; then
    fail "TEST B" "logserver accepted connection without client certificate; openssl output: $NOCERT_RESULT"
fi
pass "TEST B"

# ── TEST 4: Logserver reconnect resilience (FIXED) ───────────────────────────
echo "==> TEST 4: Logserver resilience — reconnect efter restart..."
podman stop sudo-logserver-test >/dev/null
sleep 3
podman start sudo-logserver-test >/dev/null
sleep 8  # let shipper reconnect
TOKEN4="RECONNECT_$(date +%s)"
podman exec sudo-client-test sudo sh -c "echo $TOKEN4" >/dev/null
sleep 3
podman exec sudo-logserver-test grep -r "$TOKEN4" /var/log/sudoreplay >/dev/null \
    || fail "TEST 4" "shipper did not reconnect after logserver restart"
pass "TEST 4"

# ── TEST A: Session termination when shipper is killed ────────────────────────
echo "==> TEST A: Session avslutas när shipper dödas..."
podman exec -d sudo-client-test sudo sh -c "sleep 60"
sleep 3
if ! podman exec sudo-client-test pgrep -x sleep >/dev/null 2>&1; then
    fail "TEST A" "sleep process not started (test setup broken)"
fi
podman exec sudo-client-test pkill -x sudo-shipper || true
sleep 8
if podman exec sudo-client-test pgrep -x sleep >/dev/null 2>&1; then
    fail "TEST A" "sudo session still running 8s after shipper was killed"
fi
pass "TEST A"

# Restart shipper for subsequent tests.
echo "   Startar om shipper..."
restart_shipper

# ── TEST 5: Risk scoring ───────────────────────────────────────────────────────
echo "==> TEST 5: Risk Scoring..."
# Generate htpasswd file and start replay server with auth.
podman exec sudo-logserver-test sh -c \
    "htpasswd -nBb $REPLAY_AUTH_USER $REPLAY_AUTH_PWD > /tmp/replay.htpasswd"  # pragma: allowlist secret
podman exec sudo-logserver-test sh -c \
    'sudo-replay-server -logdir /var/log/sudoreplay -rules /etc/sudo-logger/risk-rules.yaml -htpasswd /tmp/replay.htpasswd -listen :8080 &>/tmp/replay.log & echo $! > /tmp/replay.pid'
sleep 4

# Run a high-risk command (visudo triggers the visudo rule in risk-rules.yaml).
podman exec sudo-client-test sudo visudo -c >/dev/null 2>&1 || true
sleep 2
podman exec sudo-logserver-test find /var/log/sudoreplay -name risk.json \
    | grep -q risk.json \
    || fail "TEST 5" "no risk.json found after risk-scoring run"
pass "TEST 5"

# ── TEST C: Replay API + HTTP Basic Auth ──────────────────────────────────────
echo "==> TEST C: Replay API + Basic Auth..."
# Without credentials: must return 401.
STATUS_NOAUTH=$(podman exec sudo-logserver-test \
    curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/api/sessions)
[ "$STATUS_NOAUTH" = "401" ] \
    || fail "TEST C" "expected 401 without credentials, got $STATUS_NOAUTH"

# With correct credentials: must return 200 and valid JSON.
RESPONSE=$(podman exec sudo-logserver-test \
    curl -s -u "$REPLAY_AUTH_USER:$REPLAY_AUTH_PWD" http://localhost:8080/api/sessions)  # pragma: allowlist secret
echo "$RESPONSE" | grep -q '"sessions"' \
    || fail "TEST C" "expected JSON with 'sessions' key, got: $RESPONSE"

# With wrong password: must return 401.
STATUS_WRONG=$(podman exec sudo-logserver-test \
    curl -s -o /dev/null -w "%{http_code}" \
    -u "$REPLAY_AUTH_USER:wrongpass" http://localhost:8080/api/sessions)  # pragma: allowlist secret
[ "$STATUS_WRONG" = "401" ] \
    || fail "TEST C" "expected 401 for wrong password, got $STATUS_WRONG"
pass "TEST C"

# ── TEST D: SIGHUP htpasswd reload ────────────────────────────────────────────
echo "==> TEST D: SIGHUP htpasswd reload..."
NEW_USER="replayuser2"
NEW_PWD="Repl4yN3wPwd"  # pragma: allowlist secret

# Verify new user cannot authenticate before being added.
STATUS_BEFORE=$(podman exec sudo-logserver-test \
    curl -s -o /dev/null -w "%{http_code}" \
    -u "$NEW_USER:$NEW_PWD" http://localhost:8080/api/sessions)  # pragma: allowlist secret
[ "$STATUS_BEFORE" = "401" ] \
    || fail "TEST D" "new user authenticated before being added to htpasswd"

# Append new user to htpasswd file.
podman exec sudo-logserver-test sh -c \
    "htpasswd -nBb $NEW_USER $NEW_PWD >> /tmp/replay.htpasswd"  # pragma: allowlist secret

# Without SIGHUP, new user must still be rejected (not yet reloaded).
STATUS_NORELOAD=$(podman exec sudo-logserver-test \
    curl -s -o /dev/null -w "%{http_code}" \
    -u "$NEW_USER:$NEW_PWD" http://localhost:8080/api/sessions)  # pragma: allowlist secret
[ "$STATUS_NORELOAD" = "401" ] \
    || fail "TEST D" "new user authenticated without SIGHUP reload"

# Send SIGHUP to reload credentials.
REPLAY_PID=$(podman exec sudo-logserver-test cat /tmp/replay.pid)
podman exec sudo-logserver-test kill -HUP "$REPLAY_PID"
sleep 2

# After SIGHUP, new user must be accepted.
STATUS_AFTER=$(podman exec sudo-logserver-test \
    curl -s -o /dev/null -w "%{http_code}" \
    -u "$NEW_USER:$NEW_PWD" http://localhost:8080/api/sessions)  # pragma: allowlist secret
[ "$STATUS_AFTER" = "200" ] \
    || fail "TEST D" "new user rejected after SIGHUP reload (got $STATUS_AFTER)"
pass "TEST D"

# ── TEST F: Risk scoring precision via API ────────────────────────────────────
echo "==> TEST F: Risk scoring via API..."
API_RESP=$(podman exec sudo-logserver-test \
    curl -s -u "$REPLAY_AUTH_USER:$REPLAY_AUTH_PWD" http://localhost:8080/api/sessions)  # pragma: allowlist secret
# At least one session should be scored as high or critical (visudo ran in TEST 5).
echo "$API_RESP" | grep -qE '"risk_level":"(high|critical)"' \
    || fail "TEST F" "no high/critical sessions found after visudo run; response: $API_RESP"
pass "TEST F"

# ── TEST 6: Network Jitter (FIXED) ────────────────────────────────────────────
echo "==> TEST 6: Network Jitter..."
IFACE=$(podman exec sudo-client-test ip -o link show \
    | grep -v " lo:" | head -1 | awk -F': ' '{print $2}' | cut -d'@' -f1)
echo "   Nätverkskort: $IFACE"
podman exec sudo-client-test tc qdisc add dev "$IFACE" root netem delay 500ms
TOKEN6="JITTER_$(date +%s)"
# Command must succeed despite 500ms delay.
podman exec sudo-client-test sudo sh -c "echo $TOKEN6" \
    || fail "TEST 6" "sudo command failed under 500ms network jitter"
sleep 5  # extra wait: 500ms delay means log may arrive later
podman exec sudo-logserver-test grep -r "$TOKEN6" /var/log/sudoreplay >/dev/null \
    || fail "TEST 6" "command output not logged under 500ms jitter"
podman exec sudo-client-test tc qdisc del dev "$IFACE" root
pass "TEST 6"

# ── TEST E: INCOMPLETE session marker ─────────────────────────────────────────
echo "==> TEST E: INCOMPLETE-markering vid shipper-avbrott..."
# Start a long-running session.
podman exec -d sudo-client-test sudo sh -c "sleep 60"
sleep 3
if ! podman exec sudo-client-test pgrep -x sleep >/dev/null 2>&1; then
    fail "TEST E" "sleep process not started (test setup broken)"
fi
# Kill the shipper mid-session (no SESSION_END will be sent to logserver).
podman exec sudo-client-test pkill -x sudo-shipper || true
sleep 5
# Logserver must have written an INCOMPLETE marker.
podman exec sudo-logserver-test find /var/log/sudoreplay -name INCOMPLETE \
    | grep -q INCOMPLETE \
    || fail "TEST E" "no INCOMPLETE marker found after shipper was killed mid-session"
pass "TEST E"

echo ""
echo "🎉 ALLA SYSTEMTESTER LYCKADES!"
exit 0
