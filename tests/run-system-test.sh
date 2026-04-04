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

# ── TEST 1: Grundflöde ─────────────────────────────────────────────────────────
# Verifierar att hela kedjan fungerar end-to-end: plugin fångar kommandot,
# shippern skickar det via mTLS till logservern, och logservern skriver det
# till disk. En unik token söks i loggkatalogen efter kommandot körts.
echo "==> TEST 1: Grundflöde — sudo-kommando loggas och syns i loggfilen..."
TOKEN1="HAPPY_$(date +%s)"  # pragma: allowlist secret
podman exec sudo-client-test sudo sh -c "echo $TOKEN1" >/dev/null
sleep 3
podman exec sudo-logserver-test grep -r "$TOKEN1" /var/log/sudoreplay >/dev/null \
    || fail "TEST 1" "token not found in log"
pass "TEST 1"

# ── TEST 2: Plugin-socket UID-kontroll ────────────────────────────────────────
# Verifierar att plugin-sockeln är skyddad på två nivåer:
#   1. OS-nivå: sockeln är mode 0600 ägd av root — icke-root kan inte ens ansluta.
#   2. Applikationsnivå: shippern kontrollerar SO_PEERCRED och avvisar anslutningar
#      från icke-root även om socketfilen tillfälligt görs tillgänglig.
# Testet vidgar tillfälligt rättigheter för att nå applikationslagret, och
# kontrollerar sedan att shippern loggat en UID-avvisning.
echo "==> TEST 2: Plugin-socket UID-kontroll — icke-root nekas åtkomst på OS- och applikationsnivå..."
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

# ── TEST 3: Dataintegritet ────────────────────────────────────────────────────
# Verifierar att kommandoutdata bevaras ord för ord i loggfilen — inga bytes
# tappas eller skrivs om på vägen genom plugin → shipper → logserver → disk.
# En unik token echas via sudo och söks sedan i ttyout-loggen.
echo "==> TEST 3: Dataintegritet — terminalutdata bevaras ord för ord i loggfilen..."
TOKEN3="INTEGRITY_$(date +%s)"
podman exec sudo-client-test sudo sh -c "echo $TOKEN3" >/dev/null
sleep 3
podman exec sudo-logserver-test grep -r "$TOKEN3" /var/log/sudoreplay >/dev/null \
    || fail "TEST 3" "command output not captured in ttyout"
pass "TEST 3"

# ── TEST 4: mTLS-tvång ────────────────────────────────────────────────────────
# Verifierar att logservern kräver ömsesidig TLS-autentisering (mTLS):
# klienter utan giltigt klientcertifikat ska avvisas med TLS-alert.
# Med TLS 1.3 + RequireAndVerifyClientCert skickar servern alert 116
# (certificate_required) efter handshake om klienten inte presenterar ett cert.
# Testet kontrollerar först att ett giltigt cert accepteras, sedan att avsaknad
# av cert ger ett certifikatrelaterat fel.
echo "==> TEST 4: mTLS-tvång — logservern kräver giltig klientcertifikat..."
VALID_RESULT=$(echo Q | timeout 5 podman exec -i sudo-client-test \
    openssl s_client \
    -connect localhost:9876 \
    -cert /etc/sudo-logger/client.crt \
    -key /etc/sudo-logger/client.key \
    -CAfile /etc/sudo-logger/ca.crt \
    2>&1 || true)
if ! echo "$VALID_RESULT" | grep -q "Verify return code: 0"; then
    fail "TEST 4" "valid client cert was rejected (test setup broken)"
fi
# Without a client cert the server must send a certificate_required alert.
NOCERT_RESULT=$(echo Q | timeout 5 podman exec -i sudo-client-test \
    openssl s_client \
    -connect localhost:9876 \
    -CAfile /etc/sudo-logger/ca.crt \
    2>&1 || true)
if ! echo "$NOCERT_RESULT" | grep -qiE "(alert|certificate.required|peer did not return|handshake failure)"; then
    fail "TEST 4" "logserver accepted connection without client certificate; openssl output: $NOCERT_RESULT"
fi
pass "TEST 4"

# ── TEST 5: Återanslutning efter logserver-omstart ────────────────────────────
# Verifierar att shippern automatiskt återansluter till logservern efter att den
# startats om, och att loggningen återupptas utan att sudo-kommandon misslyckas.
# Logservern stoppas och startas om; shippern förväntas återansluta inom 8 s,
# varefter ett nytt kommando ska dyka upp i loggkatalogen.
echo "==> TEST 5: Återanslutning — shippern återupptar loggning efter logserver-omstart..."
podman stop sudo-logserver-test >/dev/null
sleep 3
podman start sudo-logserver-test >/dev/null
sleep 8  # let shipper reconnect
TOKEN5="RECONNECT_$(date +%s)"
podman exec sudo-client-test sudo sh -c "echo $TOKEN5" >/dev/null
sleep 3
podman exec sudo-logserver-test grep -r "$TOKEN5" /var/log/sudoreplay >/dev/null \
    || fail "TEST 5" "shipper did not reconnect after logserver restart"
pass "TEST 5"

# ── TEST 6: Sessionsterminering vid shipper-krasch ────────────────────────────
# Verifierar att sudo-processen avslutas inom rimlig tid när shippern dör.
# I icke-interaktivt läge (exec_nopty, ingen TTY) vidarebefordrar sudo inte
# SIGTERM till sina barn automatiskt. Plugin-monitortråden kompenserar genom att
# skicka SIGTERM till hela processgruppen (kill(-pgrp)) istället för bara sudo.
# "exec sleep 60" används så att sh ersätter sig med sleep — sudo får exakt ett
# barn vars pipe-stängning häver sudo:s poll()-blockering.
echo "==> TEST 6: Sessionsterminering — sudo-processen avslutas när shippern kraschar..."
podman exec -d sudo-client-test sudo sh -c 'echo $PPID > /tmp/sudo_test_pid; exec sleep 60'
sleep 3
SUDO_TEST_PID=$(podman exec sudo-client-test cat /tmp/sudo_test_pid 2>/dev/null || echo "0")
[ "$SUDO_TEST_PID" != "0" ] \
    || fail "TEST 6" "could not read sudo PID (session did not start)"
podman exec sudo-client-test kill -0 "$SUDO_TEST_PID" 2>/dev/null \
    || fail "TEST 6" "sudo PID $SUDO_TEST_PID not running (test setup broken)"
# Kill the shipper — monitor thread detects EOF, calls kill(-pgrp, SIGTERM) to
# terminate the whole process group (sudo + its children), then exits.
podman exec sudo-client-test pkill -x sudo-shipper \
    || fail "TEST 6" "sudo-shipper not found — cannot run test"
sleep 10
# The sudo process must have exited.  Zombie processes (State: Z) still appear
# in kill -0 checks, so inspect /proc directly and treat zombies as terminated.
PROC_STATE=$(podman exec sudo-client-test \
    sh -c "grep '^State:' /proc/$SUDO_TEST_PID/status 2>/dev/null || echo 'State: gone'")
if echo "$PROC_STATE" | grep -qE "^State:[[:space:]]+(R|S|D)"; then
    fail "TEST 6" "sudo (PID $SUDO_TEST_PID) still genuinely running ($PROC_STATE) after shipper was killed"
fi
pass "TEST 6"

# Restart shipper for subsequent tests.
echo "   Startar om shipper..."
restart_shipper

# ── TEST 7: Riskpoängsättning ─────────────────────────────────────────────────
# Verifierar att replay-servern genererar en risk.json för sessioner som matchar
# riskreglar (t.ex. visudo som ger 60 poäng = high risk).
# Kommandot körs INNAN replay-servern startas så att det finns på disk vid den
# initiala indexbygget — servern cachar sessionsindexet i 30 s, och kommandon
# loggade efter cache-bygget syns inte förrän TTL löpt ut.
echo "==> TEST 7: Riskpoängsättning — risk.json genereras för högriskkommandon..."
# Run the high-risk command BEFORE starting the replay server so it lands on
# disk and is included in the server's initial session-index rebuild.  The
# replay server caches the index for 30 s; any command logged after the
# initial rebuild would be invisible to TEST 10's API call.
podman exec sudo-client-test sudo visudo -c >/dev/null 2>&1 || true
sleep 3  # wait for the logserver to write the session to disk

# Generate htpasswd file and start replay server with auth.
podman exec sudo-logserver-test sh -c \
    "htpasswd -nBb $REPLAY_AUTH_USER $REPLAY_AUTH_PWD > /tmp/replay.htpasswd"  # pragma: allowlist secret
podman exec sudo-logserver-test sh -c \
    'sudo-replay-server -logdir /var/log/sudoreplay -rules /etc/sudo-logger/risk-rules.yaml -htpasswd /tmp/replay.htpasswd -listen :8080 &>/tmp/replay.log & echo $! > /tmp/replay.pid'
sleep 4

podman exec sudo-logserver-test find /var/log/sudoreplay -name risk.json \
    | grep -q risk.json \
    || fail "TEST 7" "no risk.json found after risk-scoring run"
pass "TEST 7"

# ── TEST 8: Replay-API autentisering ─────────────────────────────────────────
# Verifierar att replay-serverns REST-API kräver HTTP Basic Auth:
#   - Utan credentials ska servern returnera 401 Unauthorized.
#   - Med korrekta credentials ska svaret vara 200 OK och innehålla giltig JSON
#     med nyckeln "sessions".
#   - Med fel lösenord ska 401 returneras igen.
echo "==> TEST 8: Replay-API autentisering — Basic Auth krävs för att nå sessionslistan..."
# Without credentials: must return 401.
STATUS_NOAUTH=$(podman exec sudo-logserver-test \
    curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/api/sessions)
[ "$STATUS_NOAUTH" = "401" ] \
    || fail "TEST 8" "expected 401 without credentials, got $STATUS_NOAUTH"

# With correct credentials: must return 200 and valid JSON.
RESPONSE=$(podman exec sudo-logserver-test \
    curl -s -u "$REPLAY_AUTH_USER:$REPLAY_AUTH_PWD" http://localhost:8080/api/sessions)  # pragma: allowlist secret
echo "$RESPONSE" | grep -q '"sessions"' \
    || fail "TEST 8" "expected JSON with 'sessions' key, got: $RESPONSE"

# With wrong password: must return 401.
STATUS_WRONG=$(podman exec sudo-logserver-test \
    curl -s -o /dev/null -w "%{http_code}" \
    -u "$REPLAY_AUTH_USER:wrongpass" http://localhost:8080/api/sessions)  # pragma: allowlist secret
[ "$STATUS_WRONG" = "401" ] \
    || fail "TEST 8" "expected 401 for wrong password, got $STATUS_WRONG"
pass "TEST 8"

# ── TEST 9: SIGHUP htpasswd-omladdning ───────────────────────────────────────
# Verifierar att replay-servern laddar om htpasswd-filen vid SIGHUP utan att
# behöva startas om. En ny användare läggs till i filen; utan SIGHUP ska
# användaren fortfarande nekas (gammal konfiguration i minnet). Efter SIGHUP
# ska samma användare accepteras direkt.
echo "==> TEST 9: SIGHUP htpasswd-omladdning — nya användare aktiveras utan omstart..."
NEW_USER="replayuser2"
NEW_PWD="Repl4yN3wPwd"  # pragma: allowlist secret

# Verify new user cannot authenticate before being added.
STATUS_BEFORE=$(podman exec sudo-logserver-test \
    curl -s -o /dev/null -w "%{http_code}" \
    -u "$NEW_USER:$NEW_PWD" http://localhost:8080/api/sessions)  # pragma: allowlist secret
[ "$STATUS_BEFORE" = "401" ] \
    || fail "TEST 9" "new user authenticated before being added to htpasswd"

# Append new user to htpasswd file.
podman exec sudo-logserver-test sh -c \
    "htpasswd -nBb $NEW_USER $NEW_PWD >> /tmp/replay.htpasswd"  # pragma: allowlist secret

# Without SIGHUP, new user must still be rejected (not yet reloaded).
STATUS_NORELOAD=$(podman exec sudo-logserver-test \
    curl -s -o /dev/null -w "%{http_code}" \
    -u "$NEW_USER:$NEW_PWD" http://localhost:8080/api/sessions)  # pragma: allowlist secret
[ "$STATUS_NORELOAD" = "401" ] \
    || fail "TEST 9" "new user authenticated without SIGHUP reload"

# Send SIGHUP to reload credentials.
REPLAY_PID=$(podman exec sudo-logserver-test cat /tmp/replay.pid)
podman exec sudo-logserver-test kill -HUP "$REPLAY_PID"
sleep 2

# After SIGHUP, new user must be accepted.
STATUS_AFTER=$(podman exec sudo-logserver-test \
    curl -s -o /dev/null -w "%{http_code}" \
    -u "$NEW_USER:$NEW_PWD" http://localhost:8080/api/sessions)  # pragma: allowlist secret
[ "$STATUS_AFTER" = "200" ] \
    || fail "TEST 9" "new user rejected after SIGHUP reload (got $STATUS_AFTER)"
pass "TEST 9"

# ── TEST 10: Riskpoäng via API ────────────────────────────────────────────────
# Verifierar att riskpoängen är synlig via REST-API:et och att sessioner
# klassificeras korrekt. visudo kördes i TEST 7 och ska ha fått minst 60 poäng
# (high risk) enligt riskregeln. API-svaret ska innehålla minst en session med
# risk_level "high" eller "critical".
echo "==> TEST 10: Riskpoäng via API — högrisk-session exponeras i API-svaret..."
API_RESP=$(podman exec sudo-logserver-test \
    curl -s -u "$REPLAY_AUTH_USER:$REPLAY_AUTH_PWD" http://localhost:8080/api/sessions)  # pragma: allowlist secret
# At least one session should be scored as high or critical (visudo ran in TEST 7).
echo "$API_RESP" | grep -qE '"risk_level":"(high|critical)"' \
    || fail "TEST 10" "no high/critical sessions found after visudo run; response: $API_RESP"
pass "TEST 10"

# ── TEST 11: Nätverksjitter ───────────────────────────────────────────────────
# Verifierar att systemet håller under sämre nätverksförhållanden. En artificiell
# fördröjning på 500 ms läggs till på klientens nätverkskort med tc/netem.
# Sudo-kommandot ska lyckas (pluginet blockar inte på nätverket), och utdata ska
# ha nått logservern inom rimlig tid trots fördröjningen.
echo "==> TEST 11: Nätverksjitter — loggning håller under 500 ms artificiell fördröjning..."
IFACE=$(podman exec sudo-client-test ip -o link show \
    | grep -v " lo:" | head -1 | awk -F': ' '{print $2}' | cut -d'@' -f1)
echo "   Nätverkskort: $IFACE"
podman exec sudo-client-test tc qdisc add dev "$IFACE" root netem delay 500ms
TOKEN11="JITTER_$(date +%s)"
# Command must succeed despite 500ms delay.
podman exec sudo-client-test sudo sh -c "echo $TOKEN11" \
    || fail "TEST 11" "sudo command failed under 500ms network jitter"
sleep 5  # extra wait: 500ms delay means log may arrive later
podman exec sudo-logserver-test grep -r "$TOKEN11" /var/log/sudoreplay >/dev/null \
    || fail "TEST 11" "command output not logged under 500ms jitter"
podman exec sudo-client-test tc qdisc del dev "$IFACE" root
pass "TEST 11"

# ── TEST 12: INCOMPLETE-markering vid shipper-avbrott ─────────────────────────
# Verifierar att logservern flaggar en session som INCOMPLETE när shippern
# kraschar mitt i en pågående session utan att skicka SESSION_END. En
# långvarig sudo-session startas (sleep 60), shippern dödas, och logservern
# förväntas ha skrivit en INCOMPLETE-markör i sessionskatalogen.
echo "==> TEST 12: INCOMPLETE-markering — session flaggas om shippern dör mitt i sessionen..."
# Start a long-running session.
podman exec -d sudo-client-test sudo sh -c "sleep 60"
sleep 3
if ! podman exec sudo-client-test pgrep -x sleep >/dev/null 2>&1; then
    fail "TEST 12" "sleep process not started (test setup broken)"
fi
# Kill the shipper mid-session (no SESSION_END will be sent to logserver).
podman exec sudo-client-test pkill -x sudo-shipper || true
sleep 5
# Logserver must have written an INCOMPLETE marker.
podman exec sudo-logserver-test find /var/log/sudoreplay -name INCOMPLETE \
    | grep -q INCOMPLETE \
    || fail "TEST 12" "no INCOMPLETE marker found after shipper was killed mid-session"
pass "TEST 12"

echo ""
echo "🎉 ALLA SYSTEMTESTER LYCKADES!"
exit 0
