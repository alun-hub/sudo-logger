#!/bin/bash
# tests/run-load-test.sh — Performance and load test suite for sudo-logger.
set -euo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKI_DIR="$TEST_DIR/pki_load"
mkdir -p "$PKI_DIR"

# ── helpers ────────────────────────────────────────────────────────────────────

pass() { echo "✅ $1 PASSED"; }
fail() { echo "❌ $1 FAILED: ${2:-}"; exit 1; }

# ── PKI setup ──────────────────────────────────────────────────────────────────

echo "==> Genererar test-PKI för belastningstest..."
openssl genrsa -out "$PKI_DIR/ca.key" 2048 2>/dev/null
openssl req -x509 -new -nodes -key "$PKI_DIR/ca.key" -sha256 -days 1 \
    -subj "/CN=Load Test CA" -out "$PKI_DIR/ca.crt" 2>/dev/null
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

chmod 644 "$PKI_DIR"/*

# ── Build binaries ───────────────────────────────────────────────────────────

echo "==> Bygger binärer..."
cd "$TEST_DIR/../go"
go build -o "$TEST_DIR/bin/sudo-logserver" ./cmd/server
go build -o "$TEST_DIR/bin/sudo-logger-agent" ./cmd/agent
go build -o "$TEST_DIR/bin/loadgen" ./cmd/loadgen

# ── Cleanup trap ──────────────────────────────────────────────────────────────

cleanup() {
    echo "==> Städar upp..."
    kill $(cat "$TEST_DIR/logserver.pid" 2>/dev/null) 2>/dev/null || true
    kill $(cat "$TEST_DIR/agent.pid" 2>/dev/null) 2>/dev/null || true
    rm -rf "$PKI_DIR" "$TEST_DIR/bin" "$TEST_DIR/logs" "$TEST_DIR/*.pid"
}
trap cleanup EXIT

mkdir -p "$TEST_DIR/logs"

# ── Start Server ──────────────────────────────────────────────────────────────

echo "==> Startar logserver..."
"$TEST_DIR/bin/sudo-logserver" \
    -listen=:9877 \
    -logdir="$TEST_DIR/logs" \
    -cert="$PKI_DIR/server.crt" \
    -key="$PKI_DIR/server.key" \
    -ca="$PKI_DIR/ca.crt" \
    -signkey="$PKI_DIR/ack-sign.key" > "$TEST_DIR/logserver.out" 2>&1 &
echo $! > "$TEST_DIR/logserver.pid"

sleep 2

# ── Start Agent ───────────────────────────────────────────────────────────────

echo "==> Startar agent..."
# Create a dummy config
cat <<EOF > "$PKI_DIR/agent.conf"
server = localhost:9877
socket = $TEST_DIR/plugin.sock
cert = $PKI_DIR/client.crt
key = $PKI_DIR/client.key
ca = $PKI_DIR/ca.crt
verify_key = $PKI_DIR/ack-verify.key
ebpf = false
EOF

SUDO_LOGGER_INSECURE_TEST=1 "$TEST_DIR/bin/sudo-logger-agent" -config="$PKI_DIR/agent.conf" > "$TEST_DIR/agent.out" 2>&1 &
echo $! > "$TEST_DIR/agent.pid"

sleep 2

# ── Run Load Test ─────────────────────────────────────────────────────────────

PARALLEL=500
CHUNKS=5000
echo "==> Kör belastningstest ($PARALLEL sessioner, $CHUNKS chunks var)..."

"$TEST_DIR/bin/loadgen" -socket="$TEST_DIR/plugin.sock" -parallel=$PARALLEL -chunks=$CHUNKS

echo "==> Väntar på att servern ska skriva klart..."
sleep 5

echo "==> Verifierar resultat..."
# Count session directories that contain a session.cast file
NUM_SESSIONS=$(find "$TEST_DIR/logs" -type f -name "session.cast" | wc -l)
if [ "$NUM_SESSIONS" -ne "$PARALLEL" ]; then
    echo "❌ Belastningstest FAILED: Förväntade $PARALLEL sessioner, hittade $NUM_SESSIONS"
    echo "Faktiska filer i $TEST_DIR/logs:"
    find "$TEST_DIR/logs" -maxdepth 4
    echo "Agent-logg (sista 20 raderna):"
    tail -n 20 "$TEST_DIR/agent.out"
    echo "Logserver-logg (sista 20 raderna):"
    tail -n 20 "$TEST_DIR/logserver.out"
    fail "Belastningstest" "Sessionsantalet stämmer inte"
fi

# Check for errors in server/agent output
if grep -qi "error" "$TEST_DIR/logserver.out"; then
    echo "⚠️ Varning: Hittade fel i logserverns utdata (kan vara förväntat beroende på kontext):"
    grep -i "error" "$TEST_DIR/logserver.out" | head -n 5
fi

pass "Belastningstest"
exit 0
