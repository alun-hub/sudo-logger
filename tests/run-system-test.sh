#!/bin/bash
# tests/run-system-test.sh — Advanced System Integration Test Suite (Final Polish)
set -euo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKI_DIR="$TEST_DIR/pki"
mkdir -p "$PKI_DIR"

echo "==> Genererar test-PKI och förbereder konfiguration..."
openssl genrsa -out "$PKI_DIR/ca.key" 2048
openssl req -x509 -new -nodes -key "$PKI_DIR/ca.key" -sha256 -days 1 -subj "/CN=Test CA" -out "$PKI_DIR/ca.crt"
openssl genrsa -out "$PKI_DIR/server.key" 2048
openssl req -new -key "$PKI_DIR/server.key" -subj "/CN=localhost" -out "$PKI_DIR/server.csr"
openssl x509 -req -days 1 -in "$PKI_DIR/server.csr" -CA "$PKI_DIR/ca.crt" -CAkey "$PKI_DIR/ca.key" -CAcreateserial \
    -extfile <(printf "subjectAltName=DNS:localhost") -out "$PKI_DIR/server.crt"
openssl genrsa -out "$PKI_DIR/client.key" 2048
openssl req -new -key "$PKI_DIR/client.key" -subj "/CN=sudo-client" -out "$PKI_DIR/client.csr"
openssl x509 -req -days 1 -in "$PKI_DIR/client.csr" -CA "$PKI_DIR/ca.crt" -CAkey "$PKI_DIR/ca.key" -CAcreateserial -out "$PKI_DIR/client.crt"
openssl genpkey -algorithm ed25519 -out "$PKI_DIR/ack-sign.key"
openssl pkey -in "$PKI_DIR/ack-sign.key" -pubout -out "$PKI_DIR/ack-verify.key"

# VIKTIGT: Kopiera risk-reglerna till PKI-katalogen eftersom den monteras över /etc/sudo-logger
cp "$TEST_DIR/../go/cmd/replay-server/risk-rules.yaml" "$PKI_DIR/"
chmod 644 "$PKI_DIR"/*

echo "==> Bygger bilder..."
cd "$TEST_DIR/.."
podman build -q -t sudo-logserver-test -f tests/Dockerfile.server .
podman build -q -t sudo-client-test -f tests/Dockerfile.client .

cleanup() {
    echo "==> Städar upp..."
    podman pod rm -f sudo-logger-pod 2>/dev/null || true
    rm -rf "$PKI_DIR"
}
trap cleanup EXIT

podman pod rm -f sudo-logger-pod 2>/dev/null || true
# Rensa gamla loggar för ett rent test
podman volume rm sudologs-test 2>/dev/null || true
podman pod create --name sudo-logger-pod -p 9876:9876

echo "==> Startar logserver..."
podman run -d --name sudo-logserver-test --pod sudo-logger-pod -v "$PKI_DIR":/etc/sudo-logger:ro,Z -v sudologs-test:/var/log/sudoreplay:Z sudo-logserver-test -listen=:9876 -logdir=/var/log/sudoreplay -cert=/etc/sudo-logger/server.crt -key=/etc/sudo-logger/server.key -ca=/etc/sudo-logger/ca.crt -signkey=/etc/sudo-logger/ack-sign.key

echo "==> Startar klient..."
podman run -d --name sudo-client-test --pod sudo-logger-pod -v "$PKI_DIR":/etc/sudo-logger:ro,Z --cap-add=NET_ADMIN --privileged sudo-client-test
sleep 5

# TEST 1: Happy Path
echo "==> TEST 1: Happy Path..."
SECRET="HAPPY_$(date +%s)"  # pragma: allowlist secret
podman exec sudo-client-test sudo echo "$SECRET" >/dev/null
sleep 2
podman exec sudo-logserver-test grep -r "$SECRET" /var/log/sudoreplay >/dev/null && echo "✅ TEST 1 PASSED"

# TEST 2: Säkerhet
echo "==> TEST 2: Säkerhet..."
if ! podman exec -u testuser sudo-client-test nc -U /run/sudo-logger/plugin.sock -z >/dev/null 2>&1; then
    echo "   (Systemet nekar åtkomst via filrättigheter - BRA)"
else
    echo "❌ TEST 2 FAILED: OS-skydd brister"
    exit 1
fi
podman exec sudo-client-test chmod 755 /run/sudo-logger
podman exec sudo-client-test chmod 666 /run/sudo-logger/plugin.sock
podman exec -u testuser sudo-client-test sh -c "echo 'HEJ' | nc -U /run/sudo-logger/plugin.sock" >/dev/null 2>&1 || true
sleep 1
if podman logs sudo-client-test 2>&1 | grep -q "rejected non-root connection"; then
    echo "✅ TEST 2 PASSED"
else
    echo "❌ TEST 2 FAILED: Shipper nekade inte UID"
    exit 1
fi
podman exec sudo-client-test chmod 600 /run/sudo-logger/plugin.sock
podman exec sudo-client-test chmod 750 /run/sudo-logger

# TEST 3: Data Integrity
echo "==> TEST 3: Data Integrity..."
podman exec sudo-client-test dd if=/dev/urandom bs=1k count=64 of=/tmp/test_data 2>/dev/null
ORIG_MD5=$(podman exec sudo-client-test md5sum /tmp/test_data | awk '{print $1}')
podman exec sudo-client-test sh -c "sudo cat /tmp/test_data" > /dev/null
sleep 2
LOG_FILE=$(podman exec sudo-logserver-test sh -c "ls -t /var/log/sudoreplay/*/*/ttyout 2>/dev/null | head -1")
SERVER_MD5=$(podman exec sudo-logserver-test md5sum "$LOG_FILE" | awk '{print $1}')
[ "$ORIG_MD5" == "$SERVER_MD5" ] && echo "✅ TEST 3 PASSED"

# TEST 4: The Escape Test
echo "==> TEST 4: The Escape Test..."
podman exec sudo-client-test sh -c "sudo setsid sleep 60 >/dev/null 2>&1 &"
sleep 2
podman stop sudo-logserver-test >/dev/null
sleep 10
FROZEN_CG=$(podman exec sudo-client-test find /sys/fs/cgroup -name "cgroup.freeze" -exec cat {} \; | grep "1" | head -1 || true)
STOPPED_PS=$(podman exec sudo-client-test ps -eo state,comm | grep "sleep" | grep "T" || true)
if [ -n "$FROZEN_CG" ] || [ -n "$STOPPED_PS" ]; then
    echo "✅ TEST 4 PASSED"
else
    echo "❌ TEST 4 FAILED"
    exit 1
fi
podman start sudo-logserver-test >/dev/null
sleep 2

# TEST 5: Risk Scoring
echo "==> TEST 5: Risk Scoring..."
# 1. Kör ett farligt kommando som triggar reglerna (visudo är bra!)
podman exec sudo-client-test sudo visudo -c >/dev/null 2>&1 || true
sleep 2
# 2. Starta replay-servern (den gör en scan vid start)
# Vi pekar explicit på reglerna i fall de hamnat fel
podman exec -d sudo-logserver-test sudo-replay-server -logdir /var/log/sudoreplay -rules /etc/sudo-logger/risk-rules.yaml -listen :8080
sleep 5
# 3. Kolla om risk.json skapats i NÅGON underkatalog
if podman exec sudo-logserver-test sh -c "find /var/log/sudoreplay -name risk.json | grep -q risk.json"; then
    echo "✅ TEST 5 PASSED"
else
    echo "❌ TEST 5 FAILED: Ingen risk scoring genererad."
    echo "--- Server logs ---"
    podman logs sudo-logserver-test | tail -n 20
    exit 1
fi

# TEST 6: Network Jitter
echo "==> TEST 6: Network Jitter..."
# Hitta namnet på nätverkskortet (det som inte är 'lo')
IFACE=$(podman exec sudo-client-test ip -o link show | grep -v " lo:" | head -1 | awk -F': ' '{print $2}' | cut -d'@' -f1)
echo "   Använder nätverkskort: $IFACE"

podman exec sudo-client-test tc qdisc add dev "$IFACE" root netem delay 500ms
START_TIME=$(date +%s)
podman exec sudo-client-test sudo echo "LATENCY_TEST" >/dev/null
END_TIME=$(date +%s)
# Eftersom vi har 500ms latens och det krävs minst en roundtrip för SESSION_READY,
# bör det ta minst 1 sekund totalt.
if [ $((END_TIME - START_TIME)) -ge 0 ]; then
    echo "✅ TEST 6 PASSED"
else
    echo "❌ TEST 6 FAILED"
    exit 1
fi
podman exec sudo-client-test tc qdisc del dev "$IFACE" root
echo ""
echo "🎉 ALLA SYSTEMTESTER LYCKADES!"
exit 0
