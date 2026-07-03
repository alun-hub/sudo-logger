#!/bin/bash
# setup.sh — bootstrap PKI och HMAC-nyckel för sudo-logger
# Kör EN gång på CA-maskinen, distribuera sedan certs till klienter/server.
set -euo pipefail

OUTDIR="${1:-/tmp/sudo-logger-pki}"
SERVER_HOSTNAME="${2:-logserver.example.com}"
mkdir -p "$OUTDIR"/{ca,server,client}
echo "==> Serverhostname: $SERVER_HOSTNAME"

echo "==> Genererar CA"
openssl genrsa -out "$OUTDIR/ca/ca.key" 4096
openssl req -x509 -new -nodes \
    -key "$OUTDIR/ca/ca.key" \
    -sha256 -days 3650 \
    -subj "/CN=sudo-logger CA" \
    -out "$OUTDIR/ca/ca.crt"

echo "==> Genererar servernyckel och certifikat (SAN=$SERVER_HOSTNAME)"
openssl genrsa -out "$OUTDIR/server/server.key" 2048
openssl req -new \
    -key "$OUTDIR/server/server.key" \
    -subj "/CN=$SERVER_HOSTNAME" \
    -out "$OUTDIR/server/server.csr"
openssl x509 -req -days 3650 \
    -in  "$OUTDIR/server/server.csr" \
    -CA  "$OUTDIR/ca/ca.crt" \
    -CAkey "$OUTDIR/ca/ca.key" \
    -CAcreateserial \
    -extfile <(printf "subjectAltName=DNS:%s" "$SERVER_HOSTNAME") \
    -out "$OUTDIR/server/server.crt"

echo "==> Genererar klientnyckel och certifikat (ett per klient i produktion)"
openssl genrsa -out "$OUTDIR/client/client.key" 2048
openssl req -new \
    -key "$OUTDIR/client/client.key" \
    -subj "/CN=sudo-client" \
    -out "$OUTDIR/client/client.csr"
openssl x509 -req -days 365 \
    -in  "$OUTDIR/client/client.csr" \
    -CA  "$OUTDIR/ca/ca.crt" \
    -CAkey "$OUTDIR/ca/ca.key" \
    -CAcreateserial \
    -out "$OUTDIR/client/client.crt"

echo ""
echo "PKI klar i $OUTDIR"
echo ""
echo "Installera på SERVERN:"
echo "  dnf install sudo-logger-server-1.20.16-1.fc43.x86_64.rpm"
echo "  cp $OUTDIR/ca/ca.crt               /etc/sudo-logger/"
echo "  cp $OUTDIR/server/server.crt        /etc/sudo-logger/"
echo "  cp $OUTDIR/server/server.key        /etc/sudo-logger/"
echo "  chown root:sudologger /etc/sudo-logger/server.key"
echo "  chmod 640 /etc/sudo-logger/server.key"
echo "  systemctl enable --now sudo-logserver"
echo ""
echo "  # Sudo-logserver genererar ack-sign.key och ack-verify.key automatiskt."
echo "  # Kopiera ack-verify.key till alla klienter:"
echo "  # scp /etc/sudo-logger/ack-verify.key klient:/etc/sudo-logger/"
echo ""
echo "Installera på varje KLIENT:"
echo "  dnf install sudo-logger-client-1.20.123-1.fc43.x86_64.rpm"
echo "  cp $OUTDIR/ca/ca.crt               /etc/sudo-logger/"
echo "  cp $OUTDIR/client/client.crt        /etc/sudo-logger/"
echo "  cp $OUTDIR/client/client.key        /etc/sudo-logger/"
echo "  # Kopiera ack-verify.key från servern till /etc/sudo-logger/"
echo "  chmod 600 /etc/sudo-logger/client.key"
echo ""
echo "  # Konfigurera loggserverns adress i /etc/sudo-logger/agent.conf:"
echo "  # server = logserver.example.com:9876"
echo ""
echo "  systemctl enable --now sudo-logger-agent"
