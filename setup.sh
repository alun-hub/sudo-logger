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

echo "==> Genererar HMAC-nyckel (32 bytes)"
openssl rand -out "$OUTDIR/hmac.key" 32

echo ""
echo "PKI klar i $OUTDIR"
echo ""
echo "Installera på SERVERN:"
echo "  dnf install sudo-logger-server-1.0-1.fc43.x86_64.rpm"
echo "  cp $OUTDIR/ca/ca.crt               /etc/sudo-logger/"
echo "  cp $OUTDIR/server/server.crt        /etc/sudo-logger/"
echo "  cp $OUTDIR/server/server.key        /etc/sudo-logger/"
echo "  cp $OUTDIR/hmac.key                 /etc/sudo-logger/"
echo "  chown sudologger: /etc/sudo-logger/server.key /etc/sudo-logger/hmac.key"
echo "  chmod 600 /etc/sudo-logger/server.key /etc/sudo-logger/hmac.key"
echo "  systemctl enable --now sudo-logserver"
echo ""
echo "Installera på varje KLIENT:"
echo "  dnf install sudo-logger-client-1.0-1.fc43.x86_64.rpm"
echo "  cp $OUTDIR/ca/ca.crt               /etc/sudo-logger/"
echo "  cp $OUTDIR/client/client.crt        /etc/sudo-logger/"
echo "  cp $OUTDIR/client/client.key        /etc/sudo-logger/"
echo "  cp $OUTDIR/hmac.key                 /etc/sudo-logger/"
echo "  chmod 600 /etc/sudo-logger/client.key /etc/sudo-logger/hmac.key"
echo ""
echo "  # Konfigurera serveradress via systemd override:"
echo "  mkdir -p /etc/systemd/system/sudo-shipper.service.d/"
echo "  cat > /etc/systemd/system/sudo-shipper.service.d/server.conf << 'EOF'"
echo "  [Service]"
echo "  ExecStart="
echo "  ExecStart=/usr/bin/sudo-shipper -server DIN-SERVER:9876 \\"
echo "      -socket /run/sudo-logger/plugin.sock \\"
echo "      -cert /etc/sudo-logger/client.crt \\"
echo "      -key /etc/sudo-logger/client.key \\"
echo "      -ca /etc/sudo-logger/ca.crt \\"
echo "      -hmackey /etc/sudo-logger/hmac.key"
echo "  EOF"
echo "  systemctl daemon-reload"
echo "  systemctl enable --now sudo-shipper"
