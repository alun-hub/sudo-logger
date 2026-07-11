#!/bin/bash
# setup.sh — bootstrap a self-signed CA, server certificate, and a client
# certificate for sudo-logger. Run once on a secure machine, then distribute
# the resulting files as described below. For installing the actual
# packages/services, see INSTALLATION.md — this script only handles PKI.
set -euo pipefail

OUTDIR="${1:-/tmp/sudo-logger-pki}"
SERVER_HOSTNAME="${2:-logserver.example.com}"
mkdir -p "$OUTDIR"
echo "==> Server hostname (used as the certificate SAN): $SERVER_HOSTNAME"

echo "==> Generating CA"
openssl req -x509 -newkey ed25519 -nodes -days 3650 \
    -keyout "$OUTDIR/ca.key" -out "$OUTDIR/ca.crt" \
    -subj "/CN=sudo-logger CA"

echo "==> Generating server key and certificate (SAN=$SERVER_HOSTNAME)"
cat > "$OUTDIR/server-san.cnf" <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
[req_distinguished_name]
[v3_req]
subjectAltName = @alt_names
[alt_names]
DNS.1 = $SERVER_HOSTNAME
EOF
openssl req -newkey ed25519 -nodes \
    -keyout "$OUTDIR/server.key" -out "$OUTDIR/server.csr" \
    -subj "/CN=$SERVER_HOSTNAME" -config "$OUTDIR/server-san.cnf" -reqexts v3_req
openssl x509 -req -days 3650 \
    -in "$OUTDIR/server.csr" \
    -CA "$OUTDIR/ca.crt" -CAkey "$OUTDIR/ca.key" -CAcreateserial \
    -copy_extensions copy \
    -out "$OUTDIR/server.crt"
rm -f "$OUTDIR/server.csr" "$OUTDIR/server-san.cnf"

echo "==> Generating client key and certificate (mint one per monitored host in production — re-run with a different OUTDIR, or add a loop)"
openssl req -newkey ed25519 -nodes \
    -keyout "$OUTDIR/client.key" -out "$OUTDIR/client.csr" \
    -subj "/CN=sudo-client" \
    2>/dev/null
openssl x509 -req -days 825 \
    -in "$OUTDIR/client.csr" \
    -CA "$OUTDIR/ca.crt" -CAkey "$OUTDIR/ca.key" -CAcreateserial \
    -out "$OUTDIR/client.crt"
rm -f "$OUTDIR/client.csr"

echo ""
echo "PKI ready in $OUTDIR:"
echo "  ca.crt        # CA certificate — copy to every server and client"
echo "  ca.key        # CA private key — keep secure, needed to mint more client certs, do not distribute"
echo "  server.crt / server.key  # log server's TLS certificate/key"
echo "  client.crt / client.key  # one client's TLS certificate/key (mint more with the CA above as needed)"
echo ""
echo "The Ed25519 ACK-signing key pair (ack-sign.key / ack-verify.key) is a"
echo "separate concern from the CA above — see INSTALLATION.md's"
echo "\"About ack-sign.key\" section for how it's obtained for your chosen"
echo "deployment mode."
echo ""
echo "For installing the server/client packages and placing these files,"
echo "see INSTALLATION.md in the repository root."
