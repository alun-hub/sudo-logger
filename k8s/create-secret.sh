#!/bin/bash
# create-secret.sh — create the Kubernetes Secret from PKI files.
#
# Usage:
#   bash create-secret.sh /path/to/pki [--dry-run]
#
# The PKI directory must contain:
#   ca/ca.crt
#   server/server.crt
#   server/server.key
#   hmac.key
#
# Applies directly to the cluster unless --dry-run is passed.
set -euo pipefail

PKI_DIR="${1:?Usage: $0 <pki-dir> [--dry-run]}"
DRY_RUN="${2:-}"

KUBECTL_ARGS=""
if [[ "$DRY_RUN" == "--dry-run" ]]; then
    KUBECTL_ARGS="--dry-run=client -o yaml"
fi

kubectl create secret generic sudo-logger-tls \
    --namespace sudo-logger \
    --from-file=ca.crt="${PKI_DIR}/ca/ca.crt" \
    --from-file=server.crt="${PKI_DIR}/server/server.crt" \
    --from-file=server.key="${PKI_DIR}/server/server.key" \
    --from-file=hmac.key="${PKI_DIR}/hmac.key" \
    --save-config \
    $KUBECTL_ARGS

echo "Secret sudo-logger-tls created in namespace sudo-logger."
