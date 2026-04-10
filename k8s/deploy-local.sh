#!/usr/bin/env bash
# deploy-local.sh — Deploy sudo-logger (distributed mode) on a local k8s cluster.
#
# Prerequisites:
#   - kubectl configured and pointing to your local cluster
#   - PKI files in ../pki/ (ca.crt, server.crt, server.key, hmac.key)
#   - Docker image built and accessible to the cluster
#
# Usage:
#   bash deploy-local.sh [--image <image>] [--dry-run]
#
# Example:
#   bash deploy-local.sh --image ghcr.io/alun-hub/sudo-logserver:1.14.0
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKI_DIR="${SCRIPT_DIR}/../pki"
NAMESPACE="sudo-logger"
IMAGE="${IMAGE:-ghcr.io/alun-hub/sudo-logserver:latest}"
DRY_RUN=false

# Credentials — override via env vars before running.
S3_ACCESS_KEY="${S3_ACCESS_KEY:-minioadmin}"
S3_SECRET_KEY="${S3_SECRET_KEY:-minioadmin}"
DB_USER="${DB_USER:-sudologger}"
DB_PASSWORD="${DB_PASSWORD:-sudologger}"
DB_NAME="sudologger"

for arg in "$@"; do
  case "$arg" in
    --image) shift; IMAGE="$1"; shift ;;
    --dry-run) DRY_RUN=true ;;
  esac
done

log() { echo "[deploy] $*"; }
die() { echo "[ERROR] $*" >&2; exit 1; }

if $DRY_RUN; then
  log "DRY RUN — no changes will be applied"
  KUBECTL="kubectl --dry-run=client"
else
  KUBECTL="kubectl"
fi

# ── Validate PKI ─────────────────────────────────────────────────────────────
# Prefer /etc/sudo-logger (running installation) over the repo pki/ directory.
if [[ -f /etc/sudo-logger/ack-sign.key ]]; then
  PKI_DIR="/etc/sudo-logger"
  log "Using PKI from ${PKI_DIR}"
fi
for f in ca.crt server.crt server.key ack-sign.key; do
  [[ -f "${PKI_DIR}/${f}" ]] || die "Missing PKI file: ${PKI_DIR}/${f}"
done
log "PKI files found."

# ── Namespace ─────────────────────────────────────────────────────────────────
log "Creating namespace ${NAMESPACE}..."
$KUBECTL apply -f "${SCRIPT_DIR}/namespace.yaml"

# ── TLS Secret ────────────────────────────────────────────────────────────────
# PKI files may be root-owned (mode 600). Copy to a temp dir to allow reading.
log "Creating TLS secret sudo-logger-tls..."
TMP_PKI=$(mktemp -d)
trap 'rm -rf "${TMP_PKI}"' EXIT

for f in ca.crt server.crt server.key ack-sign.key; do
  sudo install -m 644 "${PKI_DIR}/${f}" "${TMP_PKI}/${f}"
done

$KUBECTL create secret generic sudo-logger-tls \
  --namespace "${NAMESPACE}" \
  --from-file=ca.crt="${TMP_PKI}/ca.crt" \
  --from-file=server.crt="${TMP_PKI}/server.crt" \
  --from-file=server.key="${TMP_PKI}/server.key" \
  --from-file=ack-sign.key="${TMP_PKI}/ack-sign.key" \
  --save-config \
  --dry-run=client -o yaml | kubectl apply -f -

rm -rf "${TMP_PKI}"
trap - EXIT

# ── Distributed storage credentials ──────────────────────────────────────────
DB_URL="postgres://${DB_USER}:${DB_PASSWORD}@postgresql:5432/${DB_NAME}?sslmode=disable"

log "Creating distributed storage secret sudo-logger-distributed..."
$KUBECTL create secret generic sudo-logger-distributed \
  --namespace "${NAMESPACE}" \
  --from-literal=s3-access-key="${S3_ACCESS_KEY}" \
  --from-literal=s3-secret-key="${S3_SECRET_KEY}" \
  --from-literal=db-user="${DB_USER}" \
  --from-literal=db-password="${DB_PASSWORD}" \
  --from-literal=db-url="${DB_URL}" \
  --save-config \
  --dry-run=client -o yaml | kubectl apply -f -

# ── MinIO + PostgreSQL ────────────────────────────────────────────────────────
log "Deploying PostgreSQL..."
$KUBECTL apply -f "${SCRIPT_DIR}/postgresql.yaml"

log "Deploying MinIO..."
$KUBECTL apply -f "${SCRIPT_DIR}/minio.yaml"

# ── logserver service (NodePort for shippers) ─────────────────────────────────
log "Applying logserver service..."
$KUBECTL apply -f "${SCRIPT_DIR}/service.yaml"

if $DRY_RUN; then
  log "DRY RUN — skipping wait and image patch."
  log "Next: re-run without --dry-run to deploy."
  exit 0
fi

# ── Wait for PostgreSQL ───────────────────────────────────────────────────────
log "Waiting for PostgreSQL to be ready (up to 120s)..."
kubectl rollout status statefulset/postgresql -n "${NAMESPACE}" --timeout=120s

# ── Wait for MinIO ────────────────────────────────────────────────────────────
log "Waiting for MinIO to be ready (up to 120s)..."
kubectl rollout status statefulset/minio -n "${NAMESPACE}" --timeout=120s

# ── Wait for bucket job ───────────────────────────────────────────────────────
log "Waiting for minio-create-bucket job (up to 120s)..."
kubectl wait --for=condition=complete job/minio-create-bucket \
  -n "${NAMESPACE}" --timeout=120s || {
    log "Bucket job not done yet — check: kubectl logs -n ${NAMESPACE} job/minio-create-bucket"
}

# ── Patch image if custom ─────────────────────────────────────────────────────
patch_image() {
  local deploy="$1"
  local container="$2"
  kubectl set image deployment/"${deploy}" "${container}=${IMAGE}" \
    -n "${NAMESPACE}" 2>/dev/null || true
}

# ── Deploy logserver (distributed) ───────────────────────────────────────────
log "Deploying sudo-logserver (distributed mode)..."
kubectl apply -f "${SCRIPT_DIR}/deployment-distributed.yaml"
[[ "${IMAGE}" != "ghcr.io/alun-hub/sudo-logserver:latest" ]] && \
  patch_image sudo-logserver sudo-logserver

# ── Deploy replay server ──────────────────────────────────────────────────────
log "Deploying sudo-replay-server..."
kubectl apply -f "${SCRIPT_DIR}/replay-server.yaml"
[[ "${IMAGE}" != "ghcr.io/alun-hub/sudo-logserver:latest" ]] && \
  patch_image sudo-replay-server sudo-replay-server

# ── Wait for rollouts ─────────────────────────────────────────────────────────
log "Waiting for sudo-logserver rollout..."
kubectl rollout status deployment/sudo-logserver -n "${NAMESPACE}" --timeout=120s

log "Waiting for sudo-replay-server rollout..."
kubectl rollout status deployment/sudo-replay-server -n "${NAMESPACE}" --timeout=120s

# ── Summary ───────────────────────────────────────────────────────────────────
NODE_IP=$(kubectl get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')
log ""
log "Deployment complete!"
log ""
log "  Replay UI:   http://${NODE_IP}:30080"
log "  Log server:  ${NODE_IP}:9876  (mTLS — use shippers with client certs)"
log "  MinIO:       http://${NODE_IP}  (no NodePort — internal only)"
log ""
log "Useful commands:"
log "  kubectl get pods -n ${NAMESPACE}"
log "  kubectl logs -n ${NAMESPACE} deployment/sudo-logserver"
log "  kubectl logs -n ${NAMESPACE} deployment/sudo-replay-server"
