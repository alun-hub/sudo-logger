#!/usr/bin/env bash
# deploy-local.sh — Deploy sudo-logger (distributed mode) on a local k8s cluster.
#
# Prerequisites:
#   - kubectl configured and pointing to your local cluster
#   - PKI files in ../pki/ (ca.crt, server.crt, server.key, ack-sign.key)
#   - Docker image built and accessible to the cluster
#
# Usage:
#   bash deploy-local.sh [--image <image>] [--dry-run]
#
# Example (override the default locally-built image with a published one):
#   bash deploy-local.sh --image ghcr.io/alun-hub/sudo-logger:1.25.5
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKI_DIR="${SCRIPT_DIR}/../pki"
NAMESPACE="sudo-logger"
IMAGE="${IMAGE:-localhost/sudo-logger:latest}"
DRY_RUN=false

# Credentials — override via env vars before running. If unset, reuse the
# existing sudo-logger-distributed Secret's values on a re-run (rotating
# these would break the already-running PostgreSQL/MinIO StatefulSets,
# which only pick up credentials on first init — same reasoning as
# charts/sudo-logger/templates/distributed-auth-secret.yaml's `lookup`),
# else generate fresh random ones. Usernames stay fixed/memorable; only
# the actual secrets are randomized.
existing_secret_field() {
  kubectl get secret sudo-logger-distributed -n "${NAMESPACE}" \
    -o jsonpath="{.data.$1}" 2>/dev/null | base64 -d 2>/dev/null || true
}
S3_ACCESS_KEY="${S3_ACCESS_KEY:-minioadmin}"
S3_SECRET_KEY="${S3_SECRET_KEY:-$(existing_secret_field s3-secret-key)}"
S3_SECRET_KEY="${S3_SECRET_KEY:-$(openssl rand -hex 16)}"
DB_USER="${DB_USER:-sudologger}"
DB_PASSWORD="${DB_PASSWORD:-$(existing_secret_field db-password)}"
DB_PASSWORD="${DB_PASSWORD:-$(openssl rand -hex 16)}"
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

# ── Approval token + policy ────────────────────────────────────────────────────
# Required by deployment-distributed.yaml (secretKeyRef / configMap volume) —
# without them the pod gets stuck in ContainerCreating. Generated once and
# left alone on re-runs so a shared token isn't rotated out from under a
# running deployment.
if kubectl get secret sudo-logger-approval-token -n "${NAMESPACE}" >/dev/null 2>&1; then
  log "sudo-logger-approval-token already exists, leaving it unchanged."
else
  log "Creating sudo-logger-approval-token secret..."
  $KUBECTL create secret generic sudo-logger-approval-token \
    --namespace "${NAMESPACE}" \
    --from-literal=token="$(openssl rand -hex 32)"
fi

log "Applying default approval-policy ConfigMap (JIT approval disabled by default)..."
$KUBECTL apply -f "${SCRIPT_DIR}/configmap.yaml"

# ── MinIO + PostgreSQL ────────────────────────────────────────────────────────
log "Deploying PostgreSQL..."
$KUBECTL apply -f "${SCRIPT_DIR}/postgresql.yaml"

log "Deploying MinIO..."
$KUBECTL apply -f "${SCRIPT_DIR}/minio.yaml"

# ── logserver service (NodePort for agents) ─────────────────────────────────
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
  # Also switch imagePullPolicy to IfNotPresent: the base manifests hardcode
  # "Never" (correct for the locally-built, k3s-imported image), which would
  # otherwise leave a registry image (e.g. --image ghcr.io/...) stuck in
  # ErrImageNeverPull forever.
  kubectl patch deployment/"${deploy}" -n "${NAMESPACE}" --type=strategic -p \
    "{\"spec\":{\"template\":{\"spec\":{\"containers\":[{\"name\":\"${container}\",\"image\":\"${IMAGE}\",\"imagePullPolicy\":\"IfNotPresent\"}]}}}}"
}

# ── Deploy logserver (distributed) ───────────────────────────────────────────
log "Deploying sudo-logserver (distributed mode)..."
kubectl apply -f "${SCRIPT_DIR}/deployment-distributed.yaml"
[[ "${IMAGE}" != "localhost/sudo-logger:latest" ]] && \
  patch_image sudo-logserver sudo-logserver

log "Applying admin-API NetworkPolicy (defense in depth; no-op on CNIs that don't enforce it)..."
$KUBECTL apply -f "${SCRIPT_DIR}/networkpolicy.yaml"

# ── Deploy replay server ──────────────────────────────────────────────────────
log "Deploying sudo-replay-server..."
kubectl apply -f "${SCRIPT_DIR}/replay-server.yaml"
[[ "${IMAGE}" != "localhost/sudo-logger:latest" ]] && \
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
log "  Log server:  ${NODE_IP}:9876  (mTLS — use agents with client certs)"
log "  MinIO:       http://${NODE_IP}  (no NodePort — internal only)"
log ""
log "Useful commands:"
log "  kubectl get pods -n ${NAMESPACE}"
log "  kubectl logs -n ${NAMESPACE} deployment/sudo-logserver"
log "  kubectl logs -n ${NAMESPACE} deployment/sudo-replay-server"
