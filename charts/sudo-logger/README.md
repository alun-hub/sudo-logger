# sudo-logger Helm Chart

This chart installs the sudo-logger central log server and replay server.

## Prerequisites

- Kubernetes 1.19+
- Helm 3.2.0+
- (Optional) Ingress controller if exposing the replay server externally

## Installation

### Local Storage (Default)

By default, the chart uses a single PersistentVolumeClaim for session storage,
generates a self-signed CA and server certificate, and generates an ed25519
ACK-signing key — all on first install, persisted across `helm upgrade`. No
values are required to get a working install:

```bash
helm install sudo-logger ./charts/sudo-logger
```

```bash
kubectl get svc sudo-logger-logserver   # NodePort — agent-facing TLS port (9876)
kubectl get svc sudo-logger-replay      # ClusterIP — put behind ingress.enabled or port-forward to reach it
kubectl port-forward svc/sudo-logger-replay 8080:80
```

### Distributed Storage

For high availability and scalability, use PostgreSQL and S3-compatible
storage (bundled Bitnami subcharts, enabled here):

```bash
helm install sudo-logger ./charts/sudo-logger \
  --set storage.type=distributed \
  --set postgresql.enabled=true \
  --set minio.enabled=true
```

The chart generates random PostgreSQL/MinIO credentials on first install
(Secret `sudo-logger-distributed-auth`, persisted across upgrades) and wires
them into both the bundled subcharts and the logserver/replay containers
automatically. It also provisions a separate, independent CA/cert pair for
PostgreSQL (Secret `sudo-logger-postgres-tls`) and connects with
`sslmode=verify-full` — the logserver/replay containers verify PostgreSQL's
certificate, but PostgreSQL does not require a client certificate back (see
`values.yaml`'s comment on `postgresql.tls` for why).

### JIT Approval

Wired in on both local and distributed storage, disabled by default (matching
the server's own default when no policy is configured). Enable it via values:

```bash
helm install sudo-logger ./charts/sudo-logger \
  --set approval.policy.enabled=true \
  --set approval.policy.notifications.webhook_url=https://your-mattermost/hooks/... \
  --set approval.policy.notifications.webhook_secret=<a-strong-secret>
```

See `values.yaml`'s `approval.policy` block for the full field list (mirrors
`/etc/sudo-logger/approval-policy.yaml` — INSTALLATION.md section 5). Settings
saved later via the Replay UI's **Settings → JIT Approval** page take
precedence over this at runtime; it only seeds the initial fallback. The
bearer token shared between logserver and replay for the approvals REST API
is auto-generated (Secret `<release>-approval-token`, persisted across
upgrades) unless you set `approval.existingTokenSecret`.

### cert-manager TLS mode

```bash
helm install sudo-logger ./charts/sudo-logger \
  --set tls.mode=cert-manager \
  --set tls.certManager.issuerRef.name=<your-issuer> \
  --set tls.certManager.issuerRef.kind=ClusterIssuer
```

Requires cert-manager already installed with a working Issuer/ClusterIssuer.
**The issuer must be CA-backed** (e.g. a cert-manager `CA` issuer, not an ACME
one like Let's Encrypt) — this system needs the `ca.crt` cert-manager
populates in the resulting Secret for a CA-typed issuer, to verify client
certs on the agent-facing mTLS endpoint; an ACME issuer's Secret won't have
one. Verified by rendering (`helm template`) only — no cert-manager
installation was available to test a real issuance against.

### Connecting a monitored host (agent)

The agent needs a client certificate signed by the same CA as the server, plus
the CA cert and the `ack-verify.key` (public half of the signing key). Extract
them from the generated secrets and mint a client cert:

```bash
kubectl get secret sudo-logger-tls -o jsonpath='{.data.ca\.crt}' | base64 -d > ca.crt
kubectl get secret sudo-logger-tls -o jsonpath='{.data.ca\.key}' | base64 -d > ca.key

openssl req -newkey ed25519 -nodes -keyout client.key -out client.csr \
  -subj "/CN=<monitored-host-name>"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days 825 -out client.crt

kubectl get secret sudo-logger-signing-key -o jsonpath='{.data.ack-sign\.key}' \
  | base64 -d | openssl pkey -pubout > ack-verify.key
```

Copy `ca.crt`, `client.crt`, `client.key`, and `ack-verify.key` to the
monitored host and configure `/etc/sudo-logger/agent.conf` per
[INSTALLATION.md](../../INSTALLATION.md) section 1.F, pointing `server` at the
`sudo-logger-logserver` Service's external address.

## Configuration

The following table lists the configurable parameters of the sudo-logger chart and their default values.

| Parameter | Description | Default |
| --- | --- | --- |
| `replicaCount` | Number of logserver replicas (distributed storage only — local storage is always 1) | `1` |
| `image.repository` | Logserver image repository (same combined image as `replay.image.repository`) | `ghcr.io/alun-hub/sudo-logger` |
| `image.tag` | Logserver image tag | defaults to `Chart.AppVersion` |
| `storage.type` | Storage type (`local` or `distributed`) | `local` |
| `storage.local.size` | PVC size for local storage | `10Gi` |
| `storage.distributed.s3.bucket` | S3 bucket name | `sudo-logs` |
| `storage.distributed.s3.endpoint` | S3 endpoint; empty = bundled MinIO | `""` |
| `storage.distributed.dbHost` | PostgreSQL host; empty = bundled PostgreSQL | `""` |
| `logserver.service.type` | Service type for the agent-facing TLS port — needs to be reachable from monitored hosts | `NodePort` |
| `tls.mode` | TLS mode (`self-signed`, `provided`, or `cert-manager`) | `self-signed` |
| `tls.existingSecret` | Use an existing Secret (`ca.crt`/`tls.crt`/`tls.key`) instead of chart-managed | `""` |
| `tls.certManager.issuerRef.name` | cert-manager Issuer/ClusterIssuer name (required when `tls.mode=cert-manager`) | `""` |
| `signingKey.existingSecret` | Use an existing Secret (`ack-sign.key`) instead of chart-managed | `""` |
| `approval.policy.enabled` | Enable JIT Approval | `false` |
| `approval.existingTokenSecret` | Use an existing Secret (`token`) instead of chart-managed | `""` |
| `postgresql.enabled` | Enable bundled PostgreSQL | `false` |
| `postgresql.tls.enabled` | Encrypt the bundled PostgreSQL connection (`sslmode=verify-full`) | `true` |
| `minio.enabled` | Enable bundled MinIO | `false` |
| `replay.replicaCount` | Number of replay-server replicas | `1` |
| `ingress.enabled` | Enable ingress for replay-server | `false` |

Refer to [values.yaml](values.yaml) for full configuration details.

## Uninstallation

To uninstall/delete the `sudo-logger` deployment:

```bash
helm uninstall sudo-logger
```

Note: the generated Secrets (`sudo-logger-tls`, `sudo-logger-signing-key`,
`sudo-logger-distributed-auth`, `sudo-logger-postgres-tls`,
`<release>-approval-token`) are not owned by Helm hooks and persist after
`helm uninstall` by design, so a later `helm install` reuses the same
certs/keys/credentials rather than silently breaking every connected agent or
disabling in-flight approvals. Delete them manually if you want a fully clean
slate.
