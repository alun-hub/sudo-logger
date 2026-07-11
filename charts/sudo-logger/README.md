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
automatically.

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
| `tls.mode` | TLS mode (`self-signed` or `provided`) | `self-signed` |
| `tls.existingSecret` | Use an existing Secret (`ca.crt`/`tls.crt`/`tls.key`) instead of chart-managed | `""` |
| `signingKey.existingSecret` | Use an existing Secret (`ack-sign.key`) instead of chart-managed | `""` |
| `postgresql.enabled` | Enable bundled PostgreSQL | `false` |
| `minio.enabled` | Enable bundled MinIO | `false` |
| `replay.replicaCount` | Number of replay-server replicas | `1` |
| `ingress.enabled` | Enable ingress for replay-server | `false` |

Refer to [values.yaml](values.yaml) for full configuration details.

### Known gaps

- **The bundled PostgreSQL connection uses `sslmode=disable`** (plaintext
  within the cluster network). This matches the same convention already used
  by `INSTALLATION.md`'s manual distributed setup and `k8s/deploy-local.sh` —
  not a regression specific to this chart — but it means DB traffic between
  the logserver/replay pods and PostgreSQL isn't encrypted. Provisioning a
  server cert for the bundled PostgreSQL StatefulSet (signed by the same CA
  this chart generates) and switching to `sslmode=verify-full` would close
  this; not done here to keep scope proportionate to the rest of the project.
- **`cert-manager` TLS mode is not implemented.** Only `self-signed` and
  `provided` work today. Use `tls.existingSecret` to point at a
  cert-manager-issued Secret yourself as a workaround (it must contain
  `ca.crt`/`tls.crt`/`tls.key`).
- **JIT Approval is not wired into this chart.** It stays disabled (matching
  the server's own default when `-approval-policy` points at a file that
  doesn't exist). Mount a ConfigMap at `/etc/sudo-logger/approval-policy.yaml`
  yourself if you need it — see `k8s/configmap.yaml` for a working example.

## Uninstallation

To uninstall/delete the `sudo-logger` deployment:

```bash
helm uninstall sudo-logger
```

Note: the generated Secrets (`sudo-logger-tls`, `sudo-logger-signing-key`,
`sudo-logger-distributed-auth`) are not owned by Helm hooks and persist after
`helm uninstall` by design, so a later `helm install` reuses the same
certs/keys/credentials rather than silently breaking every connected agent.
Delete them manually if you want a fully clean slate.
