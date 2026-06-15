# Installation

## Prerequisites

### Operating system

| Requirement | Minimum | Notes |
|---|---|---|
| OS | RHEL 9 / Rocky Linux 9 / Fedora 39 | SELinux enforcing supported |
| Kernel | 5.8+ | Required for eBPF LSM (sandbox feature). Kernel 5.4+ works for eBPF session recording without the sandbox. |
| sudo | 1.9.0+ | I/O plugin API v2 required |

### Ports

Open the following ports on your firewalls before installation:

| Port | Protocol | Direction | Purpose | Required |
|---|---|---|---|---|
| 9876 | TCP (mTLS) | monitored hosts → log server | Session data streaming + ACK channel | Yes |
| 9877 | TCP (plain HTTP) | replay server → log server | Health checks, metrics, JIT approval API | No (needed for approvals) |
| 8080 | TCP (HTTP or HTTPS) | browsers → replay server | Web UI | Yes |

> **Note:** Port 9877 is the `--health-listen` address on the log server. It is plain HTTP — do not expose it to untrusted networks. It carries the approval API, which requires a bearer token, but the transport is unencrypted.

---

## Quick install (RPM)

All three components are distributed as RPM packages built from specs in `rpm/`:

| Package | Contents | Deploy to |
|---|---|---|
| `sudo-logger-client` | `sudo_logger_plugin.so` + `sudo-logger-agent` daemon | Every monitored host |
| `sudo-logger-server` | `sudo-logserver` binary + systemd unit | Log server host |
| `sudo-logger-replay` | `sudo-replay-server` binary + systemd unit | Replay server host |

### 1. On the monitored host (client)

Install the `sudo-logger-client` RPM. The `%post` scriptlet automatically adds the plugin line to `/etc/sudo.conf`:

```bash
dnf install sudo-logger-client-<version>.rpm
```

After install, `/etc/sudo.conf` contains:

```
Plugin sudoers_policy sudoers.so
Plugin sudo_logger_plugin sudo_logger_plugin.so
```

The plugin binary is installed at `/usr/libexec/sudo/sudo_logger_plugin.so`.

> **Note:** On `dnf remove`, the `%preun` scriptlet removes the `Plugin` line automatically.

Install the TLS certificates and ACK verify key (generated in the [TLS certificate setup](#tls-certificate-setup) section below):

```bash
cp ca.crt          /etc/sudo-logger/
cp client.crt      /etc/sudo-logger/
cp client.key      /etc/sudo-logger/
chmod 600          /etc/sudo-logger/client.key

# Copy the ACK verify key from the server host
scp logserver:/etc/sudo-logger/ack-verify.key /etc/sudo-logger/
```

Configure the server address in `/etc/sudo-logger/agent.conf`:

```ini
Server = logserver.example.com:9876
```

Enable and start the agent:

```bash
systemctl enable --now sudo-logger-agent
```

The RPM preset file (`50-sudo-logger-agent.preset`) enables the service automatically on fresh installs. Upgrades use `systemctl enable --now` in `%post` to pick up the new binary.

> **Warning:** The agent unit sets `RefuseManualStop=yes`. Running `systemctl stop sudo-logger-agent` from within a sudo session is blocked. This is intentional: stopping the agent inside a session would evade recording. The host can still be rebooted normally.

Verify the agent is running and connected:

```bash
systemctl status sudo-logger-agent
journalctl -u sudo-logger-agent -n 50
```

### 2. On the log server

Install the `sudo-logger-server` RPM:

```bash
dnf install sudo-logger-server-<version>.rpm
```

Place the server-side TLS certificates and ACK signing key:

```bash
cp ca.crt        /etc/sudo-logger/
cp server.crt    /etc/sudo-logger/
cp server.key    /etc/sudo-logger/
chmod 600        /etc/sudo-logger/server.key

cp ack-sign.key  /etc/sudo-logger/
chmod 600        /etc/sudo-logger/ack-sign.key
```

The server reads its configuration from environment variables loaded by systemd from `/etc/sudo-logger/server.conf`. The minimum required content:

```bash
LISTEN_ADDR=:9876
LOG_DIR=/var/log/sudoreplay
```

To pass additional flags (e.g. `--health-listen`), create a systemd drop-in:

```bash
mkdir -p /etc/systemd/system/sudo-logserver.service.d/
```

```ini
# /etc/systemd/system/sudo-logserver.service.d/override.conf
[Service]
ExecStart=
ExecStart=/usr/bin/sudo-logserver \
    -listen        ${LISTEN_ADDR} \
    -logdir        ${LOG_DIR} \
    -cert          /etc/sudo-logger/server.crt \
    -key           /etc/sudo-logger/server.key \
    -ca            /etc/sudo-logger/ca.crt \
    -signkey       /etc/sudo-logger/ack-sign.key \
    -health-listen :9877
```

Enable and start:

```bash
systemctl daemon-reload
systemctl enable --now sudo-logserver
```

### 3. On the replay server host

Install the `sudo-logger-replay` RPM (often on the same host as the log server):

```bash
dnf install sudo-logger-replay-<version>.rpm
```

Minimum required flags to start (via drop-in or command line):

```bash
sudo-replay-server \
    -logdir      /var/log/sudoreplay \
    -listen      :8080 \
    -admin-users yourusername
```

To enable the JIT approval UI, also pass:

```bash
    -logserver-admin       http://localhost:9877 \
    -logserver-admin-token <shared-secret>
```

The token must match the `-approval-token` flag (or `SUDO_LOGGER_APPROVAL_TOKEN` env var, or `-approval-token-file` file) on the log server.

### Verification

After all three components are installed and running, test end-to-end:

```bash
# On a monitored host — run any sudo command
sudo ls /tmp

# Check the agent forwarded the session
journalctl -u sudo-logger-agent -n 20

# Open the replay UI in a browser
http://replay-server:8080
```

The session should appear in the replay UI within a few seconds.

---

## TLS certificate setup

sudo-logger uses mutual TLS (mTLS) between the agent and the log server. Every deployment requires a CA, a server certificate, and at least one client certificate. Additionally, the log server signs ACKs with an ed25519 key to prevent forgery.

### Certificate hierarchy

```
CA (ca.crt / ca.key)
├── server.crt / server.key   (log server — presented to agents)
└── client.crt / client.key   (agent(s) — presented to log server)

ack-sign.key    (ed25519 private key — log server only, PKCS8 PEM)
ack-verify.key  (ed25519 public key  — deployed to each agent)
```

### Generating certificates with openssl

The repository includes `setup.sh` which automates the following steps. To generate manually:

**Step 1 — CA**

```bash
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt \
    -subj "/CN=sudo-logger CA"
```

**Step 2 — Server certificate**

```bash
openssl genrsa -out server.key 4096
openssl req -new -key server.key -out server.csr \
    -subj "/CN=logserver.example.com"
openssl x509 -req -days 3650 -in server.csr \
    -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt
```

If agents connect by IP address, include a SAN:

```bash
openssl x509 -req -days 3650 -in server.csr \
    -CA ca.crt -CAkey ca.key -CAcreateserial \
    -extfile <(printf "subjectAltName=IP:10.0.0.5,DNS:logserver.example.com") \
    -out server.crt
```

**Step 3 — Client certificate**

```bash
openssl genrsa -out client.key 4096
openssl req -new -key client.key -out client.csr \
    -subj "/CN=agent"
openssl x509 -req -days 3650 -in client.csr \
    -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out client.crt
```

**Step 4 — ACK signing key pair (ed25519)**

```bash
openssl genpkey -algorithm ed25519 -out ack-sign.key
openssl pkey -in ack-sign.key -pubout -out ack-verify.key
```

**Step 5 — File placement**

| File | Host | Path | Permissions |
|---|---|---|---|
| `ca.crt` | log server + all agents | `/etc/sudo-logger/ca.crt` | 0644 |
| `server.crt` | log server | `/etc/sudo-logger/server.crt` | 0644 |
| `server.key` | log server | `/etc/sudo-logger/server.key` | 0600 |
| `client.crt` | all agents | `/etc/sudo-logger/client.crt` | 0644 |
| `client.key` | all agents | `/etc/sudo-logger/client.key` | 0600 |
| `ack-sign.key` | log server | `/etc/sudo-logger/ack-sign.key` | 0600 |
| `ack-verify.key` | all agents | `/etc/sudo-logger/ack-verify.key` | 0644 |

### Shared vs per-machine client certificates

By default, all agents share a single client certificate (`CN=agent`). This is simpler to manage and the recommended starting point.

When `--strict-cert-host` is enabled on the log server, the server reads the CN (and DNS SANs) from the client certificate and verifies it matches the `host` field in the `SESSION_START` message sent by the agent. This prevents one host from impersonating another in the audit log.

With `--strict-cert-host`, each agent needs its own certificate where CN matches the agent's reported hostname:

```bash
openssl genrsa -out host42.key 4096
openssl req -new -key host42.key -out host42.csr \
    -subj "/CN=host42.example.com"
openssl x509 -req -days 3650 -in host42.csr \
    -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out host42.crt
```

| Mode | One cert for all | Rejects impersonation | Management effort |
|---|---|---|---|
| Default (shared cert) | Yes | No | Low |
| `--strict-cert-host` | No (per-machine) | Yes | High |

### Certificate rotation without downtime

1. Generate the new certificate signed by the same CA.
2. If rotating the CA: update `ca.crt` on the log server first (supports both old and new client certs during transition), then roll out to agents.
3. Copy new `client.crt` / `client.key` to `/etc/sudo-logger/` on each agent host.
4. Restart the agent: `systemctl restart sudo-logger-agent`. Active sudo sessions from before the restart complete using the existing TCP connection.
5. Rotate `server.crt` / `server.key` on the log server and restart `sudo-logserver`. Agents reconnect automatically within 2 seconds (`RestartSec=2` on the agent).

### Kubernetes Secrets approach

```bash
kubectl create secret generic sudo-logger-tls \
    --namespace sudo-logger \
    --from-file=ca.crt \
    --from-file=server.crt \
    --from-file=server.key \
    --from-file=ack-sign.key
```

Reference the secret in the deployment:

```yaml
volumes:
  - name: tls
    secret:
      secretName: sudo-logger-tls
      defaultMode: 0400
volumeMounts:
  - name: tls
    mountPath: /etc/sudo-logger
    readOnly: true
```

Agents on monitored hosts outside the cluster still use files in `/etc/sudo-logger/` on the host.

---

## Manual installation (without RPM)

For distributions where RPM is not available.

### 1. Build the plugin

```bash
cd /path/to/sudo-logger/plugin
make
# Output: sudo_logger_plugin.so
```

### 2. Build Go binaries

```bash
cd /path/to/sudo-logger/go
make
# Output: bin/sudo-logger-agent, bin/sudo-logserver, bin/sudo-replay-server
```

### 3. Install files

```bash
# Plugin
install -m 0755 plugin/sudo_logger_plugin.so /usr/libexec/sudo/

# Binaries
install -m 0755 go/bin/sudo-logger-agent    /usr/bin/
install -m 0755 go/bin/sudo-logserver       /usr/bin/
install -m 0755 go/bin/sudo-replay-server   /usr/bin/

# Config directory
install -d -m 0750 /etc/sudo-logger

# Session log directory
install -d -m 0750 /var/log/sudoreplay

# Runtime socket directory
install -d -m 0755 /run/sudo-logger
```

### 4. Add the plugin line to /etc/sudo.conf

```bash
echo 'Plugin sudo_logger_plugin sudo_logger_plugin.so' >> /etc/sudo.conf
```

### 5. Create systemd unit files

```bash
install -m 0644 sudo-logger-agent.service  /usr/lib/systemd/system/
install -m 0644 sudo-logserver.service     /usr/lib/systemd/system/
install -m 0644 sudo-replay.service        /usr/lib/systemd/system/
systemctl daemon-reload
```

### 6. Configure and start

Follow the same configuration steps as the RPM-based install — place certificates, edit `/etc/sudo-logger/agent.conf`, and start services.

> **Note:** The RPM also installs the SELinux policy module (`sudo_logger.pp`). On manual installs, install it separately: `semodule -i /path/to/sudo_logger.pp`.

---

## Distributed installation (Kubernetes)

### Architecture in Kubernetes

```
                            ┌─────────────────────────────────────────┐
                            │          Kubernetes cluster              │
                            │                                          │
  Monitored hosts           │  ┌──────────────┐   PostgreSQL           │
  ┌───────────────┐         │  │ sudo-         │   ┌──────────────┐   │
  │ sudo-logger-  │─mTLS──►│  │ logserver     │──►│  postgres    │   │
  │ agent         │  :9876  │  │ pod           │   └──────────────┘   │
  └───────────────┘         │  │               │   MinIO / S3          │
                            │  │               │   ┌──────────────┐   │
                            │  └───────┬───────┘──►│    minio     │   │
                            │          │ :9877      └──────────────┘   │
                            │  ┌───────▼───────┐                       │
  Browsers                  │  │ sudo-replay-  │   ┌──────────────┐   │
  ──────────HTTP/S─────────►│  │ server pod    │◄──│ oauth2-      │   │
                     :8080  │  │               │   │ proxy        │   │
                            │  └───────────────┘   └──────────────┘   │
                            └─────────────────────────────────────────┘
```

### Why LoadBalancer, not Ingress

The log server speaks raw TCP with mTLS. Standard Kubernetes Ingress controllers operate at the HTTP layer and terminate TLS — this would break mTLS because the Ingress controller strips the client certificate before the connection reaches the log server pod.

The solution is a `LoadBalancer` service that passes TCP traffic straight through to the pod. The TLS handshake (including client certificate verification via `RequireAndVerifyClientCert`) happens inside the `sudo-logserver` container.

From `k8s/service.yaml`:

```yaml
# Port 9876 — TCP passthrough (mTLS terminated inside pod)
apiVersion: v1
kind: Service
metadata:
  name: sudo-logserver
  namespace: sudo-logger
spec:
  type: LoadBalancer
  selector:
    app: sudo-logserver
  ports:
    - name: tls
      port: 9876
      targetPort: 9876
      protocol: TCP
---
# Port 9877 — internal ClusterIP only (approval API, plain HTTP)
apiVersion: v1
kind: Service
metadata:
  name: sudo-logserver-admin
  namespace: sudo-logger
spec:
  type: ClusterIP
  selector:
    app: sudo-logserver
  ports:
    - name: admin
      port: 9877
      targetPort: 9877
      protocol: TCP
```

> **Note:** On AWS, annotate the LoadBalancer service with `service.beta.kubernetes.io/aws-load-balancer-type: "nlb"` to use a Network Load Balancer (NLB), which provides true TCP passthrough and preserves source IPs.

### Firewall rules for Kubernetes

| Port | From | To | Required |
|---|---|---|---|
| 9876/TCP | Monitored hosts | LoadBalancer external IP | Yes |
| 9877/TCP | Within cluster only (ClusterIP) | log server pod | Internal only |
| 8080/TCP | Browsers or Ingress controller | replay server NodePort | Yes |

### Kubernetes manifests

The `k8s/` directory contains:

| File | Purpose |
|---|---|
| `namespace.yaml` | `sudo-logger` namespace |
| `pvc.yaml` | PersistentVolumeClaims for local session storage |
| `postgresql.yaml` | PostgreSQL StatefulSet |
| `minio.yaml` | MinIO StatefulSet (S3-compatible object store) |
| `service.yaml` | LoadBalancer for port 9876 + ClusterIP for port 9877 |
| `deployment.yaml` | Combined log server + replay server (local storage) |
| `deployment-distributed.yaml` | Log server with PostgreSQL + S3/MinIO |
| `replay-server.yaml` | Replay server deployment (distributed storage) |
| `oauth2-proxy.yaml` | Optional OIDC authentication proxy |
| `kustomization.yaml` | Kustomize overlay for local mode |
| `kustomization-distributed.yaml` | Kustomize overlay for distributed mode |

### Quick deployment

```bash
# 1. Create namespace and TLS secrets first
kubectl apply -f k8s/namespace.yaml

kubectl create secret generic sudo-logger-tls \
    --namespace sudo-logger \
    --from-file=ca.crt \
    --from-file=server.crt \
    --from-file=server.key \
    --from-file=ack-sign.key

# 2. Deploy storage, services, and workloads
kubectl apply -f k8s/secret.yaml          # approval tokens, S3 credentials
kubectl apply -f k8s/pvc.yaml
kubectl apply -f k8s/postgresql.yaml
kubectl apply -f k8s/minio.yaml
kubectl apply -f k8s/service.yaml
kubectl apply -f k8s/deployment-distributed.yaml
kubectl apply -f k8s/replay-server.yaml
kubectl apply -f k8s/oauth2-proxy.yaml    # optional: OIDC proxy
```

Or with kustomize:

```bash
# Local (single-node) mode
kubectl apply -k k8s/

# Distributed mode (PostgreSQL + MinIO)
kubectl apply -f k8s/kustomization-distributed.yaml
```

### Configuring agents to connect to the Kubernetes log server

Once the `LoadBalancer` service has an external IP:

```bash
kubectl get svc sudo-logserver -n sudo-logger
# NAME            TYPE           CLUSTER-IP    EXTERNAL-IP    PORT(S)          AGE
# sudo-logserver  LoadBalancer   10.96.0.5     203.0.113.10   9876:31234/TCP   2m
```

Update `/etc/sudo-logger/agent.conf` on every monitored host:

```ini
Server = 203.0.113.10:9876
```

Restart the agent:

```bash
systemctl restart sudo-logger-agent
```

### Scaling considerations

| Component | Stateless | Scaling approach |
|---|---|---|
| `sudo-logserver` | Yes (distributed storage) | Horizontal — multiple replicas behind LoadBalancer |
| `sudo-replay-server` | Yes (distributed storage) | Horizontal — multiple replicas behind Ingress |
| PostgreSQL | No | Single instance, or HA via operator (e.g. CloudNativePG) |
| MinIO | No | Standalone for dev; distributed mode for production |

> **Note:** Local storage mode (`--storage=local`) writes session files to the pod's filesystem. It does not support multiple log server replicas — sessions land on whichever pod handles the TCP connection. Use distributed storage mode for any production multi-replica deployment.
