# sudo-logger Installation Guide

This guide covers installing and configuring `sudo-logger` in two scenarios:
**Local Storage** (single server, file-based) and **Distributed Storage**
(Kubernetes, PostgreSQL, S3/MinIO).

---

## Quick Install (Debian, Ubuntu, Fedora, RHEL, Rocky Linux)

You can install `sudo-logger` packages directly using our one-liner install script. The script automatically detects your distribution (Debian/Ubuntu `.deb` or RedHat/Fedora/Rocky `.rpm`) and architecture (`amd64` or `arm64`), downloads the latest release, verifies its signature, and installs it.

### Install Client (Monitored Hosts)
```bash
curl -sSL https://raw.githubusercontent.com/alun-hub/sudo-logger/main/scripts/install.sh | bash -s -- client
```

### Install Log Server
```bash
curl -sSL https://raw.githubusercontent.com/alun-hub/sudo-logger/main/scripts/install.sh | bash -s -- server
```

### Install Replay Server
```bash
curl -sSL https://raw.githubusercontent.com/alun-hub/sudo-logger/main/scripts/install.sh | bash -s -- replay
```

### Signature Verification
All releases are signed using **Sigstore/cosign** (keyless OIDC). To verify the downloaded package manually:
1. Download the package, signature, and certificate files from the [Releases](https://github.com/alun-hub/sudo-logger/releases) page.
2. Run:
```bash
cosign verify-blob \
  --signature sudo-logger-client_<version>_linux_amd64.deb.sig \
  --certificate sudo-logger-client_<version>_linux_amd64.deb.pem \
  --certificate-identity-regexp "https://github.com/alun-hub/sudo-logger/.*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  sudo-logger-client_<version>_linux_amd64.deb
```

---

## Architecture Overview

| Component | Package | Role |
|---|---|---|
| `sudo_logger_plugin.so` | `sudo-logger-client` | Loaded by `sudo`; streams session data to the agent |
| `sudo-logger-agent` | `sudo-logger-client` | Local daemon; records via eBPF, forwards to the log server |
| `sudo-logserver` | `sudo-logger-server` | Receives session streams; stores to disk or S3/DB |
| `sudo-replay-server` | `sudo-logger-replay` | Web UI for replay, risk scoring, JIT approvals, sudoers management |

---

## Prerequisites

- **OS:** Linux — Fedora/RHEL/Rocky Linux 9+ recommended; Ubuntu 22.04 LTS+, Debian 12+ supported. All binaries
  (client plugin included) only need symbols up to **glibc 2.34**, satisfied by every OS above.
  > Releases **v1.34.0 and earlier** are the exception: their `sudo_logger_plugin.so` was built directly on an
  > `ubuntu-24.04` CI runner (glibc 2.39) with no older/compatible build environment, so it actually requires
  > **glibc 2.38+** — which RHEL/Rocky 9, Ubuntu 22.04, and Debian 12 don't have (`sudo` fails with
  > `GLIBC_2.38 not found`). Fixed for the next release by building the plugin inside a Rocky Linux 9 container in CI
  > (see `.github/workflows/release.yml`). If you're stuck on an affected release, check `ldd --version` — you need
  > Fedora 39+/RHEL-Rocky 10+/Ubuntu 23.10+/Debian 13+ until you can upgrade past v1.34.0.
- **Kernel:** 5.8 or later (required for eBPF).
- **sudo:** 1.9.0 or later.
- **TLS certificates:** Agent → log server communication uses mutual TLS. You need a CA, a server certificate/key, and a client certificate/key per monitored host (or a shared client cert for smaller deployments). See [Preparing TLS Certificates and Signing Keys](#preparing-tls-certificates-and-signing-keys) below — bring your own, or generate a set for testing.

---

## Preparing TLS Certificates and Signing Keys

Every deployment mode below needs the same things: a CA, a server certificate/key
for the log server, and (except where the package auto-generates it) an Ed25519
signing key for chunk ACKs. Client certificates are minted from the same CA as
needed, at any time.

### Option A — Bring your own CA

If your organization already runs a CA (or you want one dedicated to
sudo-logger), you just need it to produce these, in standard PEM format:

| File | Requirement |
|---|---|
| `ca.crt` | CA certificate |
| `server.crt` / `server.key` | Server certificate/key, signed by that CA. **Must include the log server's actual hostname or IP as a Subject Alternative Name (SAN)** — a bare Common Name is not enough for modern TLS clients to verify it. |
| `client.crt` / `client.key` | Client certificate/key per monitored host, signed by the same CA |
| `ack-sign.key` | Ed25519 private key, PEM PKCS8 format (`-----BEGIN PRIVATE KEY-----`) — unrelated to the CA above, see "About ack-sign.key" below | <!-- pragma: allowlist secret -->

Everything in the rest of this guide works unchanged regardless of where these
came from — skip to the section for your deployment mode.

### Option B — Generate a self-signed CA (testing or small deployments)

`setup.sh` in the repository root automates everything below in one command
(CA, server cert with SAN, and one client cert, all flat in an output
directory):

```bash
bash setup.sh /tmp/pki logserver.example.com
```

Or do it by hand:

```bash
mkdir -p pki && cd pki

# Root CA
openssl req -x509 -newkey ed25519 -nodes -days 3650 \
  -keyout ca.key -out ca.crt -subj "/CN=sudo-logger CA"

# Server certificate — replace the SAN below with your log server's real,
# externally-reachable hostname or IP (or the Kubernetes Service DNS name —
# see the SAN note in your deployment mode's section).
cat > san.cnf <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
[req_distinguished_name]
[v3_req]
subjectAltName = @alt_names
[alt_names]
DNS.1 = logserver.example.com
EOF
openssl req -newkey ed25519 -nodes -keyout server.key -out server.csr \
  -subj "/CN=logserver.example.com" -config san.cnf -reqexts v3_req
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days 3650 -out server.crt -copy_extensions copy
```

Keep `ca.key` somewhere safe afterward — you'll need it any time you mint a
new client certificate.

#### Minting a client certificate

One per monitored host (or reuse a single one for smaller deployments):

```bash
openssl req -newkey ed25519 -nodes -keyout client.key -out client.csr \
  -subj "/CN=<monitored-host-name>"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days 825 -out client.crt
```

**Shared cert vs. per-host cert:** a single shared client certificate is
simpler to manage but means the log server cannot tell which real monitored
host a session actually came from — the `--strict-cert-host` flag (server
side, default off, see
[Network & Security](docs/chapters/08-network-security.md#--strict-cert-host))
is what would normally catch a host claiming another host's identity, and it
is off by default specifically so shared-cert deployments keep working. If
you need that protection, mint one certificate per host (CN = the real
hostname, as above) and enable `--strict-cert-host`.

### About `ack-sign.key`

Unrelated to the CA above — a separate Ed25519 key the log server uses to sign
chunk-ACKs, which agents verify using its public half (`ack-verify.key`).

- **RPM/DEB local storage (section 1):** the `sudo-logger-server` package
  generates this pair automatically on first install — nothing to do here.
- **Every other deployment mode:** generate it yourself and derive the public
  half:
  ```bash
  openssl genpkey -algorithm ed25519 -out ack-sign.key
  openssl pkey -in ack-sign.key -pubout -out ack-verify.key
  ```

---

## 1. Local Storage (single server)

Suitable for small environments or testing. All session data is stored on the log server's local filesystem.

### A. Install server and replay packages

```bash
sudo rpm -ivh sudo-logger-server-*.rpm sudo-logger-replay-*.rpm
```

The `sudo-logger-server` RPM automatically generates an Ed25519 ACK signing key pair on first install:

```
/etc/sudo-logger/ack-sign.key    # private — kept on the server
/etc/sudo-logger/ack-verify.key  # public  — must be copied to every client
```

### B. Configure the log server

Edit `/etc/sudo-logger/server.conf` (shell environment file format):

```sh
LISTEN_ADDR=:9876
LOG_DIR=/var/log/sudoreplay
```

The systemd unit reads this file and passes the values as flags to `sudo-logserver`.
Place your TLS files in `/etc/sudo-logger/` — see
[Preparing TLS Certificates and Signing Keys](#preparing-tls-certificates-and-signing-keys)
above if you don't already have these (the server certificate's SAN must be
this server's real, externally-reachable hostname or IP — whatever you put in
`server = ...` on each client's `agent.conf` in step F):

```
ca.crt       # Certificate Authority used to verify client certs
server.crt   # Server TLS certificate
server.key   # Server TLS private key
ack-sign.key # Ed25519 signing key (auto-generated by RPM — no action needed)
```

### C. Distribute the ACK verify key to clients

The agent uses this public key to verify that chunk-acknowledgements come from
the legitimate log server. Copy it to each monitored host before starting the agent:

```bash
scp /etc/sudo-logger/ack-verify.key user@client-host:/etc/sudo-logger/ack-verify.key
```

### D. Start server services

```bash
sudo systemctl enable --now sudo-logserver sudo-replay
```

The replay UI is now available at `http://<server>:8080`.

### E. Install the client package on each monitored host

```bash
sudo rpm -ivh sudo-logger-client-*.rpm
```

The RPM automatically adds the plugin line to `/etc/sudo.conf`:

```
Plugin sudo_logger_plugin sudo_logger_plugin.so
```

The plugin binary is installed at `/usr/libexec/sudo/sudo_logger_plugin.so`.

### F. Configure the agent

`client.crt`/`client.key` (one pair per monitored host, or a shared pair for
smaller deployments) aren't generated by any package — mint them from your CA,
see [Minting a client certificate](#minting-a-client-certificate),
then copy them here along with `ca.crt` and the `ack-verify.key` from step C.

Edit `/etc/sudo-logger/agent.conf`:

```ini
# Address of the log server — must match a SAN on the server's certificate.
server = logserver.example.com:9876

# TLS mutual authentication.
cert      = /etc/sudo-logger/client.crt
key       = /etc/sudo-logger/client.key
ca        = /etc/sudo-logger/ca.crt
verify_key = /etc/sudo-logger/ack-verify.key
```

All settings have built-in defaults; only the values you need to override must be
present. See the comments in the installed `/etc/sudo-logger/agent.conf` for the
full list of options (disclaimer, masking patterns, idle timeout, D-Bus monitoring, etc.).

Start the agent:

```bash
sudo systemctl enable --now sudo-logger-agent
```

> **Note:** The agent service has `RefuseManualStop=yes` to prevent users from stopping
> it to evade logging — `systemctl stop`/`restart sudo-logger-agent` (with or without
> `--force`; verified `--force` does **not** bypass this) will be refused. As root, use
> `systemctl kill sudo-logger-agent` instead: `Restart=always` respawns it immediately,
> and any attempt to kill it from inside an active sudo session is itself captured as
> TTY I/O before the agent dies, making the tampering self-documenting.

---

## 2. Kubernetes — Local Storage

Suitable for trying `sudo-logger` on a small Kubernetes cluster (k3s, kind,
minikube) without standing up PostgreSQL/S3. Session recordings are stored on
a single PersistentVolumeClaim, shared by the log server and replay server
(they run as two separate Deployments/pods, each mounting the same PVC).

> **Single-node clusters only.** The PVC is `ReadWriteOnce`, so both pods can
> mount it only because they land on the same node. On a multi-node cluster
> the scheduler could place them on different nodes, and whichever pod
> starts second would fail to mount the volume. Use the
> [Distributed Storage](#3-distributed-storage-kubernetes) path or the
> [Helm chart](charts/sudo-logger/README.md) instead if your cluster has more
> than one node.

### A. Prepare TLS certificates

Same requirements as the systemd install above: a CA, a server certificate/key,
and an Ed25519 ACK-signing key, placed flat in a local directory (e.g. `./pki`).
See [Preparing TLS Certificates and Signing Keys](#preparing-tls-certificates-and-signing-keys)
if you don't already have these — when generating the server certificate's
SAN, use whatever hostname/IP your agents will actually connect to (see
section D below); a bare Common Name with no SAN will fail modern TLS clients'
hostname verification.

```
ca.crt
server.crt
server.key
ack-sign.key
```

### B. Create the namespace and secret

```bash
kubectl apply -f k8s/namespace.yaml
bash k8s/create-secret.sh ./pki
```

`create-secret.sh` creates the `sudo-logger-tls` Secret from the files above.
`k8s/secret.yaml` is a template for reference only — it holds placeholder
values and is not meant to be applied directly (it is deliberately excluded
from `k8s/kustomization.yaml` for that reason).

### C. Deploy

```bash
cd k8s
kubectl apply -k .
```

This creates the PVC, the `sudo-logserver` and `sudo-replay-server`
Deployments (local-storage mode, using `k8s/deployment.yaml` and
`k8s/replay-server-local.yaml`), and their Services.

### D. Access

| Service | Address |
|---|---|
| Replay UI | `http://<NODE_IP>:30080` |
| Log server (agent TLS) | `<NODE_IP>:9876`, or the external IP your cluster's LoadBalancer assigns (k3s's built-in ServiceLB and cloud LBs both work out of the box; on a cluster without one, edit `k8s/service.yaml` to use `NodePort` instead) |

Continue with client setup (section 1.E–F above) to point an agent at this log server.

---

## 3. Distributed Storage (Kubernetes)

For production environments. Session metadata is stored in PostgreSQL and session
recordings in S3 (MinIO or AWS S3). Settings changed in the UI persist to the
database and are visible to all replicas immediately.

### A. Prepare TLS certificates

The log server requires mutual TLS. Have the following files ready in a local
directory (e.g. `./pki`) before running the deploy script — see
[Preparing TLS Certificates and Signing Keys](#preparing-tls-certificates-and-signing-keys)
above if you don't already have these. The server certificate's SAN needs to
cover however clients will reach the log server externally (its NodePort/
LoadBalancer hostname or IP) — the same requirement as section 1.B.

| File | Purpose |
|---|---|
| `ca.crt` | Root CA certificate |
| `server.crt` / `server.key` | Log server TLS certificate and key |
| `ack-sign.key` | Ed25519 key for signing ACKs to agents (generate it yourself here — unlike the RPM path, nothing auto-generates it) |

### B. Deploy with the script

```bash
cd k8s
./deploy-local.sh                                        # uses the locally-built localhost/sudo-logger:latest image
./deploy-local.sh --image ghcr.io/alun-hub/sudo-logger:1.25.5   # or pin a published image
```

The script performs these steps automatically:

1. Creates the `sudo-logger` namespace.
2. Creates Kubernetes secrets (`sudo-logger-tls`, `sudo-logger-distributed`) from your certificates and environment variables.
3. Deploys **PostgreSQL** (metadata) and **MinIO** (session recordings).
4. Starts **sudo-logserver** in distributed mode.
5. Starts **sudo-replay-server** (UI).

### C. Manual deployment (without the script)

If you prefer to apply manifests yourself, create the required Secrets first
— `deployment-distributed.yaml` and `replay-server.yaml` both reference them,
so applying those manifests without the Secrets in place will leave the pods
stuck unable to start:

```bash
kubectl apply -f k8s/namespace.yaml

kubectl create secret generic sudo-logger-tls \
  --namespace sudo-logger \
  --from-file=ca.crt=./pki/ca.crt \
  --from-file=server.crt=./pki/server.crt \
  --from-file=server.key=./pki/server.key \
  --from-file=ack-sign.key=./pki/ack-sign.key

kubectl create secret generic sudo-logger-distributed \
  --namespace sudo-logger \
  --from-literal=s3-access-key=<your-access-key> \
  --from-literal=s3-secret-key=<your-secret-key> \
  --from-literal=db-user=sudologger \
  --from-literal=db-password=<your-db-password> \
  --from-literal=db-url='postgres://sudologger:<your-db-password>@postgresql:5432/sudologger?sslmode=disable'  # pragma: allowlist secret

# deployment-distributed.yaml also requires an approval-token Secret and an
# approval-policy ConfigMap (used by the JIT Approval admin API — see section
# 4) even if you don't plan to use JIT Approval. Without them the pod is
# stuck in ContainerCreating.
kubectl create secret generic sudo-logger-approval-token \
  --namespace sudo-logger \
  --from-literal=token="$(openssl rand -hex 32)"

kubectl apply -f k8s/configmap.yaml

kubectl apply -f k8s/postgresql.yaml
kubectl apply -f k8s/minio.yaml
kubectl apply -f k8s/service.yaml
kubectl apply -f k8s/deployment-distributed.yaml
kubectl apply -f k8s/replay-server.yaml
kubectl apply -f k8s/networkpolicy.yaml
```

`replay-server.yaml`'s `-logserver-admin-tls-name` defaults to the placeholder
`logserver.example.com` — this must match the actual SAN on your log
server's TLS certificate (the same hostname you used as `SERVER_HOSTNAME`
when generating it, above), not the `sudo-logserver-admin` Service name
used to reach it. Edit that value before applying if it doesn't match.

There is no working `kubectl apply -k` kustomize shortcut for this mode —
kustomize's default security restrictions block a kustomization from
referencing files outside its own directory, and `kubectl apply -k` doesn't
expose a way to lift that, so the individual `kubectl apply -f` commands
above (or `deploy-local.sh`) are the only two working paths.

### D. Access

After a successful deployment:

| Service | Address |
|---|---|
| Replay UI | `http://<NODE_IP>:30080` |
| Log server (agent TLS) | `<NODE_IP>:9876` |

---

## 4. Docker Compose

Suitable for a single-host deployment without Kubernetes. Uses the same
combined image as the Kubernetes/Helm paths (one image; the command and
entrypoint differ per service).

### A. Prepare TLS certificates and signing key

Flat `pki/` directory, same requirements as the systemd install — see
[Preparing TLS Certificates and Signing Keys](#preparing-tls-certificates-and-signing-keys).
The container runs as a non-root user (uid 65532); self-generated private
keys (mode 600 by default) need to be re-owned, not loosened to world-readable:

```bash
sudo chown 65532:65532 pki/*.key
```

### B. Start

```bash
docker compose up -d      # or: podman-compose up -d
```

By default this builds the image locally (`build: .`). To use the published
image instead, override `image:` for both services in `docker-compose.yaml`
to `ghcr.io/alun-hub/sudo-logger:<version>` and remove the `build: .` line.

### C. Verify

```bash
docker compose ps          # both services should show "healthy"
curl http://localhost:8080/healthz
```

### D. Persisting risk-scoring rule changes

The default `risk-rules.yaml` is bundled inside the image. Changes saved via
the Settings UI are written back to it inside the container and lost when the
container is recreated. To persist across restarts, mount a host directory:

```bash
mkdir -p config
podman run --rm --entrypoint cat ghcr.io/alun-hub/sudo-logger:<version> \
    /etc/sudo-logger/risk-rules.yaml > config/risk-rules.yaml
sudo chown 65532:65532 config/   # rootless podman: podman unshare chown -R 65532:65532 ./config/
```

Then uncomment the config volume in `docker-compose.yaml`:

```yaml
- ./config:/etc/sudo-logger:Z
```

and restart.

### E. Accessing session logs from the host

Session recordings live in the named volume `sudologs` (`sudo-logger_sudologs`
with the default project name), one asciinema v2 `session.cast` file per
session under `<user>/<host>_<timestamp>/`. This is **not** sudo's native I/O
log format — use `asciinema play`, or the web replay UI, not the `sudoreplay`
tool.

```bash
podman volume inspect sudo-logger_sudologs --format '{{.Mountpoint}}'
```

### Troubleshooting

If a container was previously started as root, or files ended up with the
wrong ownership, fix recursively and restart:

```bash
docker compose down
sudo chown -R 65532:65532 pki/ config/   # rootless podman: podman unshare chown -R ...
docker compose up -d
```

---

## 5. JIT Approval

The JIT approval system blocks `sudo` until an administrator grants access via the
Replay UI or a Mattermost/Slack interactive button. See the **Help** tab in the
Replay UI for full field descriptions.

### Via the UI (recommended for distributed deployments)

Settings are stored in the database and take effect within 30 seconds without a restart.

1. Log in to the **Replay UI**.
2. Go to **Settings → JIT Approval**.
3. Enable the feature and fill in your policy (default window, exempt rules).
4. If using Mattermost/Slack notifications, fill in **Webhook URL**, **Replay Web App URL**, and **Webhook secret**.
   - **Webhook secret is required** when Webhook URL is set. Without it, interactive Approve/Deny buttons are disabled and all callback requests are rejected.
5. Click **Save**.

### Via YAML file (local mode only)

Edit `/etc/sudo-logger/approval-policy.yaml` directly. The server reloads it every 30 seconds.

```yaml
enabled: true
default_window: 30m
pending_ttl: 1h
exempt:
  - user: root        # root never needs approval
  # - host: build-host  # hosts that are exempt
notifications:
  webhook_url: "http://mattermost.internal:8065/hooks/..."
  request_channel: "sudo-logger"
  replay_web_app_url: "http://10.42.0.1"           # must be reachable by Mattermost
  webhook_secret: "replace-with-a-strong-secret"   # required for interactive buttons  # pragma: allowlist secret
  mention_user: true
```

#### Network requirements for interactive buttons

- The Mattermost/Slack server must be able to reach `<replay_web_app_url>/api/approvals/callback`.
- For internal IPs, enable **Allow Untrusted Internal Connections** in the Mattermost System Console.
- If the Replay UI sits behind an authenticating reverse proxy (e.g. oauth2-proxy), exempt the path `/api/approvals/callback` — it is protected by HMAC-SHA256 and does not need proxy-level authentication.

---

## 6. Replay UI authentication & Bootstrap

The Replay UI requires authentication to restrict access to sensitive audit logs.

By default, when you access the Replay UI for the first time, you will be greeted by a **Bootstrap Setup** screen. This allows you to create the first local administrator account securely.

If you are deploying `sudo-logger` via an automated process (Infrastructure as Code) and want to seed the first admin user, you can configure it via the `REPLAY_ARGS` environment variable:

```bash
echo 'REPLAY_ARGS="-admin-users your_username"' \
    | sudo tee /etc/sudo-logger/replay.conf

sudo systemctl restart sudo-replay
```

Once the initial administrator is created, you can navigate to **Config -> Users & Auth** in the web interface to configure advanced authentication strategies such as **OIDC (Enterprise SSO)** or **External Proxy** (e.g., oauth2-proxy, Pomerium).

Additional flags (TLS, etc.) can be appended to `REPLAY_ARGS` in the same file.

> **Note:** `k8s/keycloak.yaml` and `k8s/oauth2-proxy.yaml` are working
> examples of wiring up Keycloak (OIDC) and oauth2-proxy (External Proxy) in
> Kubernetes, but they hardcode one specific environment's IP/hostnames —
> they are not generic manifests you can `kubectl apply` as-is. Treat them as
> a reference to adapt, not a supported install path; edit the host/IP values
> for your own environment before applying.

---

## 7. SELinux

On SELinux-enforcing systems the `sudo-logger-client` RPM installs and
activates the required policy module automatically during `%post`. No manual
steps are needed. (The server and replay RPMs do not ship or require any
SELinux policy module.)

If you build from source, load the policy manually:

```bash
cd selinux
make -f /usr/share/selinux/devel/Makefile
sudo semodule -i sudo_logger.pp
```

---

## 8. Risk rules and SIEM

Both config files are installed with defaults by the `sudo-logger-replay` RPM and
can be edited live in **Settings → Risk Rules** / **Settings → SIEM**:

| File | Purpose |
|---|---|
| `/etc/sudo-logger/risk-rules.yaml` | Scoring rules evaluated against every session |
| `/etc/sudo-logger/siem.yaml` | SIEM forwarding (CEF/JSON/OCSF over syslog or HTTPS) |

Changes saved in the UI take effect immediately — no restart required.

---

## 9. Verification

1. On a monitored host, run `sudo -i` (or any sudo command).
2. If JIT approval is enabled you will be prompted:
   `Sudo authorization required. Please provide justification:`
3. Approve the request in the Replay UI (**Approvals** tab) or via the Mattermost button.
4. Re-run the command — it executes immediately within the approved window.
5. Open the Replay UI and confirm the session appears and can be replayed.

---

## 10. Troubleshooting

| Symptom | Check |
|---|---|
| Agent cannot connect | `systemctl status sudo-logger-agent`; verify the log server address and port are reachable. |
| TLS errors | Verify that the server certificate has the correct SAN and that `ca.crt` matches on both sides. `ack-verify.key` must match the `ack-sign.key` on the server. |
| Sessions not appearing in UI | Check `journalctl -u sudo-logserver` for ingestion errors; ensure `LOG_DIR` is writable by the `sudologger` user. |
| Settings not persisting (Kubernetes) | In distributed mode, save settings via the UI — changes written to the read-only ConfigMap mount are ignored. |
| Plugin not loaded | Check `/etc/sudo.conf` contains `Plugin sudo_logger_plugin sudo_logger_plugin.so` and `/usr/libexec/sudo/sudo_logger_plugin.so` exists. |
| SELinux denials | `ausearch -m avc -ts recent | audit2why`; ensure the SELinux policy module was installed by the RPM. |
