# sudo-logger

Real-time sudo session logging with mandatory remote acknowledgement.
All sudo commands and interactive sessions are recorded and shipped to a
central log server over mutual TLS. If the log server stops responding,
the user's terminal is frozen — preventing any unlogged sudo activity.

## Table of Contents

- [How it works](#how-it-works)
- [Architecture](#architecture)
- [Security properties](#security-properties)
- [Features](#features)
- [Limitations](#limitations)
- [Requirements](#requirements)
- [Installation](#installation)
  - [PKI bootstrap](#1-pki-bootstrap)
  - [Server installation](#2-server-installation)
  - [Client installation](#3-client-installation)
- [Configuration](#configuration)
- [Viewing and replaying sessions](#viewing-and-replaying-sessions)
- [Developer guide](#developer-guide)
  - [Repository layout](#repository-layout)
  - [Building from source](#building-from-source)
  - [Wire protocol](#wire-protocol)
  - [ACK mechanism](#ack-mechanism)
  - [Freeze mechanism](#freeze-mechanism)
  - [Building RPMs](#building-rpms)
- [Troubleshooting](#troubleshooting)

---

## How it works

```
User runs sudo
      │
      ▼
┌─────────────────────┐
│  sudo C plugin      │  Loaded by sudo for every invocation.
│  (plugin.so)        │  Records stdin/stdout/tty I/O.
│                     │  Blocks sudo entirely if shipper is unavailable.
│                     │  Freezes terminal input if ACKs go stale.
└────────┬────────────┘
         │ Unix socket (/run/sudo-logger/plugin.sock)
         ▼
┌─────────────────────┐
│  sudo-shipper       │  Local daemon running as root.
│  (Go)               │  Bridges plugin ↔ server.
│                     │  Tracks ACK state per session.
│                     │  Responds instantly to ACK queries.
└────────┬────────────┘
         │ Mutual TLS (TCP 9876)
         ▼
┌─────────────────────┐
│  sudo-logserver     │  Central server (separate machine).
│  (Go)               │  Receives session data.
│                     │  Writes sudo iolog directories.
│                     │  Sends HMAC-signed ACKs per chunk.
└─────────────────────┘
         │
         ▼
  /var/log/sudoreplay/<user>/<host>_<timestamp>/
  Replayed with: sudoreplay -d /var/log/sudoreplay <TSID>
```

When a user runs `sudo`, the plugin connects to the local shipper daemon.
The shipper opens a TLS connection to the remote log server. If the server
is unreachable at this point, sudo is blocked entirely — the command never
runs. If the connection succeeds, sudo proceeds and all I/O is streamed to
the server in real time. The server acknowledges every chunk. If ACKs stop
arriving (network loss, server crash), the terminal is frozen within ~5
seconds — no further input reaches the child process until ACKs resume or
the session is killed with Ctrl+C.

---

## Architecture

### C plugin (`plugin/plugin.c`)

A sudo I/O plugin loaded via `/etc/sudo.conf`. Implements the `sudo_plugin.h`
API. Hooks into every sudo session to:

- Connect to the local shipper over a Unix socket at session open
- Forward all terminal input (`log_ttyin`), output (`log_ttyout`), stdin,
  stdout, and stderr as framed chunks
- Periodically query the shipper for the latest server ACK timestamp
- Freeze terminal input (return 0 from `log_ttyin`) if ACKs go stale
- Block sudo entirely if the shipper/server is unreachable at startup

### Go shipper (`go/cmd/shipper/`)

A systemd service running as root on each client machine. Acts as a proxy
between the plugin (Unix socket) and the server (TLS). One goroutine per
sudo session:

- Opens a TLS connection to the server for each new session
- Forwards SESSION_START, CHUNK, SESSION_END messages
- Receives and HMAC-verifies ACKs from the server
- Tracks ACK state per session; responds instantly to plugin ACK queries
- Detects server unreachability via ACK lag tracking (no ACK for 4s while
  chunks are being sent) without relying on TCP keepalive heuristics

### Go log server (`go/cmd/server/`)

A TLS server running on a dedicated machine. For each client connection:

- Receives session metadata and writes a sudo iolog log file
- Streams terminal I/O into `ttyout`/`ttyin` files with timing data
- Acknowledges every chunk with an HMAC-signed ACK
- Sessions stored as sudoreplay-compatible directories under
  `/var/log/sudoreplay/<user>/<host>_<timestamp>/`

---

## Security properties

| Property | Detail |
|----------|--------|
| **Sudo blocked at start** | If the log server is unreachable when sudo runs, the session is rejected before the command executes |
| **Terminal freeze on network loss** | If ACKs stop arriving while a session is active, terminal input is frozen within ~5 seconds |
| **Ctrl+C escapes frozen terminal** | Ctrl+C (0x03) and Ctrl+\ (0x1c) pass through even when frozen, allowing the user to kill the session |
| **Mutual TLS** | Both client and server authenticate with certificates signed by a shared CA; unknown clients are rejected |
| **HMAC-signed ACKs** | Server signs each ACK with HMAC-SHA256; forged ACKs from a network attacker are detected and discarded |
| **Tamper-evident log storage** | Logs are written on a separate server that the sudo-running user has no access to |
| **All I/O captured** | stdin, stdout, stderr, tty input and tty output are all recorded |

---

## Features

- Full session replay with `sudoreplay` (native sudo iolog format)
- Real-time streaming — no local buffering on the client
- Interactive sessions (bash, vim, etc.) fully recorded including timing
- Scalable: designed for ~50+ simultaneous sessions
- RPM packages for Fedora/RHEL with proper systemd integration
- Automatic sudo.conf configuration on client RPM install/uninstall
- Minimal footprint: one small .so on the client + one Go daemon

---

## Limitations

- **No automatic reconnect**: if the server connection drops during a
  session, the terminal freezes and stays frozen. The user must Ctrl+C
  and start a new sudo session. A new session will attempt a fresh
  connection to the server.

- **No session buffer/replay on reconnect**: chunks sent during a network
  outage (before the freeze kicks in) may be lost. The ~5 second window
  before freeze means at most a few keystrokes may not be logged.

- **One client certificate for all clients** (default setup): the included
  `setup.sh` generates one client certificate shared across all machines.
  For stronger isolation, generate per-machine client certificates.

- **Root on the client machine is not constrained**: the shipper runs as
  root and can be killed, or the plugin .so can be removed from
  `/etc/sudo.conf`. This system is designed to deter and audit, not to
  prevent a fully compromised root from disabling logging.

- **No log rotation**: `/var/log/sudoreplay/` grows without bound. Implement
  external rotation (logrotate, cron) as needed.

- **TTY dimensions not recorded**: terminal size (rows/cols) is not sent to
  the server. Replay will use default dimensions.

- **Requires sudo 1.9+**: uses the sudo 1.9 I/O plugin API.

---

## Requirements

### Server
- Linux (Fedora 43 / RHEL 9+ recommended)
- Reachable on TCP port 9876 from all clients
- `sudo-logger-server` RPM or equivalent

### Client
- Linux with sudo 1.9+
- `sudo-logger-client` RPM or equivalent
- Network access to the log server

### Build dependencies
- `gcc`
- `sudo-devel` (for `sudo_plugin.h`)
- `golang` 1.18+
- `rpm-build` (for RPM packaging)

---

## Installation

### 1. PKI bootstrap

Run once on a secure machine (CA machine). You need `openssl`.

```bash
bash setup.sh /tmp/pki logserver.example.com
```

Replace `logserver.example.com` with the actual hostname or IP of your
log server. This must match the DNS name clients use to connect.

This generates:
```
/tmp/pki/
  ca/ca.crt             # CA certificate (distributed to all machines)
  ca/ca.key             # CA private key (keep secure, not distributed)
  server/server.crt     # Server TLS certificate
  server/server.key     # Server TLS private key
  client/client.crt     # Client TLS certificate
  client/client.key     # Client TLS private key
  hmac.key              # 32-byte HMAC key (distributed to all machines)
```

**File distribution:**

| File | Server | Client |
|------|--------|--------|
| `ca/ca.crt` | Yes | Yes |
| `server/server.crt` | Yes | No |
| `server/server.key` | Yes | No |
| `client/client.crt` | No | Yes |
| `client/client.key` | No | Yes |
| `hmac.key` | Yes | Yes |

---

### 2. Server installation

```bash
# Install RPM
dnf install sudo-logger-server-1.0-1.fc43.x86_64.rpm

# Install certificates
cp /tmp/pki/ca/ca.crt           /etc/sudo-logger/
cp /tmp/pki/server/server.crt   /etc/sudo-logger/
cp /tmp/pki/server/server.key   /etc/sudo-logger/
cp /tmp/pki/hmac.key            /etc/sudo-logger/

# Secure private key and HMAC key
chown sudologger:sudologger /etc/sudo-logger/server.key /etc/sudo-logger/hmac.key
chmod 600 /etc/sudo-logger/server.key /etc/sudo-logger/hmac.key

# Configure listen address and log directory if defaults need changing
# Defaults: LISTEN_ADDR=:9876  LOG_DIR=/var/log/sudoreplay
vim /etc/sudo-logger/server.conf

# Start service
systemctl enable --now sudo-logserver

# Verify
systemctl status sudo-logserver
journalctl -u sudo-logserver -f
```

The server creates `/var/log/sudoreplay/` (owned by `sudologger`) on
first start if it does not exist.

---

### 3. Client installation

```bash
# Install RPM (automatically adds Plugin line to /etc/sudo.conf)
dnf install sudo-logger-client-1.0-1.fc43.x86_64.rpm

# Install certificates
cp /tmp/pki/ca/ca.crt           /etc/sudo-logger/
cp /tmp/pki/client/client.crt   /etc/sudo-logger/
cp /tmp/pki/client/client.key   /etc/sudo-logger/
cp /tmp/pki/hmac.key            /etc/sudo-logger/

# Secure private key and HMAC key
chmod 600 /etc/sudo-logger/client.key /etc/sudo-logger/hmac.key

# Set the log server address
vim /etc/sudo-logger/shipper.conf
# Change: LOGSERVER=logserver.example.com:9876

# Start service
systemctl enable --now sudo-shipper

# Verify
systemctl status sudo-shipper
journalctl -u sudo-shipper -f

# Test
sudo ls
```

The RPM install adds the following line to `/etc/sudo.conf`:
```
Plugin sudo_logger_plugin sudo_logger_plugin.so
```
On uninstall (`dnf remove`), this line is automatically removed.

---

## Configuration

### Client: `/etc/sudo-logger/shipper.conf`

```bash
# Address of the remote log server
LOGSERVER=logserver.example.com:9876
```

All other shipper parameters (certificate paths, socket path) are set in
the systemd unit file `/usr/lib/systemd/system/sudo-shipper.service`.
To override, create a drop-in:

```bash
systemctl edit sudo-shipper
```

### Server: `/etc/sudo-logger/server.conf`

```bash
# Listen address (all interfaces, port 9876)
LISTEN_ADDR=:9876

# Base directory for session logs
LOG_DIR=/var/log/sudoreplay
```

### Tunable constants in `plugin/plugin.c`

| Constant | Default | Description |
|----------|---------|-------------|
| `SHIPPER_SOCK_PATH` | `/run/sudo-logger/plugin.sock` | Unix socket path |
| `ACK_TIMEOUT_SECS` | `5` | Seconds without ACK before freeze |
| `ACK_REFRESH_SECS` | `1` | How often to query the shipper for ACK status |
| `ACK_QUERY_TIMEOUT_MS` | `100` | Max wait for ACK_RESPONSE from shipper |

### Tunable constants in `go/cmd/shipper/main.go`

| Constant | Default | Description |
|----------|---------|-------------|
| `ackLagLimit` | `4s` | Unacknowledged chunk age before reporting dead to plugin |

---

## Viewing and replaying sessions

Sessions are stored on the server in sudo's native iolog format under
`/var/log/sudoreplay/<user>/<host>_<timestamp>/`.

```bash
# List all recorded sessions
sudoreplay -d /var/log/sudoreplay -l

# Example output:
# Mar  7 11:22:44 2026 : alun : TTY=unknown ; CWD=/ ; USER=root ;
#   TSID=alun/fedora_20260307-112244 ; COMMAND=bash

# Replay a session (use the TSID from -l)
sudoreplay -d /var/log/sudoreplay alun/fedora_20260307-112244

# Replay at 2x speed
sudoreplay -d /var/log/sudoreplay -s 2 alun/fedora_20260307-112244

# Replay a specific time range
sudoreplay -d /var/log/sudoreplay -f 10 -t 30 alun/fedora_20260307-112244

# Search sessions by user
sudoreplay -d /var/log/sudoreplay -l -u alun

# Search sessions by command
sudoreplay -d /var/log/sudoreplay -l -c bash
```

Each session directory contains:
```
log     — session metadata (user, host, runas, tty, command, timestamp)
timing  — event timing file (event type, delta seconds, byte count)
ttyout  — terminal output data
ttyin   — terminal input data
```

---

## Developer guide

### Repository layout

```
sudo-logger/
├── plugin/
│   └── plugin.c            # sudo I/O plugin (C)
├── go/
│   ├── go.mod
│   ├── cmd/
│   │   ├── shipper/
│   │   │   └── main.go     # Local shipper daemon
│   │   └── server/
│   │       └── main.go     # Remote log server
│   └── internal/
│       ├── protocol/
│       │   └── protocol.go # Shared wire protocol
│       └── iolog/
│           └── iolog.go    # sudo iolog directory writer
├── setup.sh                # PKI bootstrap script
├── sudo-shipper.service    # systemd unit for shipper
├── sudo-logserver.service  # systemd unit for server
├── shipper.conf            # Default client config
└── server.conf             # Default server config
```

### Building from source

```bash
# Build the plugin
cd plugin
gcc -Wall -Wextra -O2 -fPIC -shared \
    -I/usr/include/sudo \
    -D_GNU_SOURCE \
    -o sudo_logger_plugin.so plugin.c

# Build the shipper
cd go
go build -o sudo-shipper ./cmd/shipper

# Build the server
go build -o sudo-logserver ./cmd/server
```

### Wire protocol

All messages share a 5-byte frame header:
```
[1 byte: type][4 bytes: payload length, big-endian][N bytes: payload]
```

Implemented in `go/internal/protocol/protocol.go` (Go) and inline in
`plugin/plugin.c` (C).

| Type | Hex | Direction | Description |
|------|-----|-----------|-------------|
| `SESSION_START` | `0x01` | plugin → shipper → server | JSON: session_id, user, host, command, ts |
| `CHUNK` | `0x02` | plugin → shipper → server | Binary: seq(8) + ts_ns(8) + stream(1) + len(4) + data |
| `SESSION_END` | `0x03` | plugin → shipper → server | Binary: final_seq(8) + exit_code(4) |
| `ACK` | `0x04` | server → shipper | Binary: seq(8) + ts_ns(8) + hmac(32) |
| `ACK_QUERY` | `0x05` | plugin → shipper | Empty — plugin requests latest ACK state |
| `ACK_RESPONSE` | `0x06` | shipper → plugin | Binary: last_ack_ts_ns(8) + last_seq(8) |
| `SESSION_READY` | `0x07` | shipper → plugin | Empty — server connection established, sudo may proceed |
| `SESSION_ERROR` | `0x08` | shipper → plugin | String error message — server unreachable, sudo blocked |

**CHUNK stream types:**

| Value | Constant | Description |
|-------|----------|-------------|
| `0x00` | `STREAM_STDIN` | Standard input (non-tty) |
| `0x01` | `STREAM_STDOUT` | Standard output (non-tty) |
| `0x02` | `STREAM_STDERR` | Standard error |
| `0x03` | `STREAM_TTYIN` | Terminal input (what user typed) |
| `0x04` | `STREAM_TTYOUT` | Terminal output (what user saw) |

**ACK HMAC:**

The server signs each ACK with HMAC-SHA256 over the 16-byte sequence:
```
seq_be(8 bytes) || ts_ns_be(8 bytes)
```
using the shared HMAC key. The shipper verifies this before accepting the
ACK. This prevents a network attacker from injecting fake ACKs to allow
unlogged sudo access.

### ACK mechanism

The freeze system is based on a two-level ACK cache:

```
Server ──ACK──► Shipper (goroutine, updates sessionAckTs)
                    │
Plugin ──ACK_QUERY──► Shipper (main loop, responds with readAck())
                    │
Plugin ◄──ACK_RESPONSE── (ts=time.Now() if alive, ts=0 if dead)
```

The shipper's `readAck()` logic:

1. If `serverConnAlive == false`: return `(0, lastSeq)` — TCP connection dead
2. If `lastChunkSentNs > sessionAckTs` (unACKed chunks exist) AND
   `time.Now() - sessionAckTs > 4s`: return `(0, lastSeq)` — ACK lag detected
3. Otherwise: return `(time.Now(), lastSeq)` — server is alive and responding

This means:
- **Idle sessions** never freeze (no unACKed chunks → lag check skipped)
- **Active sessions** freeze ~4s after the last real ACK from the server
- **TCP death** (keepalives) triggers immediate freeze via path 1

### Freeze mechanism

In `plugin.c`, `log_ttyin()` is called for every keystroke:

```c
static int log_ttyin(const char *buf, unsigned int len, ...) {
    ship_chunk(STREAM_TTYIN, buf, len);   // always ship

    if (!ack_is_fresh()) {
        // show freeze banner on first freeze
        // pass Ctrl+C (0x03) and Ctrl+\ (0x1c) through
        // swallow all other input
        return 0;  // 0 = don't forward to child process
    }
    return 1;  // 1 = forward to child process
}
```

`ack_is_fresh()` queries the shipper at most once per second
(`ACK_REFRESH_SECS`). The plugin waits at most 100ms for the response
(`ACK_QUERY_TIMEOUT_MS`). If the shipper responds with `ts=0`, the plugin
immediately sets `g_last_ack_time = 0` which causes `ack_is_fresh()` to
return false on the next call.

### Building RPMs

```bash
# Set up rpmbuild tree
mkdir -p ~/rpmbuild/{SOURCES,SPECS,RPMS,BUILD}

# Copy spec files
cp rpmbuild/SPECS/sudo-logger-client.spec ~/rpmbuild/SPECS/
cp rpmbuild/SPECS/sudo-logger-server.spec ~/rpmbuild/SPECS/

# Create source tarball
cd /path/to/sudo-logger
tar czf ~/rpmbuild/SOURCES/sudo-logger-1.0.tar.gz \
    --transform 's,^,sudo-logger-1.0/,' \
    go plugin server.conf setup.sh shipper.conf \
    sudo-logserver.service sudo-shipper.service

# Build client RPM
rpmbuild -bb ~/rpmbuild/SPECS/sudo-logger-client.spec

# Build server RPM
rpmbuild -bb ~/rpmbuild/SPECS/sudo-logger-server.spec

# Output
ls ~/rpmbuild/RPMS/x86_64/
# sudo-logger-client-1.0-1.fc43.x86_64.rpm
# sudo-logger-server-1.0-1.fc43.x86_64.rpm
```

**Version bump:** update `Version:` in both spec files and the tarball name.

---

## Kubernetes deployment

### Why not standard Ingress?

sudo-logserver speaks raw TCP with mutual TLS. Standard Kubernetes Ingress
is HTTP/HTTPS only and terminates TLS — this breaks mTLS. Use a
`LoadBalancer` Service instead (TCP passthrough).

### Quick start

```bash
# 1. Create namespace
kubectl apply -f k8s/namespace.yaml

# 2. Load PKI files as a Secret (run setup.sh first if you haven't)
bash k8s/create-secret.sh /path/to/pki

# 3. Deploy everything else
kubectl apply -f k8s/pvc.yaml
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml

# Or apply all at once with kustomize
kubectl apply -k k8s/

# 4. Get the external IP assigned by your cloud LB
kubectl get svc -n sudo-logger sudo-logserver
# NAME             TYPE           EXTERNAL-IP      PORT(S)
# sudo-logserver   LoadBalancer   203.0.113.42     9876:31234/TCP

# 5. Update shipper.conf on all clients
# LOGSERVER=203.0.113.42:9876
```

### Build and push the container image

```bash
docker build -t ghcr.io/alun-hub/sudo-logserver:1.0 .
docker push ghcr.io/alun-hub/sudo-logserver:1.0
```

Or with podman:
```bash
podman build -t ghcr.io/alun-hub/sudo-logserver:1.0 .
podman push ghcr.io/alun-hub/sudo-logserver:1.0
```

### Accessing logs from the pod

```bash
# Open a shell via a debug sidecar or ephemeral container
kubectl debug -it -n sudo-logger deploy/sudo-logserver \
    --image=debian:slim --target=sudo-logserver

# Or copy logs out
kubectl cp sudo-logger/<pod-name>:/var/log/sudoreplay ./sudoreplay-backup

# Run sudoreplay against the PVC locally by port-forwarding is not possible
# since sudoreplay reads files directly. Mount the PVC in a separate pod:
kubectl run replay --rm -it --image=fedora:latest \
    --overrides='{
      "spec": {
        "volumes": [{"name":"logs","persistentVolumeClaim":{"claimName":"sudoreplay-logs"}}],
        "containers": [{"name":"replay","image":"fedora:latest",
          "command":["bash"],
          "volumeMounts":[{"name":"logs","mountPath":"/var/log/sudoreplay"}]}]
      }
    }' \
    -n sudo-logger -- bash
# Inside: dnf install -y sudo && sudoreplay -d /var/log/sudoreplay -l
```

### Multiple replicas (HA)

Running more than one replica requires:

1. **ReadWriteMany PVC** — NFS, CephFS, or a cloud file share (EFS, Filestore)
   so all pods can write logs to the same directory simultaneously.

2. **Connection-level sticky sessions** — each sudo session is one TCP
   connection; it must stay on the same pod for the duration. Configure
   `sessionAffinity: ClientIP` on the Service, or use an NLB/cloud LB
   that supports connection tracking.

3. Change `strategy.type` from `Recreate` to `RollingUpdate` in
   `deployment.yaml` once the above are in place.

For most environments (≤50 simultaneous users) a single replica with a
cloud-managed PVC is simpler and sufficient.

### Security notes

- The container runs as UID 65532 (distroless `nonroot`) with a read-only
  root filesystem and all Linux capabilities dropped.
- TLS private key and HMAC key are mounted read-only from a Kubernetes
  Secret (`defaultMode: 0400`).
- Consider using `loadBalancerSourceRanges` in `service.yaml` to restrict
  which IP ranges (your client machines) can reach port 9876.
- Rotate the HMAC key and client certificates periodically; update the
  Secret and restart the pod.

---

## Troubleshooting

### `sudo: error in /etc/sudo.conf: unable to load plugin`

Verify the plugin file exists and the symbol name matches:
```bash
ls -la /usr/libexec/sudo/sudo_logger_plugin.so
grep Plugin /etc/sudo.conf
# Should show: Plugin sudo_logger_plugin sudo_logger_plugin.so
```

### `sudo-logger: cannot connect to shipper daemon`

The shipper is not running or the socket doesn't exist:
```bash
systemctl status sudo-shipper
journalctl -u sudo-shipper -n 50
ls /run/sudo-logger/plugin.sock
```

### `sudo-logger: cannot reach log server: tls: ...`

Certificate issue. Common causes:

- **`tls: either ServerName or InsecureSkipVerify must be specified`**:
  ServerName mismatch in TLS config. Check shipper code version.
- **`x509: certificate is not valid for any names`**:
  Server certificate has no SAN for the hostname clients are connecting to.
  Regenerate with `setup.sh` using the correct hostname:
  ```bash
  bash setup.sh /tmp/pki your-actual-hostname
  ```
- **`x509: certificate signed by unknown authority`**:
  The CA cert on the client doesn't match the one used to sign the server cert.

### Terminal freezes immediately on session start

The plugin seeded `g_last_ack_time = 0` but the shipper is not responding to
ACK_QUERY before `ACK_TIMEOUT_SECS` elapses. Check that:
- `sudo-shipper` is running and connected to the server
- The HMAC key is identical on client and server

### `sudoreplay: time stamp field is missing`

Old log format from a previous server version. Sessions recorded with older
server builds are not compatible. New sessions will work correctly.
Delete the old session directories or re-install the server RPM.

### Freeze takes too long after network loss

Ensure you are running the latest client RPM. Earlier versions relied on
TCP keepalive heuristics (slow). The current version uses application-level
ACK lag detection and should freeze within ~5 seconds of network loss while
the user is actively typing.
