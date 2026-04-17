<p align="center">
  <img src="docs/sudo-logger.png" alt="Sudo-Logger Banner" width="100%">
</p>

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
  - [Wayland screen capture](#wayland-screen-capture)
  - [Distributed storage (S3 + PostgreSQL)](#distributed-storage-s3--postgresql)
- [Web replay interface](#web-replay-interface)
  - [Authentication](#authentication)
- [Viewing and replaying sessions](#viewing-and-replaying-sessions)
- [Developer guide](#developer-guide)
  - [Repository layout](#repository-layout)
  - [Building from source](#building-from-source)
  - [Wire protocol](#wire-protocol)
  - [ACK mechanism](#ack-mechanism)
  - [Freeze mechanism](#freeze-mechanism)
  - [Building RPMs](#building-rpms)
- [Performance and capacity](#performance-and-capacity)
- [Troubleshooting](#troubleshooting)
- [License](#license)

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
│                     │  Freezes child process if ACKs go stale.
└────────┬────────────┘
         │ Unix socket (/run/sudo-logger/plugin.sock)
         ▼
┌─────────────────────┐
│  sudo-shipper       │  Local daemon running as root.
│  (Go)               │  Bridges plugin ↔ server.
│                     │  Tracks ACK state per session.
│                     │  Responds instantly to ACK queries.
│                     │  Sends heartbeats every 400 ms.
└────────┬────────────┘
         │ Mutual TLS (TCP 9876)
         ▼
┌─────────────────────┐
│  sudo-logserver     │  Central server (separate machine).
│  (Go)               │  Receives session data.
│                     │  Writes asciinema v2 recordings.
│                     │  Sends ed25519-signed ACKs per chunk.
│                     │  Replies to heartbeats immediately.
└─────────────────────┘
         │
         ▼
  /var/log/sudoreplay/<user>/<host>_<timestamp>/session.cast
```

When a user runs `sudo`, the plugin connects to the local shipper daemon.
The shipper opens a TLS connection to the remote log server. If the server
is unreachable at this point, sudo is blocked entirely — the command never
runs. If the connection succeeds, sudo proceeds and all I/O is streamed to
the server in real time. The server acknowledges every chunk and replies to
periodic heartbeat probes. If ACKs and heartbeats stop arriving (network
loss, server crash), the child process is frozen within ~1 second — no
further input reaches it until ACKs resume or the session is killed with
Ctrl+C.

---

## Architecture

> For full technical details — session lifecycle, wire protocol, cgroup isolation, and storage internals — see [ARCHITECTURE.md](ARCHITECTURE.md).

### C plugin (`plugin/plugin.c`)

A sudo I/O plugin loaded via `/etc/sudo.conf`. Implements the `sudo_plugin.h`
API. Hooks into every sudo session to:

- Connect to the local shipper over a Unix socket at session open
- Forward all terminal input (`log_ttyin`), output (`log_ttyout`), stdin,
  stdout, and stderr as framed chunks
- Run a background monitor thread that polls ACK state every 150 ms and
  writes freeze/unfreeze banners to `/dev/tty` when ACK state changes
- Block sudo entirely if the shipper/server is unreachable at startup
- Terminate the active sudo session if the shipper socket drops mid-session
  (EPIPE/ECONNRESET/EOF detected by monitor thread → SIGTERM to sudo within 150 ms)
- Actual process freezing is performed by the shipper via cgroup.freeze (see
  [Freeze mechanism](#freeze-mechanism))

### Go shipper (`go/cmd/shipper/`)

A systemd service running as root on each client machine. Acts as a proxy
between the plugin (Unix socket) and the server (TLS). One goroutine per
sudo session:

- Opens a TLS connection to the server for each new session
- Forwards SESSION_START, CHUNK, SESSION_END messages
- Receives and ed25519-verifies ACKs from the server
- Tracks ACK state per session; responds instantly to plugin ACK queries
- Sends a HEARTBEAT to the server every 400 ms; declares the connection
  dead if no HEARTBEAT_ACK arrives within 800 ms (~1 s freeze latency)
- Recovers automatically when the network returns; the TCP connection
  remains alive as long as the OS retransmission timeout has not expired
  (typically several minutes on Linux with default settings)
- Terminates frozen sessions that have been unreachable for longer than
  `freeze_timeout` (default 3 min) — sends `FREEZE_TIMEOUT` to the plugin,
  which unfreezes the cgroup and prints a human-readable banner before
  killing the session
- Creates a per-session cgroup subtree to freeze all child processes
- Tracks processes that escape to foreign cgroups (moved by GNOME/systemd)
  and freezes them via SIGSTOP when safe (see [Freeze mechanism](#freeze-mechanism))
- Spawns a `wayland-proxy` subprocess for GUI sessions (when `WAYLAND_DISPLAY`
  is set); the proxy intercepts `wl_surface_commit` to capture JPEG frames
  without any compositor patches (see [Wayland screen capture](#wayland-screen-capture))
- Enters linger mode after `sudo` exits if GUI processes remain in the session
  cgroup — holds the server connection open until all GUI processes exit, then
  sends SESSION_END
- Reads all settings from `/etc/sudo-logger/shipper.conf` (key = value format)

### Go log server (`go/cmd/server/`)

A TLS server running on a dedicated machine. For each client connection:

- Receives session metadata and opens session.cast for writing
- Streams terminal I/O as events into session.cast
- Acknowledges every chunk with an ed25519-signed ACK
- Replies to HEARTBEAT probes immediately with HEARTBEAT_ACK
- Sessions stored via the pluggable storage backend (see below)

### Storage abstraction (`go/internal/store/`)

The log server and replay server share a pluggable `SessionStore` interface with two backends selected at startup via `--storage`:

| Backend | Flag | Use case |
|---------|------|----------|
| `local` (default) | `--storage=local` | Single-node deployment; sessions stored on local disk under `--logdir` |
| `distributed` | `--storage=distributed` | Multi-node / Kubernetes; session cast files stored in S3 (or MinIO / NetApp StorageGRID), metadata in PostgreSQL |

**Local storage** (`--storage=local`, default):
- Zero new dependencies — identical to previous behavior
- Sessions stored as `<logdir>/<user>/<host_timestamp>/session.cast`
- Replay server detects completed sessions via inotify (fsnotify)

**Distributed storage** (`--storage=distributed`):
- Cast files uploaded to S3 after each session closes (async, 3 retries)
- Session metadata, risk cache, and block policy stored in PostgreSQL
- During upload, cast files are buffered locally in `--buffer-dir` (suitable for a K8s `emptyDir`)
- Replay server detects completed sessions by polling `sudo_sessions` every 5 s
- Both servers can run as multiple independent replicas — no shared filesystem required
- Supports AWS S3, MinIO, and NetApp StorageGRID via configurable endpoint and path-style URLs

**Migration tool** (`go/cmd/migrate-sessions`):
One-time idempotent migrator for existing deployments switching from local to distributed storage. Walks the existing log directory, inserts metadata into PostgreSQL (`ON CONFLICT DO NOTHING`), and uploads each `session.cast` to S3. Safe to re-run.

```bash
migrate-sessions \
  --logdir /var/log/sudoreplay \
  --db-url postgres://user:pass@host/dbname \  # pragma: allowlist secret
  --s3-bucket my-bucket \
  [--s3-endpoint https://minio.internal:9000] \
  [--s3-path-style] \
  [--dry-run]
```

---

## Security properties

| Property | Detail |
|----------|--------|
| **Sudo blocked at start** | If the log server is unreachable when sudo runs, the session is rejected before the command executes |
| **Child process frozen on network loss** | If ACKs stop arriving, the child process is frozen within ~1 second |
| **Freeze cannot be escaped with `fg`** | Terminal sessions are frozen via `cgroup.freeze=1` — no job-control signals involved, so `fg` cannot escape the freeze |
| **cgroup namespace isolation** | At session start the plugin calls `unshare(CLONE_NEWCGROUP)`: child processes see the session cgroup as their filesystem root for `/sys/fs/cgroup`. They cannot migrate to a parent cgroup to escape the freeze, even with `CAP_SYS_ADMIN`. The shipper remains in the host cgroup namespace and manages freeze/unfreeze normally. |
| **Ctrl+C always works** | Ctrl+C and Ctrl+\ are forwarded to the child even while frozen; the session can always be killed |
| **Mutual TLS** | Both client and server authenticate with certificates signed by a shared CA; unknown clients are rejected |
| **Asymmetric ACK signing (ed25519)** | Server signs each ACK with its ed25519 private key over `sessionID \|\| seq \|\| ts_ns`; a compromised client cannot forge ACKs for other sessions or other clients |
| **ACK bound to session** | Session ID is included in every ACK signature — a valid ACK for session A cannot be replayed to unfreeze session B |
| **Host field verified against TLS certificate** | Server rejects SESSION_START if the claimed `host` does not match the CN or DNS SANs of the presenting client certificate; a compromised shipper on host A cannot forge log entries attributed to host B |
| **Plugin socket peer verification** | Shipper verifies via `SO_PEERCRED` that only root processes (sudo) may connect to the Unix socket, as a second layer beyond file permissions |
| **Session ID collision resistance** | Session IDs include nanosecond precision and 4 cryptographically random bytes — simultaneous sessions on the same host are always distinct |
| **Tamper-evident log storage** | Logs are written on a separate server that the sudo-running user has no access to |
| **All I/O captured** | stdin, stdout, stderr, tty input and tty output are all recorded |
| **Input validated before filesystem use** | User, host, and session ID fields are validated with strict regexes; cgroup names are validated before directory creation |
| **Log directory confinement** | iolog writer and replay server both verify the resolved session path stays within the base log directory (symlinks resolved with `EvalSymlinks`) |
| **SELinux domain confinement** | `sudo-shipper` runs as `sudo_shipper_t` in enforcing mode; kernel-level restrictions on what the shipper process can access |
| **Active session terminated if shipper dies** | If the shipper socket drops mid-session (EPIPE/ECONNRESET/EOF), the plugin sends SIGTERM to sudo within 150 ms — terminating the active shell. The attacker cannot continue working unlogged; they must start a new sudo session, which is fail-closed until the shipper restarts (~2 s). |
| **Incomplete session detection** | If the shipper is killed mid-session, the server logs a `SECURITY:` warning, writes an `INCOMPLETE` marker, and the replay UI flags the session with a red ⚠ badge. Sessions terminated by the freeze-timeout watchdog are distinguished with an amber ⏱ badge and carry no risk score — a network outage is not a security incident. |

---

## Features

- Full session replay via web interface (asciinema v2 format; `sudoreplay` CLI not compatible)
- **Wayland screen capture**: GUI programs started with `sudo` on a Wayland desktop are screen-recorded via a transparent compositor proxy — no compositor patches required. The replay interface shows an image slideshow for GUI sessions.
- Active session terminated if shipper is killed mid-session — plugin detects socket drop (EPIPE/ECONNRESET) and sends SIGTERM within 150 ms
- Incomplete session detection — replay UI flags sessions where the shipper was killed mid-recording
- SELinux policy for `sudo-shipper` (enforcing mode, ships in the `selinux/` directory)
- Real-time streaming — no local buffering on the client
- Interactive sessions (bash, vim, etc.) fully recorded including timing
- Freeze within ~1 s of network loss; automatic recovery when network returns
- Frozen sessions automatically terminated after configurable timeout (default 3 min) with a human-readable error banner — prevents permanent hangs when the TCP connection dies
- Terminal sessions (bash, zsh, …) frozen via `cgroup.freeze` — no job control triggered
- GUI programs with own process group (gvim, okular, …) frozen via direct SIGSTOP/SIGCONT
- cgroup namespace isolation (`CLONE_NEWCGROUP`) prevents child processes from escaping the freeze cgroup, even with `CAP_SYS_ADMIN`
- Web replay interface with Basic Auth + TLS + trusted-user-header support (works standalone or behind Pomerium/oauth2-proxy/OpenShift ingress)
- Scalable: designed for 50+ simultaneous sessions
- RPM packages for Fedora/RHEL with proper systemd integration
- Automatic sudo.conf configuration on client RPM install/uninstall
- Minimal footprint: one small .so on the client + one Go daemon

---

## Limitations

- **Recovery window limited by TCP retransmission timeout**: the shipper
  keeps the TCP connection alive by writing heartbeats into the kernel send
  buffer even when the network is down. Recovery happens automatically when
  the network returns, as long as the OS retransmission timeout has not
  expired. On Linux with default settings this is typically several minutes.
  If the connection is truly gone (OS gave up), automatic recovery is no
  longer possible. The freeze-timeout watchdog (default 5 min) handles this
  case: it terminates the frozen session, unfreezes the cgroup, and prints
  a human-readable error banner so the user knows why the session ended.
  Without this, a dead TCP connection would cause a permanent freeze that
  could only be broken with `kill -9` from another terminal.

- **No session buffer on reconnect**: chunks sent during the window between
  network loss and freeze detection (~400–800 ms) may not be acknowledged.
  The session recording up to that point is intact on the server.

- **One client certificate for all clients** (default setup): the included
  `setup.sh` generates one client certificate shared across all machines.
  For stronger isolation, generate per-machine client certificates.

- **Root on the client machine is not fully constrained**: the shipper runs as
  root and can be killed by a user with a `sudo bash` shell (`unconfined_t`
  in Fedora's targeted SELinux policy). When the shipper dies, the plugin
  detects the socket drop (EPIPE/ECONNRESET) and terminates the active sudo
  session within 150 ms — the kill command itself is already in the log.
  `Restart=always` brings the shipper back within 2 seconds; until then,
  new sudo sessions are fail-closed. The server also writes an `INCOMPLETE`
  marker. This system is designed to deter and audit; a fully compromised
  root at the kernel level is out of scope for any software solution.

- **No log rotation**: `/var/log/sudoreplay/` grows without bound. A sample
  logrotate configuration is provided in `sudo-logserver.logrotate` — install
  it to `/etc/logrotate.d/sudo-logserver`. To enforce a maximum session age,
  add a cron job: `find /var/log/sudoreplay -mindepth 3 -maxdepth 3 -type d -mtime +365 -exec rm -rf {} +`

- **GUI programs that share bash's process group are not frozen**: helper
  processes launched by bash that share its process group are dropped from
  freeze tracking — sending SIGSTOP to their group would also stop bash and
  trigger job control. Only GUI apps that have their own process group
  (e.g. gvim after setsid) are frozen via direct SIGSTOP.

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
- Go 1.25+
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
```

The ACK signing key pair is generated automatically on the server when the
`sudo-logger-server` RPM is installed for the first time:

```
/etc/sudo-logger/ack-sign.key    # ed25519 private key (server only, root:sudologger 0640)
/etc/sudo-logger/ack-verify.key  # ed25519 public key  (copy to all clients)
```

**File distribution:**

| File | Server | Client |
|------|--------|--------|
| `ca/ca.crt` | Yes | Yes |
| `server/server.crt` | Yes | No |
| `server/server.key` | Yes | No |
| `client/client.crt` | No | Yes |
| `client/client.key` | No | Yes |
| `ack-sign.key` | Yes — auto-generated | No |
| `ack-verify.key` | Yes — auto-generated | Yes — copy from server |

---

### 2. Server installation

```bash
# Install RPM
dnf install sudo-logger-server-1.10.0-1.fc43.x86_64.rpm

# Install certificates
cp /tmp/pki/ca/ca.crt           /etc/sudo-logger/
cp /tmp/pki/server/server.crt   /etc/sudo-logger/
cp /tmp/pki/server/server.key   /etc/sudo-logger/

# Secure TLS private key
chown root:sudologger /etc/sudo-logger/server.key
chmod 640 /etc/sudo-logger/server.key

# ack-sign.key and ack-verify.key are generated automatically by the RPM %post
# scriptlet if they do not exist. After first start, distribute ack-verify.key
# to all clients:
#   scp /etc/sudo-logger/ack-verify.key client:/etc/sudo-logger/

# Configure listen address and log directory if needed
# Defaults: LISTEN_ADDR=:9876  LOG_DIR=/var/log/sudoreplay
vim /etc/sudo-logger/server.conf

# Start service
systemctl enable --now sudo-logserver

# Verify
systemctl status sudo-logserver
journalctl -u sudo-logserver -f
```

---

### 3. Client installation

```bash
# Install RPM (automatically adds Plugin line to /etc/sudo.conf)
dnf install sudo-logger-client-1.11.0-1.fc43.x86_64.rpm

# Install certificates and ACK verify key
cp /tmp/pki/ca/ca.crt                    /etc/sudo-logger/
cp /tmp/pki/client/client.crt            /etc/sudo-logger/
cp /tmp/pki/client/client.key            /etc/sudo-logger/
scp logserver:/etc/sudo-logger/ack-verify.key /etc/sudo-logger/

# Secure TLS private key
chmod 600 /etc/sudo-logger/client.key

# Set the log server address
vim /etc/sudo-logger/shipper.conf
# Change: server = logserver.example.com:9876

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

All shipper settings live in a single `key = value` config file. Lines
starting with `#` are comments. All keys are optional — the defaults below
match a standard RPM installation.

```ini
# Address of the remote log server (required — change this).
server = logserver.example.com:9876

# TLS mutual authentication — paths to PEM-encoded files.
# Defaults match the paths installed by the RPM.
#cert          = /etc/sudo-logger/client.crt
#key           = /etc/sudo-logger/client.key
#ca            = /etc/sudo-logger/ca.crt
#verify_key    = /etc/sudo-logger/ack-verify.key

# Unix socket the sudo plugin connects to.
#socket        = /run/sudo-logger/plugin.sock

# Wayland screen capture via wayland-proxy.
# Set to false to disable recording of GUI sessions entirely.
#wayland       = true

# Path to the wayland-proxy helper binary.
#proxy_bin     = /usr/libexec/sudo-logger/wayland-proxy

# How long to keep a session frozen when the log server is unreachable
# before abandoning it. Use Go duration syntax (e.g. 3m, 90s, 0 = never).
#freeze_timeout = 3m

# Verbose debug logging to syslog/journal.
#debug         = false
```

After editing, restart the shipper:

```bash
sudo systemctl kill -s SIGTERM sudo-shipper.service
```

#### Verbose debug logging

By default, `sudo-shipper` only logs errors and key events (session start,
freeze/unfreeze). To enable verbose logging, set `debug = true` in
`shipper.conf` and restart the shipper. Then watch the full output:

```bash
journalctl -u sudo-shipper -f
```

### Server: `/etc/sudo-logger/server.conf`

```bash
# Listen address (all interfaces, port 9876)
LISTEN_ADDR=:9876

# Base directory for session logs
LOG_DIR=/var/log/sudoreplay
```

Additional flags can be passed via a systemd drop-in:

```ini
# /etc/systemd/system/sudo-logserver.service.d/override.conf
[Service]
ExecStart=
ExecStart=/usr/bin/sudo-logserver \
    -listen   ${LISTEN_ADDR} \
    -logdir   ${LOG_DIR} \
    -cert     /etc/sudo-logger/server.crt \
    -key      /etc/sudo-logger/server.key \
    -ca       /etc/sudo-logger/ca.crt \
    -signkey  /etc/sudo-logger/ack-sign.key \
    -strict-cert-host
```

| Flag | Default | Description |
|------|---------|-------------|
| `-strict-cert-host` | off | Reject sessions where the `host` field in SESSION_START does not match the CN or DNS SANs of the client's TLS certificate. Recommended when each machine has its own certificate; leave off for shared-certificate setups. |
| `-health-listen addr` | *(disabled)* | Start a plain HTTP listener on `addr` (e.g. `:9877`) that serves `/healthz` (always 200) and `/metrics` (Prometheus text format). Disabled by default; enable in Kubernetes to replace the TCP socket liveness probe. |

### Distributed storage (S3 + PostgreSQL)

Pass `--storage=distributed` plus the flags below to both `sudo-logserver` and
`sudo-replay-server` when running in a multi-node or Kubernetes environment.

| Flag | Default | Description |
|------|---------|-------------|
| `--storage` | `local` | Storage backend: `local` or `distributed` |
| `--s3-bucket` | — | S3 bucket name (required for distributed) |
| `--s3-region` | `us-east-1` | AWS region (or any value for MinIO/StorageGRID) |
| `--s3-prefix` | `sessions/` | Key prefix for cast objects in the bucket |
| `--s3-endpoint` | — | Custom endpoint URL for MinIO / NetApp StorageGRID (e.g. `https://minio.internal:9000`) |
| `--s3-path-style` | `false` | Use path-style URLs — required for MinIO and NetApp StorageGRID |
| `--s3-access-key` | — | Static access key (leave empty to use `AWS_ACCESS_KEY_ID` or IAM) |
| `--s3-secret-key` | — | Static secret key (leave empty to use `AWS_SECRET_ACCESS_KEY` or IAM) |
| `--db-url` | — | PostgreSQL DSN (e.g. `postgres://user@host:5432/sudologger?sslmode=require`); pass password via `PGPASSWORD` env var or the DSN |
| `--buffer-dir` | `/var/lib/sudo-logger/buffer` | Local write-buffer directory for in-flight S3 uploads (use `emptyDir` in Kubernetes) |

**Example (MinIO):**
```bash
sudo-logserver \
  --storage=distributed \
  --s3-bucket=sudo-logs \
  --s3-endpoint=https://minio.internal:9000 \
  --s3-path-style \
  --s3-access-key=minioadmin \  # pragma: allowlist secret
  --s3-secret-key=minioadmin \  # pragma: allowlist secret
  --db-url=postgres://sudologger:secret@postgres:5432/sudologger?sslmode=require \  # pragma: allowlist secret
  --buffer-dir=/var/lib/sudo-logger/buffer \
  ...
```

**Credential priority (S3):**
1. `--s3-access-key` / `--s3-secret-key` flags (static credentials — MinIO, StorageGRID)
2. `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` environment variables
3. IAM instance profile / IRSA (when running on AWS / EKS)

**PostgreSQL schema** is applied automatically at startup with `CREATE TABLE IF NOT EXISTS` — no separate migration step required for new deployments.

**Importing risk rules into the database** — in distributed mode, risk rules are stored in PostgreSQL rather than on disk. To seed the database from an existing `risk-rules.yaml`:

```bash
sudo cat /etc/sudo-logger/risk-rules.yaml | python3 -c "
import yaml, json, sys
data = yaml.safe_load(sys.stdin)
print(json.dumps({'rules': data.get('rules', [])}))
" | curl -s -X PUT http://<replay-server>:8080/api/rules \
     -H "Content-Type: application/json" \
     --data-binary @-
```

After import, rules are served from the database and changes via the Settings UI are persisted there automatically.

### Tunable constants in `plugin/plugin.c`

| Constant | Default | Description |
|----------|---------|-------------|
| `SHIPPER_SOCK_PATH` | `/run/sudo-logger/plugin.sock` | Unix socket path |
| `ACK_TIMEOUT_SECS` | `2` | Seconds without ACK before plugin-side freeze |
| `ACK_REFRESH_SECS` | `0` | Re-query shipper on every monitor poll (every 150 ms) |
| `ACK_QUERY_TIMEOUT_MS` | `100` | Max wait for ACK_RESPONSE from shipper |

### Tunable constants in `go/cmd/shipper/main.go`

| Constant | Default | Description |
|----------|---------|-------------|
| `ackLagLimit` | `2s` | Unacknowledged chunk age before reporting dead to plugin |
| `hbInterval` | `400ms` | Heartbeat interval; freeze declared after 2 missed replies (800 ms) |

### Shipper config keys (relevant to freeze and Wayland behaviour)

All of these go in `/etc/sudo-logger/shipper.conf`:

| Key | Default | Description |
|-----|---------|-------------|
| `freeze_timeout` | `3m` | Terminate a frozen session after this duration of server unreachability. Prevents permanent hangs when the TCP connection dies. Set to `0` to disable (not recommended). |
| `wayland` | `true` | Enable Wayland screen capture for GUI sessions. Set to `false` to disable. |
| `proxy_bin` | `/usr/libexec/sudo-logger/wayland-proxy` | Path to the wayland-proxy helper binary. |

### Wayland screen capture

GUI programs started with `sudo` on a Wayland desktop produce no terminal I/O
and therefore no xterm.js replay. sudo-logger handles this by spawning a
transparent Wayland proxy between the sudo'd application and the compositor.
The proxy intercepts `wl_surface_commit` calls and JPEG-encodes each frame;
the replay interface shows these as an image slideshow.

**Requirements:**
- A running Wayland compositor (KDE, GNOME, …)
- `WAYLAND_DISPLAY` and `XDG_RUNTIME_DIR` preserved through sudo — add to
  `/etc/sudoers` (use `visudo`):

```
Defaults env_keep += "WAYLAND_DISPLAY XDG_RUNTIME_DIR"
```

This is included in the sudoers snippet installed by the client RPM
(`/etc/sudoers.d/sudo-logger-wayland`).

**Disable Wayland capture** (e.g. on headless or X11-only machines):

```ini
# /etc/sudo-logger/shipper.conf
wayland = false
```

When `wayland = false`, GUI sessions are still logged (start/end times,
command name, cgroup freeze) but no screen frames are captured.

#### Blocking X11 GUI applications (legacy / X11 deployments)

On systems without Wayland or when Wayland capture is disabled, graphical
applications produce empty session recordings. To prevent unrecorded GUI
sessions entirely, remove `DISPLAY` from all sudo sessions so GUI programs
fail immediately with *"cannot open display"*:

```
Defaults env_delete += DISPLAY
```

---

## Web replay interface

`sudo-replay-server` is a lightweight HTTP server that provides a browser-based
terminal player for recorded sessions.  It reads asciinema v2 session recordings written by
`sudo-logserver` and requires no database.

![sudo-replay web interface showing session list and terminal player](docs/replay-ui.svg)

```bash
# Install RPM on the log server
dnf install sudo-logger-replay-1.11.0-1.fc43.x86_64.rpm

# Start the service (runs as sudologger, reads /var/log/sudoreplay)
systemctl enable --now sudo-replay

# Open in browser
xdg-open http://localhost:8080
```

**Features:**
- Session list with live search by user, host, or command
- **Full command with all arguments** shown in the session list and info bar
  (e.g. `vim /etc/nginx/nginx.conf`, `pg_dump -U postgres mydb -f backup.sql`)
- Terminal player with play/pause, scrubbing, and speed control (0.25×–16×)
- Keyboard shortcuts: `Space` play/pause, `←`/`→` seek ±5 s, `R` restart
- **Summary tab** — aggregate statistics for a selectable date range: total
  sessions, unique users and hosts, incomplete sessions, sessions > 2 h, High
  Risk and Critical sessions. Per-user table with sortable columns (Sessions,
  Avg Duration, Long, High Risk, Critical, Top Commands, Hosts). Click any
  stat card to filter the table. User search box.
- **Anomalies tab** — flagged sessions by rule: incomplete sessions, High Risk
  sessions (score ≥ 50), direct root shell invocations, activity outside
  working hours (23:00–06:00), and sessions longer than 2 h. Sortable columns.
  Each anomaly links directly to the session in the player.
- **Risk scoring** — every session is scored 0–100 based on configurable rules
  in `/etc/sudo-logger/risk-rules.yaml`. Rules match against the sudo command
  line and terminal output events in `session.cast` for shell sessions. Scores are cached in
  `risk.json` per session and invalidated automatically when rules change.
  Levels: Low (0–24) · Medium (25–49) · High (50–74) · Critical (75+). Risk
  badges are shown on session cards and in the session info bar.
- **Settings tab** — browser UI for risk rules and SIEM forwarding. Rule
  changes and SIEM configuration are written back immediately (disk in local
  mode, PostgreSQL in distributed mode) and take effect without a server
  restart. PEM certificate upload is available in local storage mode; in
  distributed mode manage certificates via Kubernetes Secrets.
- **Blocked Users tab** — security teams can block individual users from running
  sudo, either globally or per host. A configurable message is shown to the
  blocked user at the sudo prompt. The log server enforces blocks centrally and
  reloads the policy every 30 seconds. See [Blocking users](#blocking-users).
- **SIEM forwarding** — completed sessions are forwarded to an external SIEM
  after the session closes. Risk score and reasons are included in every event.
  See [SIEM forwarding](#siem-forwarding) below.
- **Auto-refresh** — session list polls for new sessions every 15 seconds and
  immediately on tab focus; no manual browser refresh needed.
- **Prometheus metrics** — `/metrics` endpoint with session counts, risk level
  distribution, and view counter; see [Prometheus metrics](#prometheus-metrics).
- **No external dependencies** — xterm.js and CSS are vendored into the binary;
  works in air-gapped environments with no internet access

> **Security note:** sudo session recordings may contain sensitive data
> (passwords typed, private keys, etc.).  Always protect the replay interface
> with authentication; see [Authentication](#authentication) below.

### Authentication

`sudo-replay-server` supports three authentication modes that can be combined
freely.  Choose the mode that fits your deployment:

#### Mode 1: No built-in auth — deploy behind a reverse proxy

The simplest option when you already have infrastructure for authentication.
The replay server runs on localhost and the proxy handles auth and TLS.

Compatible proxies:
- **Pomerium** (identity-aware proxy, recommended)
- **oauth2-proxy** (lightweight OIDC proxy, works with any IdP: Keycloak, Azure AD, Dex, …)
- **OpenShift ingress** with built-in OAuth support

Configure the proxy to set a header with the authenticated username (e.g.
`X-Forwarded-User`) and pass `-trusted-user-header` to the replay server so
it is recorded in the access log:

```bash
# /etc/sudo-logger/replay.conf  (read by sudo-replay.service via EnvironmentFile)
# All flags must be on ONE line — no line continuations.
REPLAY_ARGS=-trusted-user-header X-Forwarded-User
```

Then reload:
```bash
systemctl daemon-reload && systemctl restart sudo-replay
```

#### Mode 2: Built-in HTTP Basic Auth with TLS

Standalone deployment with no external proxy required.  Credentials are stored
in a standard htpasswd file with bcrypt hashing.  Multiple users are supported
and credentials can be rotated without restarting the service.

**Step 1 — Create the htpasswd file:**

```bash
# Install htpasswd (part of httpd-tools):
dnf install httpd-tools

# Create the file with the first user (-c creates, -B forces bcrypt):
htpasswd -cB /etc/sudo-logger/replay.htpasswd alice

# Add more users:
htpasswd -B /etc/sudo-logger/replay.htpasswd bob

# Set ownership and permissions:
#   root owns and writes the file; sudologger (the service user) reads it;
#   no world access — the file contains bcrypt hashes that could be
#   brute-forced offline if exposed.
chown root:sudologger /etc/sudo-logger/replay.htpasswd
chmod 0640 /etc/sudo-logger/replay.htpasswd
```

The file format is one entry per line:
```
alice:$2b$12$...bcrypt-hash...
bob:$2b$12$...bcrypt-hash...
# Comments and blank lines are ignored
```

**Step 2 — Obtain a TLS certificate:**

Use your existing PKI, a self-signed cert, or Let's Encrypt:
```bash
# Self-signed (for internal use):
openssl req -x509 -newkey rsa:4096 -keyout replay.key -out replay.crt \
    -days 365 -nodes -subj '/CN=replay.example.com'
cp replay.crt replay.key /etc/sudo-logger/
chmod 640 /etc/sudo-logger/replay.key
```

**Step 3 — Configure the service:**

Create `/etc/sudo-logger/replay.conf` with all flags on a single line
(systemd `EnvironmentFile` does not support line continuations):

```bash
REPLAY_ARGS=-tls-cert /etc/sudo-logger/replay.crt -tls-key /etc/sudo-logger/replay.key -htpasswd /etc/sudo-logger/replay.htpasswd
```

Reload and restart:
```bash
systemctl daemon-reload
systemctl restart sudo-replay

# Verify TLS is active (look for "listening on ... (TLS)"):
journalctl -u sudo-replay -n 5

# Test with curl (skip cert verification for self-signed):
curl -ku alice:your-password https://localhost:8080/api/sessions
```

**Rotating passwords or adding users — no restart needed:**

```bash
# Change a password:
htpasswd -B /etc/sudo-logger/replay.htpasswd alice

# Remove a user (edit the file manually or use sed):
sed -i '/^alice:/d' /etc/sudo-logger/replay.htpasswd

# Reload credentials (no service restart):
systemctl kill --signal=HUP sudo-replay
```

#### Mode 3: Trusted header only (logging, no enforcement)

When a proxy handles authentication and you only want the replay server to
log who accessed it — without enforcing auth itself:

```bash
REPLAY_ARGS="-trusted-user-header X-Forwarded-User"
```

Every request is logged as:
```
access user=alice addr=10.0.0.1:52341 GET /api/sessions 200
```

> **Important:** This mode does not reject unauthenticated requests.
> The proxy must restrict access before requests reach the replay server.

#### Combining modes

All flags work together.  Example: TLS + Basic Auth + trusted header logging,
in `/etc/sudo-logger/replay.conf`:

```bash
REPLAY_ARGS=-tls-cert /etc/sudo-logger/replay.crt -tls-key /etc/sudo-logger/replay.key -htpasswd /etc/sudo-logger/replay.htpasswd -trusted-user-header X-Forwarded-User
```

#### Flag reference

| Flag | Default | Description |
|------|---------|-------------|
| `-tls-cert file` | — | PEM TLS certificate (enables HTTPS, requires `-tls-key`) |
| `-tls-key file` | — | PEM TLS private key |
| `-htpasswd file` | — | htpasswd file for Basic Auth (bcrypt only; reload with `SIGHUP`) |
| `-trusted-user-header hdr` | — | Log username from this request header (e.g. `X-Forwarded-User`) |
| `-listen addr` | `:8080` | Listen address |
| `-logdir dir` | `/var/log/sudoreplay` | Session log directory |
| `-rules file` | `/etc/sudo-logger/risk-rules.yaml` | Risk scoring rules |
| `-siem-config file` | `/etc/sudo-logger/siem.yaml` | SIEM forwarding config |

---

## SIEM forwarding

`sudo-replay-server` can forward a structured event to an external SIEM after
each session closes.  Events are sent by the replay server (not the log server)
so that the computed **risk score** and **risk reasons** can be included.

### How it works

**Local storage mode** — the replay server watches the log directory for `ACTIVE`
marker file removal using inotify.

**Distributed storage mode** — the replay server polls the `sudo_sessions`
PostgreSQL table every 5 seconds.  A PostgreSQL advisory lock
(`pg_try_advisory_lock`) ensures that only one replica forwards events when
multiple replay-server pods are running.

When a session ends (cleanly or abnormally), the server:

1. Reads session metadata from the store (file header / PostgreSQL row).
2. Computes the risk score using the configured rules.
3. Sends a structured event to the configured SIEM endpoint.

### Configuration

Configure SIEM forwarding via the **Settings tab** in the browser, or by
editing `/etc/sudo-logger/siem.yaml` directly.  In distributed mode the
configuration is stored in PostgreSQL (`sudo_config` table) and the Settings UI
writes directly to the database — no shared filesystem is required.

```yaml
enabled: true
transport: syslog        # https | syslog | stdout
format: json             # json | cef | ocsf
replay_url_base: https://replay.example.com:8080

syslog:
  addr: siem.example.com:514
  protocol: udp          # udp | tcp | tcp-tls
  # For tcp-tls only:
  # ca:   /etc/sudo-logger/siem-ca.crt
  # cert: /etc/sudo-logger/siem-client.crt
  # key:  /etc/sudo-logger/siem-client.key

https:
  url: https://siem.example.com/ingest
  token: ""              # Bearer or Splunk HEC token (optional)
  ca:   /etc/sudo-logger/siem-ca.crt
  cert: /etc/sudo-logger/siem-client.crt
  key:  /etc/sudo-logger/siem-client.key
```

The `https` transport requires mutual TLS (client certificate mandatory).

#### Stdout transport (Kubernetes / container environments)

Set `transport: stdout` to write each event as a single JSON/CEF/OCSF line to
the container's standard output instead of pushing to an external endpoint.
The container runtime (Docker, containerd) collects the output and your log
aggregation pipeline (Fluentd, Promtail, Vector, etc.) forwards it to your SIEM.

This is the recommended transport for Kubernetes deployments: no TLS
certificates to manage, no endpoint to configure, and the replay-server pod
needs no outbound network access to the SIEM.

```yaml
enabled: true
transport: stdout
format: json
replay_url_base: https://replay.example.com:8080
```

> **Note:** Certificate upload via the Settings UI (`POST /api/siem-cert`) is
> not available in distributed mode.  Manage TLS certificates for the `https`
> transport using Kubernetes Secrets and volume mounts.

### Event formats

#### JSON

Flat JSON object — suitable for most modern SIEMs:

```json
{
  "session_id": "fedora-alice-12345-1712345678-ab12cd34",
  "user": "alice",
  "host": "fedora",
  "runas": "root",
  "runas_uid": 0,
  "runas_gid": 0,
  "command": "vim /etc/nginx/nginx.conf",
  "resolved_command": "/usr/bin/vim",
  "cwd": "/home/alice",
  "flags": "",
  "start_time": "2026-04-06T10:30:00Z",
  "end_time": "2026-04-06T10:31:23Z",
  "duration_s": 83.2,
  "exit_code": 0,
  "incomplete": false,
  "risk_score": 25,
  "risk_reasons": ["edit_sensitive_config"],
  "replay_url": "https://replay.example.com:8080/?tsid=alice%2Ffedora_20260406-103000"
}
```

#### CEF

`CEF:0|sudo-logger|sudo-logger|1.0|sudo-session|Privileged Command Session|Severity|...`

Key extension fields: `rt` (start ms), `shost`, `suser`, `duser`, `duid`,
`dgid`, `dproc` (command), `cs1`=sessionId, `cs2`=cwd, `cs3`=resolvedCommand,
`cs4`=flags, `cs5`=status, `cs6`=replayUrl, `cn1`=exitCode, `cn2`=durationSec,
`cn3`=riskScore, `cs7`=riskReasons.

#### OCSF

OCSF v1.3.0 Class 3003 (Process Activity).  Risk score and reasons appear in
the `unmapped` object.

### Testing with netcat

```bash
# Listen on port 514 and print raw syslog events
nc -lk 514
```

Set `addr: localhost:514` and `protocol: tcp` in the Settings UI, run a sudo
command, and verify the event appears within a few seconds.

### Flag reference (replay server, SIEM-related)

| Flag | Default | Description |
|------|---------|-------------|
| `-siem-config file` | `/etc/sudo-logger/siem.yaml` | SIEM forwarding configuration |

---

## Blocking users

Security teams can block individual users from running sudo without modifying
sudoers files on every host. When a blocked user runs sudo, they see a
configurable message and the command is denied before it executes.

### How it works

1. The security team adds a user to the **Blocked Users** tab in the replay
   interface.
2. The config is written to `/etc/sudo-logger/blocked-users.yaml` (shared
   between replay server and log server).
3. The log server reloads the file every 30 seconds and enforces the policy
   centrally for all incoming sessions.
4. When the blocked user runs sudo, the log server denies the session during the
   startup handshake — before the command is executed.
5. The plugin displays the configured block message in a red banner at the
   terminal, then exits without running the command.

### Configuration

Blocks are managed via the **Blocked Users** tab in the browser UI:

- **Block message** — the text shown to blocked users. Customise this to
  include a contact address or ticket reference.
- **Block all hosts** — leave all host checkboxes unchecked to block the user
  everywhere.
- **Block specific hosts** — check individual hosts to block the user only on
  those machines. The host list is populated from session history.
- **Reason** — an internal note (not shown to users) for audit purposes.

The underlying config file is YAML:

```yaml
# /etc/sudo-logger/blocked-users.yaml
block_message: "Your sudo access has been suspended. Contact security@example.com."
users:
  - username: alice
    hosts: []                 # empty = all hosts
    reason: "Ticket SEC-123"
    blocked_at: 1712425200
  - username: bob
    hosts: ["web-01", "db-02"]  # specific hosts only
    reason: "Policy violation"
    blocked_at: 1712425300
```

### Flag reference (log server, blocking-related)

| Flag | Default | Description |
|------|---------|-------------|
| `-blocked-users file` | `/etc/sudo-logger/blocked-users.yaml` | Blocked users config (reloaded every 30 s) |

### Flag reference (replay server, blocking-related)

| Flag | Default | Description |
|------|---------|-------------|
| `-blocked-users file` | `/etc/sudo-logger/blocked-users.yaml` | Blocked users config (shared with log server) |

---

## Prometheus metrics

`sudo-replay-server` exposes a Prometheus-compatible metrics endpoint at `/metrics`.
No external library is required — the endpoint writes the standard
[Prometheus text exposition format](https://prometheus.io/docs/instrumenting/exposition_formats/)
directly.

### Available metrics

| Metric | Type | Description |
|--------|------|-------------|
| `sudoreplay_sessions_total` | Gauge | Total number of recorded sessions |
| `sudoreplay_sessions_active` | Gauge | Sessions currently being recorded |
| `sudoreplay_sessions_incomplete` | Gauge | Sessions that ended without clean termination |
| `sudoreplay_sessions_by_risk{level="low\|medium\|high\|critical"}` | Gauge | Sessions per risk level |
| `sudoreplay_session_views_total` | Counter | Session views via the replay UI since last restart |

### Scrape configuration

Add the replay server as a Prometheus scrape target:

```yaml
# prometheus.yml
scrape_configs:
  - job_name: sudo-replay
    static_configs:
      - targets: ["replay.example.com:8080"]
    # If Basic Auth is enabled on the replay server:
    basic_auth:
      username: prometheus
      password: <token>
    # If TLS is enabled:
    scheme: https
    tls_config:
      ca_file: /etc/prometheus/ca.crt
```

### Example Grafana queries

```promql
# Sessions recorded per risk level
sudoreplay_sessions_by_risk

# Incomplete session ratio (alert if > 5%)
sudoreplay_sessions_incomplete / sudoreplay_sessions_total > 0.05

# Session views over time (rate per minute)
rate(sudoreplay_session_views_total[5m]) * 60
```

### Example output

```
# HELP sudoreplay_sessions_total Total number of recorded sessions.
# TYPE sudoreplay_sessions_total gauge
sudoreplay_sessions_total 1234

# HELP sudoreplay_sessions_active Sessions currently being recorded.
# TYPE sudoreplay_sessions_active gauge
sudoreplay_sessions_active 3

# HELP sudoreplay_sessions_incomplete Sessions that ended without clean termination.
# TYPE sudoreplay_sessions_incomplete gauge
sudoreplay_sessions_incomplete 12

# HELP sudoreplay_sessions_by_risk Number of sessions per risk level.
# TYPE sudoreplay_sessions_by_risk gauge
sudoreplay_sessions_by_risk{level="low"} 800
sudoreplay_sessions_by_risk{level="medium"} 300
sudoreplay_sessions_by_risk{level="high"} 100
sudoreplay_sessions_by_risk{level="critical"} 34

# HELP sudoreplay_session_views_total Total session views via the replay UI since last restart.
# TYPE sudoreplay_session_views_total counter
sudoreplay_session_views_total 567
```

> **Note:** `/metrics` is protected by the same authentication layer as the rest of the
> replay server.  When using Basic Auth, create a dedicated read-only account for the
> Prometheus scraper rather than reusing an operator account.

---

## Viewing and replaying sessions

Sessions are stored on the server as asciinema v2 recordings under
`/var/log/sudoreplay/<user>/<host>_<timestamp>/`.

Use the web replay interface to browse and play back sessions:

```bash
# Open in browser (requires sudo-logger-replay package)
xdg-open http://localhost:8080
```

Each session directory contains:
```
session.cast  — asciinema v2 recording (header + event lines)
exit_code     — decimal exit status, written by log server on clean SESSION_END
ACTIVE        — present while session is being recorded
INCOMPLETE    — present if connection dropped mid-session
risk.json     — risk score cache (written by replay server)
```

The `session.cast` file is compatible with the asciinema ecosystem:
```bash
# Install asciinema CLI for terminal playback
asciinema play /var/log/sudoreplay/alice/gnarg_20260404-120000/session.cast
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
│   │   │   ├── main.go          # Local shipper daemon
│   │   │   └── cgroup.go        # Per-session cgroup management + freeze tracking
│   │   ├── server/
│   │   │   └── main.go          # Remote log server
│   │   ├── replay-server/
│   │   │   ├── main.go          # Web replay interface (HTTP + embedded SPA)
│   │   │   ├── risk-rules.yaml  # Default risk scoring rules
│   │   │   └── static/
│   │   │       └── index.html   # Single-page terminal player (xterm.js)
│   │   └── migrate-sessions/
│   │       └── main.go          # One-time migrator: local → distributed storage
│   └── internal/
│       ├── protocol/
│       │   └── protocol.go # Shared wire protocol
│       ├── iolog/
│       │   └── iolog.go    # asciinema v2 session writer
│       ├── store/
│       │   ├── store.go    # SessionStore / SessionWriter interfaces + New()
│       │   ├── local.go    # Local filesystem backend (default)
│       │   ├── local_test.go
│       │   └── distributed.go  # S3 + PostgreSQL backend
│       └── siem/
│           ├── config.go   # YAML config loader (30 s polling)
│           ├── event.go    # Event struct + JSON/CEF/OCSF formatters
│           └── sender.go   # HTTPS and syslog transports
├── rpm/
│   ├── sudo-logger-client.spec  # RPM spec for client package
│   ├── sudo-logger-server.spec  # RPM spec for server package
│   └── sudo-logger-replay.spec  # RPM spec for replay web interface
├── setup.sh                # PKI bootstrap script
├── sudo-shipper.service         # systemd unit for shipper
├── sudo-logserver.service       # systemd unit for server
├── sudo-logserver-restart.timer # daily 03:00 restart timer (leak mitigation)
├── sudo-logserver-restart.service # oneshot unit invoked by the timer
├── sudo-replay.service          # systemd unit for replay web interface
├── sudo-logserver.logrotate     # logrotate config for /var/log/sudoreplay
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

# Build the shipper, server, and replay interface
cd go
go build -o sudo-shipper       ./cmd/shipper
go build -o sudo-logserver     ./cmd/server
go build -o sudo-replay-server ./cmd/replay-server

# Build the migration tool (optional, for distributed storage deployments)
go build -o migrate-sessions   ./cmd/migrate-sessions
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
| `SESSION_START` | `0x01` | plugin → shipper → server | JSON: session_id, user, host, command, ts, pid, rows, cols |
| `CHUNK` | `0x02` | plugin → shipper → server | Binary: seq(8) + ts_ns(8) + stream(1) + len(4) + data |
| `SESSION_END` | `0x03` | plugin → shipper → server | Binary: final_seq(8) + exit_code(4) |
| `ACK` | `0x04` | server → shipper | Binary: seq(8) + ts_ns(8) + sig(64) |
| `ACK_QUERY` | `0x05` | plugin → shipper | Empty — plugin requests latest ACK state |
| `ACK_RESPONSE` | `0x06` | shipper → plugin | Binary: last_ack_ts_ns(8) + last_seq(8) |
| `SESSION_READY` | `0x07` | shipper → plugin | Empty — server connection established, sudo may proceed |
| `SESSION_ERROR` | `0x08` | shipper → plugin | String error message — server unreachable, sudo blocked |
| `HEARTBEAT` | `0x09` | shipper → server | Empty — keepalive probe sent every 400 ms |
| `HEARTBEAT_ACK` | `0x0a` | server → shipper | Empty — immediate reply to HEARTBEAT |
| `SERVER_READY` | `0x0b` | server → shipper | Empty — session accepted, shipper may send SESSION_READY |
| `SESSION_DENIED` | `0x0c` | server → shipper → plugin | String block message — policy denial, sudo blocked |
| `FREEZE_TIMEOUT` | `0x0d` | shipper → plugin | Empty — server unreachable beyond `-freeze-timeout`; session will be terminated |
| `SESSION_ABANDON` | `0x0e` | shipper → server (new conn) | UTF-8 session_id — freeze-timeout fired; server marks session as `freeze_timeout` |

**CHUNK stream types:**

| Value | Constant | Description |
|-------|----------|-------------|
| `0x00` | `STREAM_STDIN` | Standard input (non-tty) |
| `0x01` | `STREAM_STDOUT` | Standard output (non-tty) |
| `0x02` | `STREAM_STDERR` | Standard error |
| `0x03` | `STREAM_TTYIN` | Terminal input (what user typed) |
| `0x04` | `STREAM_TTYOUT` | Terminal output (what user saw) |

**ACK signing (ed25519):**

The server signs each ACK with its ed25519 private key over:
```
sessionID || 0x00 || seq_be(8 bytes) || ts_ns_be(8 bytes)
```
The null byte separates the variable-length session ID from the fixed fields.
The shipper verifies the signature using the server's public key before
accepting the ACK.

This design provides two layers of protection:

1. **Network attacker** cannot inject fake ACKs to unfreeze sessions — they
   lack the server's private key.
2. **Replay attack** is prevented — an ACK captured from session A cannot be
   replayed against session B because the session ID is part of the signed
   message. Both must match for the signature to verify.

Unlike the previous HMAC-SHA256 design (symmetric shared secret), the private
key never leaves the server. A compromised client holds only the public key
and cannot forge valid ACKs for any session on any client.

### ACK mechanism

```
Server ──ACK/HEARTBEAT_ACK──► Shipper (ACK reader goroutine)
                                    │ updateAck() / markAlive() / touchServerMsg()
                                    │
Shipper ──HEARTBEAT──────────► Server (heartbeat goroutine, every 400 ms)
                                    │ markDead() if no reply within 800 ms
                                    │
Plugin ──ACK_QUERY──────────► Shipper (main loop, readAck())
Plugin ◄──ACK_RESPONSE────── (ts=time.Now() if alive, ts=0 if dead)
```

The shipper's `readAck()` returns:

1. `(0, lastSeq)` if `serverConnAlive == false` — connection declared dead
2. `(0, lastSeq)` if unACKed chunks exist and debt age > `ackLagLimit` (2 s)
3. `(time.Now(), lastSeq)` otherwise — server is alive and responding

Recovery: when a `HEARTBEAT_ACK` or `ACK` arrives after a dead period,
`markAlive()` sets `serverConnAlive = true`, resets `ackDebtStartNs = 0`,
and calls `cg.unfreeze()`.

### Freeze mechanism

Two complementary freeze mechanisms work together:

**Plugin-side (C):** the background monitor thread polls `ack_is_fresh()` every
150 ms and writes banners to `/dev/tty` on state transitions:

```
monitor thread (every 150 ms)
    │
    ├── ack stale → write FREEZE banner to /dev/tty (once)
    │
    └── ack fresh again → write UNFREEZE banner to /dev/tty
```

The plugin does **not** send any signals. All process freezing is delegated
to the shipper (cgroup-based), keeping the plugin simple and avoiding any
interaction with the kernel's job-control machinery.

**Shipper-side (Go):** the shipper manages a per-session cgroup subtree and
freezes processes at the cgroup level:

```
cgroup.freeze=1  →  all processes in the session cgroup are suspended
```

For processes that escape the session cgroup (moved by GNOME/systemd to
`app-*.scope`), the shipper tracks them and applies per-process SIGSTOP if
safe. Safety is determined by process group membership:

- **Shell processes** (bash, zsh, …): reclaimed back into the session cgroup
  so `cgroup.freeze` covers them. SIGSTOP is never sent to shells — it would
  trigger job control and background the session.
- **Escaped GUI apps with own process group** (e.g. gvim after `setsid`):
  frozen via `syscall.Kill(pid, SIGSTOP)` targeting only that PID directly.
  On unfreeze, `syscall.Kill(pid, SIGCONT)` resumes them.
- **Escaped helpers sharing bash's process group**: dropped from tracking.
  Sending SIGSTOP to their process group would also stop bash and trigger
  job control, so they are left alone.

During a freeze, terminal sessions are suspended via `cgroup.freeze=1` and
the plugin writes the freeze banner to the terminal. When the network returns,
the cgroup is unfrozen and the banner clears automatically. If bash was moved
out of the session cgroup and ended up backgrounded (visible as
`[1]+ Stopped sudo bash` in the parent shell), run `fg` to restore it.

**Freeze-timeout (permanent hang prevention):** if the server connection
cannot be recovered — because the OS TCP retransmission timer expired and
the kernel closed the socket — the session would remain frozen permanently
until killed from another terminal. The shipper's freeze-timeout watchdog
prevents this:

```
Shipper detects server dead (markDead())
    │
    └─ frozenSince = time.Now()

Watchdog goroutine (checks every 10 s)
    │
    └─ time.Since(frozenSince) >= freeze-timeout (default 5 min)
           │
           ├── cg.unfreeze()                 ← release cgroup freeze first
           ├── send FREEZE_TIMEOUT (0x0d) to plugin socket
           └── close plugin connection → plugin detects EOF → kill(-pgrp, SIGTERM)
```

The plugin distinguishes `FREEZE_TIMEOUT` from an ordinary shipper death
and prints a different banner:

```
[ SUDO-LOGGER: gave up waiting for log server — session terminated ]
```

The `-freeze-timeout` flag (default `5m`) controls how long the shipper
waits before giving up. Set to `0` to disable (not recommended — sessions
may hang indefinitely if the log server is permanently unreachable).

The freeze-timeout is also the reason the plugin calls
`unfreeze_session_cgroup()` itself on receiving `FREEZE_TIMEOUT`: even if
the shipper is already dead, the plugin ensures the cgroup is unfrozen so
the SIGTERM actually reaches the shell.

**Distinguishing freeze-timeout from shipper-killed in the replay UI:**

When the freeze-timeout fires, the shipper is still alive and knows why
the session ended. After terminating the plugin it opens a **new** TLS
connection to the server and sends `SESSION_ABANDON (0x0e)` with the
session ID:

```
Freeze-timeout fires
    │
    ├── cg.unfreeze() + FREEZE_TIMEOUT → plugin → session killed
    │
    └── goroutine: dial server (new connection, 30 s timeout)
            │
            ├── Success → SESSION_ABANDON(session_id)
            │            Server: marks session freeze_timeout=true
            │            UI: amber ⏱ badge, no risk score added
            │
            └── Fail (server still unreachable)
                         Session stays as generic INCOMPLETE
                         UI: red ⚠ badge (cannot distinguish)
```

This covers the common case — a temporary outage where the server came
back before or shortly after the timeout fired. For permanent outages
where the server never becomes reachable, the session remains as generic
INCOMPLETE (the shipper cannot contact an unreachable server).

| Termination cause | Badge | Risk score | Server sees |
|-------------------|-------|-----------|-------------|
| Shipper killed/crashed | ⚠ incomplete (red) | +15 | EOF/RST on active conn |
| Freeze-timeout (network outage) | ⏱ freeze-timeout (amber) | +0 | SESSION_ABANDON on new conn |
| Freeze-timeout (server still down) | ⚠ incomplete (red) | +15 | EOF/RST, no ABANDON |

`log_ttyin()` always returns 1 and never blocks. Blocking there would
prevent sudo's event loop from processing signals, breaking Ctrl+C.

### Building RPMs

The RPM spec files are in `rpm/` in the repository. Always commit all changes
before creating the tarball — `git archive` only includes committed files.

```bash
# Set up rpmbuild tree (once)
rpmdev-setuptree

# Set the version (must match Version: in the spec files)
VERSION=1.9.2

# 1. Commit your changes first, then create the source tarball from HEAD
git archive --format=tar.gz --prefix=sudo-logger-${VERSION}/ HEAD \
    > ~/rpmbuild/SOURCES/sudo-logger-${VERSION}.tar.gz

# 2. Build packages directly from the repo directory
rpmbuild -ba rpm/sudo-logger-client.spec
rpmbuild -ba rpm/sudo-logger-server.spec
rpmbuild -ba rpm/sudo-logger-replay.spec

# RPMs end up in:
ls ~/rpmbuild/RPMS/x86_64/
```

**Version bump:** increment `Release:` in the spec file for spec-only fixes.
Increment `Version:` for code changes and add a `%changelog` entry — reset
`Release:` back to `1%{?dist}` each time `Version:` changes. The three
packages are versioned independently; only bump the affected package.

---

## Container deployment (Podman)

The repository includes a `Dockerfile` and `docker-compose.yaml` for running
the log server and web replay interface as containers. The plugin and shipper
still run natively on client machines — only the server side is containerised.

Containers run as the distroless nonroot user (UID 65532). Because rootless
Podman uses a user namespace, file ownership on bind mounts and named volumes
must be set up once with `podman unshare` before first start.

### Prerequisites

- `podman` and `podman-compose`
- A `pki/` directory with the server-side certificates (see
  [PKI bootstrap](#1-pki-bootstrap))

```
pki/
├── ca.crt
├── server.crt
├── server.key      ← must be readable only by the container user
├── ack-sign.key    ← must be readable only by the container user
└── server.conf     ← optional: override LISTEN_ADDR / LOG_DIR
```

### First-time setup

Run once after creating the `pki/` directory:

```bash
# 1. Fix ownership of pki/ so the nonroot container user (65532) can read it
podman unshare chown -R 65532:65532 ./pki/

# 2. Lock down private keys
podman unshare chmod 600 ./pki/server.key ./pki/ack-sign.key

# 3. Build the image
podman-compose build

# 4. Pre-create the log volume and fix its ownership before first start
#    The replay server writes risk.json cache files here — must be read-write.
podman volume create sudo-logger_sudologs
podman unshare chown -R 65532:65532 \
    $(podman volume inspect sudo-logger_sudologs --format '{{.Mountpoint}}')

# 5. Start
podman-compose up -d
```

### Persisting risk-scoring rule changes (Settings UI)

The default `risk-rules.yaml` is bundled inside the image.  Changes saved via
the Settings tab are written back to `/etc/sudo-logger/risk-rules.yaml` inside
the container and are lost when the container is recreated.

To persist rule changes across restarts, mount a host directory:

```bash
# 1. Create a config directory and copy the default rules into it
mkdir -p config
podman run --rm --entrypoint cat sudo-logger:latest \
    /etc/sudo-logger/risk-rules.yaml > config/risk-rules.yaml

# 2. Fix ownership for the nonroot container user
podman unshare chown -R 65532:65532 ./config/

# 3. Uncomment the config volume in docker-compose.yaml:
#      - ./config:/etc/sudo-logger:Z
#    Then restart:
podman-compose down && podman-compose up -d
```

### Start

```bash
podman-compose up -d
```

### Stop

```bash
podman-compose down        # stop and remove containers, keep logs
podman-compose down -v     # also delete the session log volume
```

### View logs

```bash
podman-compose logs -f             # both services
podman logs -f sudo-logserver      # logserver only
podman logs -f sudo-replay-server  # replay server only
```

### Rebuild after code changes

```bash
podman-compose down
podman-compose build --no-cache
podman-compose up -d
```

### Access session logs from the host

Session recordings are stored in the named volume `sudo-logger_sudologs`.
To find the path on disk (e.g. for `sudoreplay` or backup):

```bash
podman volume inspect sudo-logger_sudologs --format '{{.Mountpoint}}'
```

To replay a session directly from the host:

```bash
sudoreplay -d \
    $(podman volume inspect sudo-logger_sudologs --format '{{.Mountpoint}}') \
    alun/fedora_20260311-175401
```

### Fixing permission errors after a failed start

If containers were previously started as root (`user: "0:0"`) or files were
created with wrong ownership, fix recursively and restart:

```bash
podman-compose down
podman unshare chown -R 65532:65532 \
    $(podman volume inspect sudo-logger_sudologs --format '{{.Mountpoint}}')
podman unshare chown -R 65532:65532 ./pki/
podman-compose up -d
```

### Production readiness

| # | Item | Status |
|---|------|--------|
| ✅ | Distroless base image (minimal attack surface) | Good |
| ✅ | Runs as nonroot UID 65532 | Good |
| ✅ | Named volume (no bind mount permission issues) | Good |
| ✅ | Replay server mounts log volume read-only | Good |
| ✅ | Replay server supports Basic Auth + TLS + trusted-user-header | See [Authentication](#authentication) |
| ⚠️ | No `no-new-privileges` / `cap_drop: ALL` | Add to both services for defence in depth |
| ⚠️ | No resource limits | Add `deploy.resources.limits` for memory/CPU |
| ⚠️ | No healthcheck | `depends_on` does not wait for logserver to be ready |

---

## Kubernetes deployment

### Storage modes

Two deployment topologies are supported:

| Mode | Replicas | Shared storage | Use case |
|------|----------|---------------|----------|
| **Local** (default) | 1 log-server + 1 replay-server | ReadWriteOnce PVC | Small / single-team deployments |
| **Distributed** | N log-servers + M replay-servers | S3 + PostgreSQL | Multi-team, high-availability, multi-region |

### Why not standard Ingress?

sudo-logserver speaks raw TCP with mutual TLS. Standard Kubernetes Ingress
is HTTP/HTTPS only and terminates TLS — this breaks mTLS. Use a
`LoadBalancer` Service instead (TCP passthrough).

### Quick start — local storage (single node)

```bash
# 1. Create namespace
kubectl apply -f k8s/namespace.yaml

# 2. Load PKI files as a Secret (run setup.sh first)
bash k8s/create-secret.sh /path/to/pki

# 3. Deploy (uses ReadWriteOnce PVC, single replica)
kubectl apply -k k8s/

# 4. Get the external IP
kubectl get svc -n sudo-logger sudo-logserver

# 5. Update shipper.conf on all clients
# LOGSERVER=<EXTERNAL-IP>:9876
```

### Distributed storage (horizontal scaling)

With `--storage=distributed` both servers share no local state — cast files go
to S3 and all metadata goes to PostgreSQL. This enables:
- Multiple `sudo-logserver` replicas behind a TCP load balancer
- Multiple `sudo-replay-server` replicas behind an HTTP ingress
- Zero-downtime rolling updates

**Prerequisites:** an S3-compatible bucket and a PostgreSQL 14+ database. No
manual schema migration is needed — the schema is applied automatically at
startup.

**Step 1 — create the Secret with PKI + credentials:**

```bash
kubectl create secret generic sudo-logger-tls \
  --namespace sudo-logger \
  --from-file=ca.crt=/path/to/pki/ca/ca.crt \
  --from-file=server.crt=/path/to/pki/server/server.crt \
  --from-file=server.key=/path/to/pki/server/server.key \
  --from-file=ack-sign.key=/etc/sudo-logger/ack-sign.key

kubectl create secret generic sudo-logger-distributed \
  --namespace sudo-logger \
  --from-literal=db-url='postgres://sudologger:YOURPASSWORD@postgres:5432/sudologger?sslmode=require' \  # pragma: allowlist secret
  --from-literal=s3-access-key='YOUR_ACCESS_KEY' \  # pragma: allowlist secret
  --from-literal=s3-secret-key='YOUR_SECRET_KEY'  # pragma: allowlist secret
```

**Step 2 — patch the deployment** (`k8s/distributed/deployment-patch.yaml`):

```yaml
# k8s/distributed/deployment-patch.yaml
- op: replace
  path: /spec/template/spec/containers/0/args
  value:
    - -listen=:9876
    - -cert=/etc/sudo-logger/server.crt
    - -key=/etc/sudo-logger/server.key
    - -ca=/etc/sudo-logger/ca.crt
    - -signkey=/etc/sudo-logger/ack-sign.key
    - -storage=distributed
    - -s3-bucket=sudo-logs
    - -s3-endpoint=https://minio.internal:9000
    - -s3-path-style
    - -buffer-dir=/var/lib/sudo-logger/buffer
- op: replace
  path: /spec/replicas
  value: 3
```

Add env vars sourced from the Secret:
```yaml
env:
  - name: S3_ACCESS_KEY
    valueFrom:
      secretKeyRef: { name: sudo-logger-distributed, key: s3-access-key }
  - name: S3_SECRET_KEY
    valueFrom:
      secretKeyRef: { name: sudo-logger-distributed, key: s3-secret-key }
  - name: DB_URL
    valueFrom:
      secretKeyRef: { name: sudo-logger-distributed, key: db-url }
```

Or pass `--s3-access-key` / `--s3-secret-key` / `--db-url` directly in args
(not recommended for production — use Secrets or an external secrets manager).

Replace the PVC volume with an `emptyDir` for the write buffer:

```yaml
volumes:
  - name: tls-certs
    secret:
      secretName: sudo-logger-tls
      defaultMode: 0400
  - name: buffer
    emptyDir: {}   # replaces the PVC — only holds in-flight uploads
```

And mount it:
```yaml
volumeMounts:
  - name: tls-certs
    mountPath: /etc/sudo-logger
    readOnly: true
  - name: buffer
    mountPath: /var/lib/sudo-logger/buffer
```

**Step 3 — migrate existing sessions (first deployment only):**

```bash
# Run once from any machine that can reach S3 and PostgreSQL
migrate-sessions \
  --logdir /var/log/sudoreplay \
  --db-url 'postgres://sudologger@postgres:5432/sudologger?sslmode=require' \  # pragma: allowlist secret
  --s3-bucket sudo-logs \
  --s3-endpoint https://minio.internal:9000 \
  --s3-path-style \
  --workers 8
```

### Security notes

- The container runs as UID 65532 (distroless `nonroot`) with a read-only
  root filesystem and all Linux capabilities dropped.
- TLS private key and ACK signing key are mounted read-only from a Kubernetes
  Secret (`defaultMode: 0400`).
- Store S3 credentials and the database URL in Kubernetes Secrets (or an
  external secrets manager such as Vault or ESO), not in deployment args.
- Consider using `loadBalancerSourceRanges` in `service.yaml` to restrict
  which IP ranges can reach port 9876.

---

## Performance and capacity

| Resource | Per session |
|----------|-------------|
| Goroutines | 3 (main loop + ACK reader + heartbeat) |
| Memory | ~100–200 KB |
| File descriptors | 4 |

**FD limit** is the first hard limit. At 4 FD/session the default limit of
1 024 caps at ~250 sessions. Add `LimitNOFILE=65536` to the server service
file to raise this to ~15 000+ sessions.

**Known resource leak:** a shipper that is killed without sending
`SESSION_END` and without the OS sending a TCP RST (e.g. VM hard-reset
with network down) leaves a goroutine and 4 FDs open on the server.
The included `sudo-logserver-restart.timer` restarts the server daily at
03:00 to reclaim any leaked resources. For Kubernetes deployments, add a
liveness probe instead.

---

## Troubleshooting

### `sudo: error in /etc/sudo.conf: unable to load plugin`

```bash
ls -la /usr/libexec/sudo/sudo_logger_plugin.so
grep Plugin /etc/sudo.conf
# Expected: Plugin sudo_logger_plugin sudo_logger_plugin.so
```

### `sudo-logger: cannot connect to shipper daemon`

```bash
systemctl status sudo-shipper
journalctl -u sudo-shipper -n 50
ls /run/sudo-logger/plugin.sock
```

### `sudo-logger: cannot reach log server: tls: ...`

- **`x509: certificate is not valid for any names`**: regenerate with the
  correct server hostname: `bash setup.sh /tmp/pki your-actual-hostname`
- **`x509: certificate signed by unknown authority`**: CA cert mismatch
  between client and server.

### Terminal freezes and network has returned

If the freeze banner is visible and the network is back, the session should
resume automatically within ~1 second once a `HEARTBEAT_ACK` arrives.

If bash was suspended by job control (visible as `[1]+ Stopped sudo bash`
in the parent shell), run `fg` to bring it back to the foreground.

### Terminal freezes and `fg`/network does not resume

If the network was down for > 2 s, the TCP connection is gone and the
session cannot recover. Use Ctrl+C to kill the frozen session, wait for
the network to return, then start a new `sudo` session.

### Terminal freezes immediately on session start

The shipper cannot reach the server, or the `ack-verify.key` on the client
does not match the `ack-sign.key` on the server:
```bash
journalctl -u sudo-shipper -n 50
# On the server:
journalctl -u sudo-logserver -n 50
```

### Freeze is too slow after network loss

Ensure you are running client ≥ 1.3.0 and server ≥ 1.3.0. Earlier versions
used TCP keepalive only (~2 s latency). Current versions use heartbeats (~1 s).

---

## License

sudo-logger is licensed under the [GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0).

This means:
- You are free to use, modify, and distribute this software
- Any modifications must be released under the same license
- If you run a modified version as a network service, you must make the source available to users of that service
