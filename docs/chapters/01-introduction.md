# Introduction

## What is sudo-logger?

sudo-logger is a session recording and audit system for privilege escalation events on Linux. It hooks into every `sudo` invocation at the kernel plugin level, captures all terminal input and output in real time, and streams the data over mutual TLS to a central log server. Every keystroke and every byte of output produced by a privileged process is preserved as an asciinema v2 cast file. Beyond `sudo`, the agent supplements coverage by using eBPF tracepoints to catch `pkexec` invocations and direct root shells that would otherwise bypass the sudo plugin, and by monitoring D-Bus/polkit privilege grants. The result is a complete audit trail of privileged activity across a fleet of Linux hosts, searchable and replayable through a web UI.

---

## How it differs from alternatives

| Tool | What it does | Gap vs sudo-logger |
|---|---|---|
| **sudoreplay** (built-in sudo) | Records sudo sessions as local tty logs; `sudoreplay` replays them locally | Local only; no central server; no real-time streaming; no eBPF coverage; no web UI; session files are on the compromised host |
| **tlog** (SSSD) | Records full login sessions via a PAM module into a structured JSON log | Requires SSSD integration; records the entire login session rather than per-command; no cgroup freeze enforcement; no pkexec or polkit coverage |
| **auditd** | Kernel audit framework records syscall-level events and command metadata | Records command names and arguments only — no terminal I/O content; no replay capability; high configuration complexity |
| **PAM-based solutions** | Hook at PAM layer to capture session open/close events | No I/O recording; no replay; typically capture authentication events only, not command output |

sudo-logger records the full byte stream of terminal I/O for each individual `sudo` invocation, forwards it in real time with integrity guarantees (ed25519-signed acknowledgements per chunk), and provides a web replay UI. Coverage extends beyond sudo to eBPF-tracked `pkexec` invocations and D-Bus/polkit events. A cgroup-based freeze mechanism blocks the child process if the connection to the log server is lost, ensuring data cannot escape capture.

---

## Component overview

### C plugin (`plugin/plugin.c`)

The sudo I/O plugin is a shared library (`sudo_logger_plugin.so`) loaded by sudo via the `Plugin` directive in `/etc/sudo.conf`. It hooks sudo's plugin API at the `log_ttyin`, `log_ttyout`, `log_stdin`, `log_stdout`, and `log_stderr` entry points to intercept all terminal I/O before it reaches the terminal or the child process. The plugin connects to the local agent over a Unix domain socket (`/run/sudo-logger/plugin.sock`) and forwards session data as a length-prefixed binary protocol. It also participates in the cgroup freeze mechanism: when the agent signals a freeze the plugin blocks its I/O forwarding loop, preventing any further output from being delivered to the terminal until the agent receives an acknowledgement from the server.

### Agent (`go/cmd/agent/`)

The agent is a Go daemon running as root on each monitored host (systemd unit: `sudo-logger-agent`). It consolidates six subsystems:

- **Plugin handler** — listens on the Unix socket, accepts connections from the sudo plugin (verified via `SO_PEERCRED` to be root), opens one mTLS connection to the log server per session, and forwards framed session data in real time. ACKs received from the server are verified against the ed25519 public key (`VerifyKey` in `agentConfig`).
- **eBPF subsystem** — loads three kernel tracepoints at startup (`sys_enter_write`, `sys_enter_execve`, `sched_process_exit`) to capture TTY I/O from all processes in tracked cgroups, including `pkexec` invocations and subprocesses inside SSH or TTY login sessions. Degrades gracefully to plugin-only mode on kernels without BTF support (`/sys/kernel/btf/vmlinux`).
- **Cgroup manager** — creates a per-session cgroup subtree for each sudo invocation. Freezes all child processes in the cgroup within approximately 800 ms if ACKs from the server stop arriving, preventing output from escaping capture during a network outage. Sessions frozen longer than `FreezeTimeout` (default: 3 minutes) are terminated with a human-readable banner.
- **D-Bus/polkit monitor** — monitors the system D-Bus using `BecomeMonitor` to track polkit privilege grants, generating event records with `source = "dbus-polkit"`.
- **Process sandbox (eBPF LSM)** — an optional kernel-level restriction layer (`go/cmd/agent/bpf/sandbox.bpf.c`) enforcing a deny-list of protected files, capabilities, and operations on every process running inside a session cgroup. Twenty hooks are loaded at startup: 18 LSM hooks plus `sched_process_fork`/`sched_process_exit` tracepoints. Enabled by setting `SandboxConfig` to a `sandbox.yaml` path.
- **Sudoers management** — polls the log server for a desired sudoers config per host, validates it with `visudo -c`, and atomically installs it to `/etc/sudoers.d/sudo-logger-managed`; reports state back via `MsgSudoersSnapshot`.

The agent reads its configuration from `/etc/sudo-logger/agent.conf` at startup (parsed by `go/cmd/agent/config.go`).

### Log server (`go/cmd/server/`)

The log server is a Go daemon (systemd unit: `sudo-logserver`) that accepts mTLS connections from agents on port 9876 (configurable via `--listen`). It stores each session as an asciinema v2 cast file on local disk (default `--logdir /var/log/sudoreplay`) or in a distributed backend (PostgreSQL metadata + S3/MinIO session files, selected via `--storage=distributed`). The server signs each acknowledgement with an ed25519 private key (`--signkey`), so the agent can verify that ACKs originate from the legitimate server and not an impostor. An optional plain-HTTP health and metrics endpoint is available via `--health-listen`.

### Replay server (`go/cmd/replay-server/`)

The replay server is a Go daemon (systemd unit: `sudo-replay`) that serves a browser-based web UI on port 8080 (configurable via `--listen`). It reads session files from the same storage backend as the log server and provides:

- A session list view with full-text search across user, host, command, and session content.
- A terminal player powered by **asciinema-player** for faithful reproduction of recorded terminal sessions, including resize events.
- Risk scoring using configurable YAML rules (`--rules /etc/sudo-logger/risk-rules.yaml`).
- Role-based access control (RBAC): `admin` and `viewer` roles, configured via `--admin-users`.
- JIT (just-in-time) approval workflows for privileged commands.
- SIEM forwarding via `--siem-config /etc/sudo-logger/siem.yaml` (HTTPS, syslog UDP/TCP/TLS; JSON, CEF, and OCSF formats).
- A Prometheus metrics endpoint at `GET /metrics` on the main port.

---

## Data flow overview

```
┌─────────────────────────── monitored host ──────────────────────────────┐
│                                                                          │
│   user                                                                   │
│    │  sudo <command>                                                      │
│    ▼                                                                      │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  sudo process                                                    │   │
│  │  (loads /usr/libexec/sudo/sudo_logger_plugin.so                  │   │
│  │   via Plugin directive in /etc/sudo.conf)                        │   │
│  │                                                                  │   │
│  │  I/O hooks: log_ttyin, log_ttyout, log_stdin,                   │   │
│  │             log_stdout, log_stderr                                │   │
│  └────────────────────────┬─────────────────────────────────────────┘   │
│                           │ Unix socket                                  │
│                           │ /run/sudo-logger/plugin.sock                 │
│                           ▼                                              │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │  sudo-logger-agent                                                │  │
│  │                                                                   │  │
│  │  ┌──────────────┐   ┌────────────────────────────────────────┐   │  │
│  │  │ plugin       │   │ eBPF tracepoints:                      │   │  │
│  │  │ handler      │   │   sys_enter_write  (TTY I/O, cgroups)  │   │  │
│  │  │ (per-session │   │   sys_enter_execve (pkexec detection)  │   │  │
│  │  │  goroutine)  │   │   sched_process_exit                   │   │  │
│  │  └──────┬───────┘   └─────────────────┬──────────────────────┘   │  │
│  │         │                             │                           │  │
│  │  ┌──────▼─────────────────────────────▼─────────────────────┐    │  │
│  │  │  cgroup manager + D-Bus/polkit monitor                    │    │  │
│  │  └───────────────────────────────────────────────────────────┘    │  │
│  └───────────────────────────────────┬───────────────────────────────┘  │
│                                      │ mTLS, port 9876                  │
└──────────────────────────────────────┼──────────────────────────────────┘
                                       │
                                       ▼
                    ┌──────────────────────────────────────────┐
                    │  sudo-logserver (log server)             │
                    │                                          │
                    │  storage:                                │
                    │    local:        /var/log/sudoreplay/    │
                    │    distributed:  PostgreSQL + S3/MinIO   │
                    │                                          │
                    │  signs ACKs with ed25519 private key     │
                    │  optional: --health-listen :9877         │
                    └──────────────────┬───────────────────────┘
                                       │  reads same storage
                    ┌──────────────────▼───────────────────────┐
                    │  sudo-replay-server (web UI)             │
                    │                                          │
                    │  port 8080                               │
                    │  session list + full-text search         │
                    │  asciinema-player terminal replay        │
                    │  risk scoring, RBAC, SIEM config         │
                    │  GET /metrics (Prometheus)               │
                    └──────────────────────────────────────────┘
                                       ▲
                                       │  browser HTTP/HTTPS
                                    operator
```

---

## Deployment models

### Single-host (default)

All components run together. The log server writes sessions to local disk under `/var/log/sudoreplay`. The replay server reads from the same path. This is the standard RPM-based installation: install `sudo-logger-client` on each monitored host and `sudo-logger-server` plus `sudo-logger-replay` on a central log server.

```
monitored host 1  ──┐
monitored host 2  ──┤  mTLS :9876   sudo-logserver  (local disk: /var/log/sudoreplay)
monitored host N  ──┘                       │
                                    sudo-replay-server  :8080
```

### Distributed (Kubernetes / multi-server)

In distributed mode (`--storage=distributed`), the log server and replay server both use a PostgreSQL DSN (`--db-url`) for session metadata and an S3-compatible object store (`--s3-bucket`, `--s3-endpoint`) for session files. This allows horizontal scaling of the replay server and full separation of the write path from the read path. A local write-buffer directory (`--buffer-dir /var/lib/sudo-logger/buffer`, default) absorbs sessions temporarily when the S3 upload is delayed.

The `migrate-sessions` tool (`go/cmd/migrate-sessions/`) migrates existing local-disk sessions into the distributed backend when converting an existing installation.

```
monitored hosts ──── mTLS :9876 ──── sudo-logserver  ──── S3/MinIO (session files)
                                           │
                                       PostgreSQL (metadata)
                                           │
                                    sudo-replay-server  :8080  (read-only, scalable)
```

---

## What gets recorded

| Data | Source | Notes |
|---|---|---|
| Terminal output (`stdout`, `stderr`) | sudo I/O plugin (`log_ttyout`, `log_stdout`) | Every byte written to the terminal by the privileged command |
| Terminal input (`stdin`) | sudo I/O plugin (`log_stdin`) | Keystrokes typed by the user |
| TTY I/O from child processes | eBPF `sys_enter_write` | Captures output from subprocesses, `su`, `screen`, `tmux` within the session cgroup — no separate session entries |
| `pkexec` invocations | eBPF `sys_enter_execve` | Recorded with `source = "ebpf-pkexec"`; terminal I/O included if a TTY is present |
| D-Bus/polkit privilege grants | D-Bus `BecomeMonitor` | Recorded as event cards with `source = "dbus-polkit"`; no terminal I/O — metadata only |
| Session metadata | Plugin + agent | User, host, command, timestamps (`yyyy-mm-dd HH:mm`), exit code, terminal dimensions (cols × rows), working directory, `runas` user and UID/GID |
| Terminal resize events | Plugin (`TIOCGWINSZ` poll, 150 ms interval) | Stored as asciinema v2 `r` events; reproduced faithfully in replay |

> **Note:** The eBPF subsystem requires `/sys/kernel/btf/vmlinux` (Linux 5.8+ with `CONFIG_DEBUG_INFO_BTF=y`). On older kernels or when BTF is absent the agent falls back to plugin-only mode automatically; `pkexec` and direct root-shell TTY sessions are not captured in that mode.

---

## Security properties

sudo-logger is designed so that a compromised client (agent or plugin) cannot forge log entries for other hosts, forge ACKs to unfreeze a blocked session, or bypass the logging requirement without the log server noticing.

| Property | Detail |
|---|---|
| **Session blocked at start** | If the log server is unreachable when `sudo` runs, the session is rejected before the command executes. No data escapes without being logged. |
| **Child process frozen on network loss** | If ACKs from the log server stop arriving, the cgroup freeze fires within approximately 800 ms. The child process cannot produce more output until the log server responds. |
| **Freeze timeout terminates session** | If the freeze persists longer than `FreezeTimeout` (default: 3 minutes), the agent sends a `FREEZE_TIMEOUT` signal to the plugin, which prints a banner and kills the session. |
| **Mutual TLS** | Both the agent (client) and the log server authenticate with certificates signed by a shared CA. An unknown client certificate is rejected by the server. |
| **Asymmetric ACK signing (ed25519)** | The server signs each acknowledgement with its ed25519 private key over `sessionID \|\| seq \|\| ts_ns`. A compromised agent cannot forge ACKs for sessions it does not own, and cannot replay an ACK from one session to unfreeze a different session. |
| **Host field verified against TLS certificate** | The server rejects `SESSION_START` if the claimed `host` field does not match the CN or DNS SANs of the presenting client certificate. A compromised agent on host A cannot forge log entries attributed to host B. |
| **Plugin socket peer verification** | The agent verifies via `SO_PEERCRED` that only processes running as root (i.e. sudo) may connect to `/run/sudo-logger/plugin.sock`. |
| **Ctrl+C always works** | `Ctrl+C` and `Ctrl+\` are forwarded to the child even while the cgroup is frozen, so the operator can always kill a hung session. |

---

## Agent configuration reference

The agent reads `/etc/sudo-logger/agent.conf` at startup. The file uses `key = value` syntax; keys are matched case-sensitively as exact lowercase strings (the loader does not lower-case input), and unknown keys are silently ignored for backward compatibility. The `agentConfig` struct in `go/cmd/agent/config.go` defines the full set of fields.

| Key | Default | Description |
|---|---|---|
| `server` (also accepts the literal key `LOGSERVER`) | `logserver:9876` | Log server address (`host:port`); mTLS connection target |
| `socket` | `/run/sudo-logger/plugin.sock` | Unix socket path the agent listens on for plugin connections |
| `cert` | `/etc/sudo-logger/client.crt` | Agent client TLS certificate (PEM) |
| `key` | `/etc/sudo-logger/client.key` | Agent client TLS private key (PEM) |
| `ca` | `/etc/sudo-logger/ca.crt` | CA certificate used to verify the server (PEM) |
| `verify_key` | `/etc/sudo-logger/ack-verify.key` | ed25519 public key for ACK signature verification (PEM) |
| `mask_pattern` | (empty) | One regular expression per occurrence; repeat the key on multiple lines to add more than one pattern. Matching content in session output is redacted before forwarding |
| `freeze_timeout` | `3m` | How long to keep the cgroup frozen before terminating the session |
| `idle_timeout` | `0` (disabled) | Maximum time a session can be idle before it is terminated |
| `disclaimer` | (empty) | Text displayed to users before a sudo session begins |
| `disclaimer_color` | (empty) | Terminal colour for the disclaimer banner |
| `ebpf` | `true` | Enable or disable the eBPF subsystem (set to `false` on kernels without BTF) |
| `sandbox_config` | (empty) | Path to `sandbox.yaml` deny-list; empty disables the eBPF LSM sandbox |
| `hostname` | (auto) | Override the agent's auto-detected hostname (FQDN via reverse DNS) |
| `debug` | `false` | Enable verbose debug logging to stderr |

### Minimal agent.conf example

```ini
server        = logserver.example.internal:9876
cert          = /etc/sudo-logger/client.crt
key           = /etc/sudo-logger/client.key
ca            = /etc/sudo-logger/ca.crt
verify_key    = /etc/sudo-logger/ack-verify.key
freeze_timeout = 3m
ebpf          = true
```

---

## Session sources and source badges

The replay UI displays a source badge on session cards that were not recorded through the sudo plugin directly. The `source` field in `session.json` identifies the recording path.

| `source` value | Badge | Meaning |
|---|---|---|
| `plugin` (or empty) | *(no badge)* | Standard sudo session via the C plugin |
| `ebpf-tty` | `ebpf` | Login-shell TTY session captured via eBPF `sys_enter_write` within a tracked cgroup |
| `ebpf-pkexec` | `pkexec` | `pkexec` invocation captured via eBPF `sys_enter_execve` |
| `dbus-polkit` | `polkit` | D-Bus polkit privilege grant; event record only, no terminal I/O |

Sessions with `source = "ebpf-pkexec"` that have no associated I/O, and all `dbus-polkit` sessions, are displayed as event cards in the replay UI rather than as playable recordings.

---

## Quick-start overview

The following sequence summarises a minimal installation. Each step is covered in detail in Chapter 3 (Installation).

**1. Bootstrap the PKI**

Run `setup.sh` on the log server to generate the CA, server certificate, and an initial client certificate:

```bash
bash setup.sh
```

The script writes all certificate material to `/etc/sudo-logger/`.

**2. Install the log server and replay server**

```bash
dnf install sudo-logger-server-<version>.rpm sudo-logger-replay-<version>.rpm
systemctl enable --now sudo-logserver sudo-replay
```

**3. Install the agent on each monitored host**

Copy the client certificate and CA from the log server, then install the client package:

```bash
dnf install sudo-logger-client-<version>.rpm
systemctl enable --now sudo-logger-agent
```

**4. Configure sudo to load the plugin**

Add to `/etc/sudo.conf`:

```
Plugin sudoers_policy sudoers.so
Plugin sudo_logger_plugin sudo_logger_plugin.so
```

**5. Verify**

Run a test sudo command on a monitored host and open `http://<logserver>:8080` in a browser. The session should appear in the session list within a few seconds.

---

## Repository layout

The complete source tree is structured as follows:

```
sudo-logger/
├── plugin/
│   ├── plugin.c                 # sudo I/O plugin (C)
│   └── include/
│       └── sudo_plugin.h        # vendored sudo plugin API header (no sudo-devel needed to build)
├── go/
│   ├── go.mod
│   └── cmd/
│       ├── agent/               # Agent daemon
│       │   ├── main.go          # Entry point: flags (-config, -version), startup
│       │   ├── plugin.go        # Unix socket handler
│       │   ├── ebpf.go          # eBPF ring buffer consumer
│       │   ├── ebpf_session.go  # eBPF-sourced session (pkexec/tty) writer
│       │   ├── divergence.go    # plugin vs. eBPF divergence detection
│       │   ├── cgroup.go        # Per-session cgroup management
│       │   ├── config.go        # agentConfig struct and file parser
│       │   ├── sandbox.go       # eBPF LSM sandbox loader/attacher
│       │   ├── sandbox_config.go   # sandbox.yaml parser
│       │   ├── sandbox_watch.go    # inotify re-protection on atomic file replace
│       │   ├── sandbox_poll.go     # polls server for sandbox.yaml via MsgFetchConfig
│       │   ├── redaction.go     # output redaction patterns
│       │   ├── sudoers.go       # sudoers snapshot push/pull
│       │   ├── tls.go           # mTLS config helpers
│       │   ├── groups.go        # local group resolution
│       │   └── bpf/
│       │       ├── recorder.c      # eBPF tracepoint hooks (I/O + execve + exit)
│       │       └── sandbox.bpf.c   # eBPF LSM sandbox (18 LSM hooks + 2 tracepoints)
│       ├── server/
│       │   ├── main.go          # Entry point
│       │   ├── config.go        # CLI flags
│       │   ├── handler.go       # Per-connection frame handling
│       │   ├── heartbeat.go     # Agent liveness tracking
│       │   └── approval.go      # JIT approval manager + REST API
│       ├── replay-server/
│       │   ├── main.go          # Entry point
│       │   ├── config.go        # CLI flags
│       │   ├── routes.go        # HTTP route registration
│       │   ├── middleware.go    # Auth/access-log middleware
│       │   ├── handlers_auth.go     # Login, OIDC, session cookies
│       │   ├── handlers_session.go  # Session list/replay/cast endpoints
│       │   ├── handlers_admin.go    # Users, roles, config endpoints
│       │   ├── approval_proxy.go    # Proxies approval calls to the log server
│       │   ├── oidc.go          # OIDC discovery/token verification
│       │   ├── rbac.go          # Role/permission model
│       │   ├── websocket.go     # Stub — unimplemented
│       │   ├── ui/              # React/TS SPA source
│       │   └── static/          # Vite build output (embedded via go:embed)
│       ├── migrate-sessions/
│       │   └── main.go          # Local-to-distributed migration tool
│       └── loadgen/
│           └── main.go          # Synthetic session load generator for testing
│   └── internal/
│       ├── store/               # SessionStore interface + local + distributed backends
│       ├── protocol/            # Wire protocol frame types and constants
│       ├── iolog/               # asciinema v2 session.cast writer
│       ├── config/              # ResolveSecret helper
│       ├── policy/              # Blocked/whitelisted user policy helpers
│       └── siem/                # SIEM forwarding (HTTPS, syslog; JSON, CEF, OCSF)
├── rpm/
│   ├── sudo-logger-client.spec
│   ├── sudo-logger-server.spec
│   └── sudo-logger-replay.spec
├── setup.sh                     # PKI bootstrap script
├── sudo-logger-agent.service    # systemd unit
├── sudo-logserver.service       # systemd unit
└── sudo-replay.service          # systemd unit
```
