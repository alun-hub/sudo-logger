# Architecture

sudo-logger is a mandatory sudo session recording system. Every sudo invocation is intercepted, all terminal I/O is streamed to a central server, and the command is **frozen** if the server becomes unreachable — ensuring no sudo activity goes unlogged.

---

## Components

```
┌─────────────────────────────────────────────────────────────────┐
│  Client machine (each host)                                      │
│                                                                  │
│  ┌─────────────────┐   Unix socket    ┌───────────────────────┐  │
│  │  sudo + plugin  │ ──────────────► │  agent daemon         │  │
│  │  (C plugin)     │ ◄────────────── │  (Go, runs as root)   │  │
│  └─────────────────┘                 └──────────┬────────────┘  │
│                                                 │ TLS TCP :9876  │
└─────────────────────────────────────────────────┼───────────────┘
                                                  │
                                      ┌───────────▼────────────┐
                                      │  Log server            │
                                      │  (Go, central)         │
                                      │  /var/log/sudoreplay/  │
                                      └───────────┬────────────┘
                                                  │ reads from disk
                                      ┌───────────▼────────────┐
                                      │  Replay server         │
                                      │  (Go, browser GUI)     │
                                      │  HTTP :8080            │
                                      └────────────────────────┘
```

| Component | Language | Runs on | Purpose |
|-----------|----------|---------|---------|
| `plugin/plugin.c` | C | Every client (loaded by sudo) | Intercepts sudo, streams I/O, enforces freeze |
| `go/cmd/agent` | Go | Every client (systemd service) | Bridges plugin ↔ log server; eBPF session recording; pkexec tracking; divergence detection |
| `go/cmd/server` | Go | Central server | Receives sessions, writes .cast files, signs ACKs, enforces block policy |
| `go/cmd/replay-server` | Go | Central server | Browser GUI for playback, reporting, configuration |

---

## Session lifecycle

### 1. Startup (synchronous, blocks sudo)

```
plugin_open()
  │
  ├─ connect to agent (Unix socket /run/sudo-logger/plugin.sock)
  ├─ send SESSION_START (JSON: user, host, command, pid, terminal size…)
  │
  │             agent
  │               ├─ create session cgroup, move sudo PID into it
  │               ├─ connect to log server (TLS TCP :9876)
  │               ├─ forward SESSION_START to server
  │               │
  │               │             log server
  │               │               ├─ validate session (user/host names, TLS cert)
  │               │               ├─ check JIT approval policy
  │               │               │   ├─ exempt/window active → send SERVER_READY
  │               │               │   ├─ challenge required → send MSG_SESSION_CHALLENGE
  │               │               │   └─ denied → send SESSION_DENIED
  │               │               └─ open session directory + ACTIVE file
  │               │
  │               ├─ receive handshake from server
  │               │   ├─ SESSION_DENIED → forward to plugin, abort
  │               │   ├─ MSG_SESSION_CHALLENGE → forward to plugin
  │               │   │    │
  │               │   │    └─ plugin: prompt user for justification
  │               │   │       → send MSG_CHALLENGE_RESPONSE
  │               │   │       → agent forwards to server
  │               │   │       → server creates pending request, sends SESSION_DENIED (wait)
  │               │   │
  │               │   └─ SERVER_READY → send SESSION_READY to plugin
  │
  └─ receive SESSION_READY → sudo forks child (inherits cgroup)
     (or SESSION_DENIED / SESSION_ERROR → sudo blocked, message shown)
```

sudo is blocked at the prompt until the agent responds. If the log server requires JIT approval, the plugin will prompt the user for a justification (shown only once per host/window). If the session is denied or the request is pending, sudo never executes the command.

### 2. Recording (concurrent)

```
plugin (main thread)           agent                    log server
  │                              │                           │
  ├─ log_ttyin/ttyout()          │                           │
  │  → send CHUNK frames ───────►│                           │
  │    (seq, ts_ns, data)        ├─ forward CHUNK ──────────►│
  │                              │                           ├─ write to session.cast
  │                              │◄── signed ACK (seq) ──────┤
  │                              │                           │
  │◄── ACK_RESPONSE ─────────────┤ (plugin polls every 150ms)│
  │    (cached, no round-trip)   │                           │
  │                              │◄──── HEARTBEAT_ACK ───────┤
  │                              │  (agent sends HB/400ms) │
```

The plugin never waits for the server. It polls the agent for the latest ACK timestamp via ACK_QUERY/ACK_RESPONSE — the agent answers from its in-memory cache, making the round-trip sub-millisecond.

### 3. Freeze (network loss)

If the agent stops receiving ACKs or heartbeat replies for ~800 ms, it calls `cgroup.freeze` on the session cgroup. This suspends all child processes at the kernel level — they cannot be unfrozen with `fg`, `kill -CONT`, or by escaping to another cgroup (see [Cgroup isolation](#cgroup-isolation) below). When the connection recovers, the agent unfreezes and the session continues transparently.

### 4. Freeze-timeout and network-outage detection

If the network does not recover, the agent's freeze-timeout watchdog (default 5 min, `-freeze-timeout`) terminates the session. Two out-of-band messages allow the server to distinguish a **network outage** from an **agent kill**:

| Time | Actor | Event |
|------|-------|-------|
| t = 0 | — | Network drops |
| t ≈ 800 ms | Agent | `markDead()` fires; cgroup frozen; agent opens a **new TLS connection** and sends **SESSION_FREEZING (0x0f)** with the session ID |
| t ≈ 800 ms | Server | Receives SESSION_FREEZING; sets `freezeCandidate = true` on the active session |
| t ≈ 3.4 min | Server | TCP ETIMEDOUT — connection drops; because `freezeCandidate` is set, calls `MarkNetworkOutage()` instead of `MarkIncomplete()` |
| t = 5 min | Agent | Freeze-timeout fires; unfreeze cgroup; send `MsgFreezeTimeout` to plugin; send **SESSION_ABANDON (0x0e)** as fallback (succeeds only if network has recovered) |

**Why two messages?**
SESSION_FREEZING is sent at t≈800 ms when the server is still likely reachable over TCP. SESSION_ABANDON is sent at t=5 min after the watchdog fires — by then the network is often still down, making it unreliable as the sole signal. SESSION_ABANDON is kept as a fallback for sessions where SESSION_FREEZING was lost.

The replay server shows a distinct **⏱ network outage** badge for these sessions and suppresses the `incomplete_session` risk rule (+15 pts) — a network event is not a security incident.

### 5. High-Performance Data Pipeline (Release 12)

To handle 500+ concurrent sessions and massive I/O bursts (e.g., `cat` of multi-gigabyte files), the system uses an asynchronous, non-blocking pipeline:

- **Batch Disk Writer (Server)**: Instead of one system call per log chunk, the server collects up to 100 chunks in a memory queue and writes them as a single atomic batch to disk or the S3 buffer. This reduces I/O overhead by 99%.
- **Non-Blocking Ingestion (Server)**: The server's main network loop never blocks on disk I/O. If the primary disk queue (50,000 slots) is full, the server spawns temporary overflow goroutines to hold the data, ensuring the main loop remains free to process Heartbeats and ACKs instantly.
- **Thread-Safe Networking**: All network writes on the server are protected by a `netWriteMu` mutex, and the C plugin uses `g_send_mu`. This prevents interleaved bytes from different messages (e.g., an ACK and a Heartbeat) that would otherwise corrupt the protocol stream.
- **Precise Deadlines (Agent)**: Write deadlines are applied only to explicit `Flush()` calls. This prevents the TCP stream from being truncated mid-message by an automatic buffered write timeout.

### 6. JIT Approval Window & Session TTL

If JIT approval is enabled, the log server includes a `session_ttl` in the `SERVER_READY` message. This value is derived from the remaining time in the user's approval window.

```
agent (TTL timer)               plugin (monitor)             terminal
  │                              │                           │
  ├─ 60s remaining               │                           │
  ├─ send MSG_SESSION_WARNING ──►│                           │
  │                              ├─ print amber banner ─────►│ [ SUDO-LOGGER: window expires in 60s ]
  │                              │                           │
  ├─ 0s remaining                │                           │
  ├─ unfreeze cgroup             │                           │
  ├─ send MSG_SESSION_EXPIRED ──►│                           │
  │                              ├─ print red banner ───────►│ [ SUDO-LOGGER: session expired ]
  │                              ├─ send SIGTERM to sudo     │
  └─ close plugin connection     └─ exit                     │
```

The agent enforces the TTL at the kernel level by unfreezing and then terminating all processes in the session cgroup. This prevents users from outliving their approved window by leaving a `sudo bash` open.

### 7. Shutdown

```
plugin_close()
  ├─ send SESSION_END (final_seq, exit_code)
  │
  agent
  ├─ forward SESSION_END to server
  ├─ wait for cgroup to empty (all child PIDs exit)
  └─ remove session cgroup

log server
  ├─ write exit_code file
  ├─ remove ACTIVE marker
  └─ close session.cast
```

---

## Wire protocol

All messages share a 5-byte frame:

```
[1 byte: type][4 bytes: payload length, big-endian][N bytes: payload]
```

Defined in `go/internal/protocol/protocol.go` (Go) and inline in `plugin/plugin.c` (C).

| Hex | Name | Direction | Payload |
|-----|------|-----------|---------|
| `0x01` | `SESSION_START` | plugin→agent→server | JSON (SessionStart) |
| `0x02` | `CHUNK` | plugin→agent→server | seq(8)+ts_ns(8)+stream(1)+len(4)+data |
| `0x03` | `SESSION_END` | plugin→agent→server | final_seq(8)+exit_code(4) |
| `0x04` | `ACK` | server→agent | seq(8)+ts_ns(8)+sig(64) — ed25519 signed |
| `0x05` | `ACK_QUERY` | plugin→agent | empty |
| `0x06` | `ACK_RESPONSE` | agent→plugin | last_ts_ns(8)+last_seq(8) |
| `0x07` | `SESSION_READY` | agent→plugin | empty — sudo may proceed |
| `0x08` | `SESSION_ERROR` | agent→plugin | string — infrastructure failure, sudo blocked |
| `0x09` | `HEARTBEAT` | agent→server | empty — sent every 400 ms |
| `0x0a` | `HEARTBEAT_ACK` | server→agent | empty |
| `0x0b` | `SERVER_READY` | server→agent | empty — session accepted |
| `0x0c` | `SESSION_DENIED` | server→agent, agent→plugin | string block message — policy denial |
| `0x0d` | `FREEZE_TIMEOUT` | agent→plugin | empty — server unreachable beyond `-freeze-timeout`; session will be terminated |
| `0x0e` | `SESSION_ABANDON` | agent→server (new conn) | UTF-8 session_id — freeze-timeout fired; server marks session `freeze_timeout` |
| `0x0f` | `SESSION_FREEZING` | agent→server (new conn) | UTF-8 session_id — session is being frozen due to network loss |
| `0x18` | `MsgSudoersSnapshot` | agent→server | JSON `SudoersSnapshot` — full snapshot of `/etc/sudoers` + `/etc/sudoers.d/` |
| `0x19` | `MsgSudoersError` | agent→server | JSON `SudoersError` — `visudo -c` validation failure when applying a pushed config |
| `0x1a` | `MsgHeartbeatAgent` | agent→server | UTF-8 host name — sudoers liveness keepalive, every 30 s |

CHUNK stream types: `0x00` stdin, `0x01` stdout, `0x02` stderr, `0x03` tty-in, `0x04` tty-out.

---

## ACK signing

The server signs every ACK with an **ed25519 private key** (`/etc/sudo-logger/ack-sign.key`). The agent verifies signatures using the corresponding public key (`/etc/sudo-logger/ack-verify.key`). The signed message is:

```
sessionID || 0x00 || seq_be(8) || ts_ns_be(8)
```

The session ID in the signature prevents a valid ACK from one session being replayed to satisfy the freeze check of another. A compromised agent cannot forge ACKs for sessions it does not own.

---

## Cgroup isolation

The agent places each sudo session in a dedicated cgroup subtree under the agent's delegated cgroup. This enables two things:

1. **Atomic freeze** — `echo 1 > cgroup.freeze` suspends every process in the subtree simultaneously, including GUI applications that re-parent to init.

2. **Escape prevention** — the plugin calls `unshare(CLONE_NEWCGROUP)` immediately after receiving `SESSION_READY`. All child processes see the session cgroup as the root of the cgroup hierarchy. Writing a PID to `/sys/fs/cgroup/../../escape/cgroup.procs` resolves only within the private subtree and fails — even with `CAP_SYS_ADMIN`.

For processes that escape to foreign cgroups before the namespace is established (e.g. GNOME or systemd moving a GUI process to an app scope), the agent tracks them via `/proc/<pid>/cgroup` polling and sends `SIGSTOP`/`SIGCONT` as a fallback.

---

## eBPF Subsystem

The agent includes a unified eBPF subsystem that provides kernel-level observability and divergence detection. It requires BTF support (`/sys/kernel/btf/vmlinux`) and kernel ≥ 5.8.

### Divergence detection

The agent uses the `sys_enter_execve` tracepoint to record every execution of `sudo` and `pkexec` on the system. When an execution is detected:

1. The agent starts a **30-second timer**.
2. It waits for a matching `SESSION_START` message from the sudo plugin.
3. If the timer expires without a match, a **divergence alert** is generated.

This detects plugin tampering, binary replacement, or cases where `sudo` was compiled without plugin support.

### pkexec tracking

Unlike `sudo`, `pkexec` does not support I/O plugins. The eBPF subsystem captures TTY input and output for `pkexec` sessions by tracking the process hierarchy and intercepting `write` syscalls to TTY devices.

### Outage buffering

When the log server is unreachable, the eBPF subsystem buffers session chunks in memory. Once the connection is re-established, the buffer is flushed in-order to ensure zero data loss for short network blips.

---

## Process Sandbox (eBPF LSM)

For high-security environments, the agent can enforce a kernel-level sandbox on sudo sessions. This is implemented using **eBPF LSM hooks** and is effective even against a root user.

The sandbox is configured via `/etc/sudo-logger/sandbox.yaml` and enforces:

- **File Immutability**: Blocks writes, truncations, and deletions of protected files (e.g., `/etc/shadow`).
- **Directory Protection**: Prevents file creation inside protected directories (e.g., `/etc/pam.d`).
- **Process Protection**: Prevents sending signals (SIGKILL, etc.) to protected system daemons.
- **Socket Protection**: Prevents deletion or replacement of critical Unix sockets.

The sandbox is automatically propagated to all child processes via the `sched_process_fork` tracepoint.

---

## Session storage

Two storage backends are supported, selected with the `-storage` flag on both the log server and the replay server.

### Local storage (default)

The log server writes sessions to disk in a two-level hierarchy:

```
/var/log/sudoreplay/
└── <user>/
    └── <host>_<timestamp>/
        ├── session.cast   ← asciinema v2 recording
        ├── ACTIVE         ← present while session is live (removed on close)
        ├── INCOMPLETE     ← written if connection drops without SESSION_END
        └── exit_code      ← written on clean SESSION_END
```

`session.cast` is compatible with `sudoreplay(8)` and asciinema v2 viewers:

```
line 1:  JSON header  {"version":2, "width":..., "height":..., "user":..., "host":..., ...}
line 2+: JSON events  [relative_time, "o"|"i", base64_data]
```

### Distributed storage (Kubernetes / multi-replica)

Specify `-storage=distributed -s3-bucket=<name> -db-url=<DSN>` on both servers.

| What | Where |
|------|-------|
| `session.cast` files | S3 or S3-compatible store (MinIO, StorageGRID) |
| Session metadata | PostgreSQL `sudo_sessions` table |
| Risk score cache | PostgreSQL `sudo_risk_cache` table |
| Blocked-user policy | PostgreSQL `sudo_blocked_users` table |
| SIEM / server config | PostgreSQL `sudo_config` table |
| Session access audit | PostgreSQL `sudo_access_log` table |

The log server buffers cast files locally (configurable with `-buffer-dir`) and uploads them to S3 after each session closes.

The PostgreSQL schema is created automatically at first startup.

---

## Replay server

The replay server is a self-contained HTTP server that embeds a single-page application (vanilla JavaScript + vendored xterm.js). In local mode it reads session data directly from the log directory on disk. In distributed mode it fetches cast files from S3 and reads metadata from PostgreSQL.

### Session index

**Local mode:** Sessions are discovered by scanning the two-level directory tree. The index is rebuilt at most once per 30 seconds and cached in memory. A file-system watcher (`fsnotify`) triggers an immediate rebuild when new session directories appear.

**Distributed mode:** Session metadata is read from PostgreSQL on each request (with database-side filtering and pagination). No full-scan index is needed.

### Risk scoring

A YAML rules file (`/etc/sudo-logger/risk-rules.yaml`) defines scoring rules. Each rule can match on command name, terminal output content, run-as user, session duration, time of day, and whether the session ended cleanly. Scores accumulate across matching rules (capped at 100). Computed scores are cached in `risk.json` alongside the session (local mode) or in `sudo_risk_cache` (distributed mode) and invalidated when the rules change.

### SIEM forwarding

Completed sessions are forwarded after each session closes:

- **Local mode:** The replay server watches for removal of the `ACTIVE` marker using `inotify(7)`.
- **Distributed mode:** The replay server polls `sudo_sessions` every 5 seconds for newly completed sessions.

When multiple replay-server replicas run (distributed mode), only one pod forwards events. Leader election uses a PostgreSQL advisory lock (`pg_try_advisory_lock(0x5349454d)`) acquired on a dedicated connection at startup. The lock is released automatically when the connection closes (pod death or restart), allowing another replica to take over within one poll cycle.

Three SIEM transports are supported: `https` (mTLS POST), `syslog` (UDP/TCP/TCP-TLS), and `stdout` (write to container stdout for Fluentd/Promtail/Vector collection — recommended for Kubernetes).

### Access log

Who viewed which session is recorded in the access log:

- **Local mode:** In-memory ring buffer (up to 10,000 entries); lost on restart.
- **Distributed mode:** Persisted to the `sudo_access_log` PostgreSQL table; shared across all replicas and survives pod restarts.

### Health and metrics

| Path | Description |
|------|-------------|
| `GET /healthz` | Always returns `200 ok`. Use for K8s liveness/readiness probes. |
| `GET /metrics` | Prometheus metrics (views total). |

### API endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/healthz` | Health check (K8s probes) |
| `GET` | `/api/sessions` | Session list with filtering, sorting, pagination |
| `GET` | `/api/session/events` | Stream playback events for a session |
| `GET` | `/api/access-log` | Audit log of who viewed which sessions |
| `GET` | `/api/report` | Aggregate statistics and anomaly detection |
| `GET/PUT` | `/api/rules` | Risk scoring rules |
| `GET/PUT` | `/api/siem-config` | SIEM forwarding configuration |
| `POST` | `/api/siem-cert` | Upload TLS certificate for SIEM (local mode only) |
| `GET/PUT` | `/api/blocked-users` | Blocked users policy |
| `GET` | `/api/approvals` | List pending approval requests |
| `POST` | `/api/approvals/{id}/approve` | Approve a request (param: `window`) |
| `POST` | `/api/approvals/{id}/deny` | Deny a request (body: `{reason}`) |
| `GET/PUT` | `/api/approval-config` | JIT approval policy configuration |
| `GET` | `/api/hosts` | Unique host names seen in session history |
| `GET` | `/metrics` | Prometheus metrics |
| `GET` | `/api/sudoers/hosts` | All hosts with sudoers snapshot or session history; includes `inSync`, `isOffline`, `isOverride`, and `error` fields |
| `GET` | `/api/sudoers/snapshots` | Latest snapshots for a host (`?host=`) |
| `GET/PUT/DELETE` | `/api/sudoers/config` | Desired sudoers config for a host or `_default` template |

---

## Block policy

Security teams can block individual users from running sudo without touching sudoers files.

In **local mode** the policy is stored in `/etc/sudo-logger/blocked-users.yaml`.
In **distributed mode** it is stored in the `sudo_blocked_users` PostgreSQL table, shared across all replicas automatically.

```
security team (browser)
  └─ PUT /api/blocked-users
       └─ replay server writes blocked-users.yaml (local)
          or updates sudo_blocked_users table (distributed)

log server (background goroutine)
  └─ reloads policy every 30 s

next sudo attempt by blocked user
  └─ log server sends SESSION_DENIED during startup handshake
       └─ agent forwards SESSION_DENIED to plugin
            └─ plugin shows red banner + configured message
                 └─ sudo exits without running the command
```

Blocking is per-user and optionally per-host. An empty host list means "all hosts". The block message is configurable from the GUI.

---

## Sudoers management

Operators push desired sudoers rules to managed hosts from the **Sudoers** tab in the replay UI. The agent applies the config locally and reports sync status back in near-real time.

### Data flow

```
replay UI
  PUT /api/sudoers/config?host=_default   ← global template
  PUT /api/sudoers/config?host=<hostname> ← per-host override
       │
       stored in SessionStore (file: .sudoers/<key> / distributed: sudo_config table)

agent (every 15 s, MsgFetchConfig)
  ├─ fetch "sudoers/<host>" → fallback "sudoers/_default"
  ├─ content changed AND previous content didn't fail validation?
  │    └─ write tmpfile → visudo -c tmpfile
  │         ├─ success → rename onto /etc/sudoers.d/sudo-logger-managed
  │         │            send MsgSudoersSnapshot (0x18)
  │         └─ failure → remove tmpfile
  │                       send MsgSudoersError (0x19)
  ├─ content empty AND no fetch error?
  │    └─ remove /etc/sudoers.d/sudo-logger-managed
  │       send MsgSudoersSnapshot (0x18)
  └─ fetch error → leave existing file untouched

agent inotify watcher + 10-min periodic tick
  └─ send MsgSudoersSnapshot whenever /etc/sudoers or /etc/sudoers.d changes

agent MsgHeartbeatAgent (0x1a, every 30 s)
  └─ log server updates last_seen timestamp for this host
```

### Sync computation

`handleGetSudoersHosts` in the replay server computes sync state per host:

```go
staged  = stripSudoersHeader(hostConfig ?? defaultConfig)
managed = extractManagedSudoers(latestSnapshot.Content)
inSync  = (staged == managed)
```

`stripSudoersHeader` normalises the config: strips `# sudo-logger` header lines and
whitespace around operators so minor formatting differences do not cause false diffs.
`extractManagedSudoers` extracts the `# --- /etc/sudoers.d/sudo-logger-managed ---`
block from the concatenated snapshot.

### Snapshot storage

Each snapshot is stored keyed by `(host, sha256)`. When an agent re-sends an
identical snapshot (e.g. after reverting to a previously-seen config), the
`uploaded_at` timestamp is refreshed so `ListSudoersSnapshots ORDER BY uploaded_at DESC`
returns the correct most-recent entry — preventing stale diffs in the UI.

### Security

- Host names in `MsgSudoersSnapshot`, `MsgSudoersError`, and `MsgHeartbeatAgent` are
  validated against a strict allowlist: non-empty, ≤ 255 chars, no `/`, `\`, `..`,
  or leading `.`. Rejects path traversal attempts against the local snapshot store.
- Config is validated by `visudo -c` on the agent before any write.
- The managed file is written atomically (tmp + `rename`).
- `/etc/sudoers` is never touched — the agent only manages
  `/etc/sudoers.d/sudo-logger-managed`.

---

## Configuration files

### Local storage mode

| File | Used by | Hot-reloaded |
|------|---------|--------------|
| `/etc/sudo-logger/server.conf` | log server (systemd env) | No (restart required) |
| `/etc/sudo-logger/agent.conf` | agent (systemd env) | No |
| `/etc/sudo-logger/risk-rules.yaml` | replay server | On each request |
| `/etc/sudo-logger/siem.yaml` | replay server | Every 30 s |
| `/etc/sudo-logger/blocked-users.yaml` | log server, replay server | Every 30 s |
| `/etc/sudo-logger/ack-sign.key` | log server | No |
| `/etc/sudo-logger/ack-verify.key` | agent | No |
| `/etc/sudo-logger/server.crt/.key` | log server | No |
| `/etc/sudo-logger/client.crt/.key` | agent | No |
| `/etc/sudo-logger/ca.crt` | log server, agent | No |

### Distributed storage mode (Kubernetes)

File-based config for SIEM and blocked-users is replaced by PostgreSQL tables (`sudo_config`, `sudo_blocked_users`). TLS certificates are managed as Kubernetes Secrets and mounted into pods. Only the agent and plugin config files remain on disk.

---

## Log server health and metrics

When `-health-listen=:9877` is set, the log server starts a plain HTTP listener with:

| Path | Description |
|------|-------------|
| `GET /healthz` | Always returns `200 ok`. Use for K8s liveness/readiness probes instead of a TCP-socket check. |
| `GET /metrics` | Prometheus text format with `sudologger_sessions_active`, `sudologger_sessions_total`, `sudologger_sessions_incomplete_total`. |

## Graceful shutdown

Both the log server and the replay server handle `SIGTERM` / `SIGINT` gracefully:

- **Log server:** Closes the TLS accept loop so no new agent connections are accepted. Active sessions have up to 30 seconds to send `SESSION_END`. Sessions still open after the drain window are marked `INCOMPLETE`.
- **Replay server:** Calls `http.Server.Shutdown` with a 30-second timeout so in-flight HTTP requests complete before the process exits.

In Kubernetes set `terminationGracePeriodSeconds: 40` on the pod spec to give the 30-second drain window a 10-second buffer before the container is forcibly killed.

---

## Security properties

| Property | Mechanism |
|----------|-----------|
| Sudo blocked if server unreachable | Plugin waits for `SESSION_READY`; times out and returns -1 if agent is down |
| Session frozen on network loss | Agent calls `cgroup.freeze` within ~800 ms of last ACK/heartbeat |
| Network outage vs agent kill | SESSION_FREEZING sent at t≈800 ms; server marks session `network_outage` instead of generic `incomplete` |
| Freeze cannot be escaped by the user | `unshare(CLONE_NEWCGROUP)` in plugin at session start; subtree appears as root to all children |
| ACKs cannot be forged | ed25519 signature over `sessionID‖seq‖ts_ns`; private key stays on log server |
| ACKs cannot be replayed across sessions | Session ID is included in every signed message |
| Host identity verified | Log server checks that claimed `host` in SESSION_START matches the TLS client certificate CN/SAN |
| Plugin socket access restricted | Agent verifies `SO_PEERCRED`; only root (sudo) can connect |
| Block policy enforced centrally | Policy check happens at the log server during startup handshake, before sudo forks the child |
| SIEM cert upload blocked in K8s | `/api/siem-cert` returns 501 in distributed mode; use Kubernetes Secrets instead |
| Single SIEM forwarder in multi-replica | PostgreSQL advisory lock ensures exactly one replica forwards events |
