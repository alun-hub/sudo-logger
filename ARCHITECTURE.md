# Architecture

sudo-logger is a mandatory sudo session recording system. Every sudo invocation is intercepted, all terminal I/O is streamed to a central server, and the command is **frozen** if the server becomes unreachable — ensuring no sudo activity goes unlogged.

---

## Components

```
┌─────────────────────────────────────────────────────────────────┐
│  Client machine (each host)                                      │
│                                                                  │
│  ┌─────────────────┐   Unix socket    ┌───────────────────────┐  │
│  │  sudo + plugin  │ ──────────────► │  shipper daemon       │  │
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
| `go/cmd/shipper` | Go | Every client (systemd service) | Bridges plugin ↔ log server via TLS |
| `go/cmd/server` | Go | Central server | Receives sessions, writes .cast files, signs ACKs, enforces block policy |
| `go/cmd/replay-server` | Go | Central server | Browser GUI for playback, reporting, configuration |

---

## Session lifecycle

### 1. Startup (synchronous, blocks sudo)

```
plugin_open()
  │
  ├─ connect to shipper (Unix socket /run/sudo-logger/plugin.sock)
  ├─ send SESSION_START (JSON: user, host, command, pid, terminal size…)
  │
  │             shipper
  │               ├─ create session cgroup, move sudo PID into it
  │               ├─ connect to log server (TLS TCP :9876)
  │               ├─ forward SESSION_START to server
  │               │
  │               │             log server
  │               │               ├─ validate session (user/host names, TLS cert)
  │               │               ├─ check blocked-users policy
  │               │               │   ├─ blocked → send SESSION_DENIED, close
  │               │               │   └─ allowed → send SERVER_READY
  │               │               └─ open session directory + ACTIVE file
  │               │
  │               ├─ receive SERVER_READY or SESSION_DENIED from server
  │               │   ├─ SESSION_DENIED → forward to plugin, abort
  │               │   └─ SERVER_READY  → send SESSION_READY to plugin
  │
  └─ receive SESSION_READY → sudo forks child (inherits cgroup)
     (or SESSION_DENIED / SESSION_ERROR → sudo blocked, message shown)
```

sudo is blocked at the prompt until the shipper responds. If the log server is unreachable or denies the session, sudo never executes the command.

### 2. Recording (concurrent)

```
plugin (main thread)           shipper                    log server
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
  │                              │  (shipper sends HB/400ms) │
```

The plugin never waits for the server. It polls the shipper for the latest ACK timestamp via ACK_QUERY/ACK_RESPONSE — the shipper answers from its in-memory cache, making the round-trip sub-millisecond.

### 3. Freeze (network loss)

If the shipper stops receiving ACKs or heartbeat replies for ~800 ms, it calls `cgroup.freeze` on the session cgroup. This suspends all child processes at the kernel level — they cannot be unfrozen with `fg`, `kill -CONT`, or by escaping to another cgroup (see [Cgroup isolation](#cgroup-isolation) below). When the connection recovers, the shipper unfreezes and the session continues transparently.

### 4. Shutdown

```
plugin_close()
  ├─ send SESSION_END (final_seq, exit_code)
  │
  shipper
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
| `0x01` | `SESSION_START` | plugin→shipper→server | JSON (SessionStart) |
| `0x02` | `CHUNK` | plugin→shipper→server | seq(8)+ts_ns(8)+stream(1)+len(4)+data |
| `0x03` | `SESSION_END` | plugin→shipper→server | final_seq(8)+exit_code(4) |
| `0x04` | `ACK` | server→shipper | seq(8)+ts_ns(8)+sig(64) — ed25519 signed |
| `0x05` | `ACK_QUERY` | plugin→shipper | empty |
| `0x06` | `ACK_RESPONSE` | shipper→plugin | last_ts_ns(8)+last_seq(8) |
| `0x07` | `SESSION_READY` | shipper→plugin | empty — sudo may proceed |
| `0x08` | `SESSION_ERROR` | shipper→plugin | string — infrastructure failure, sudo blocked |
| `0x09` | `HEARTBEAT` | shipper→server | empty — sent every 400 ms |
| `0x0a` | `HEARTBEAT_ACK` | server→shipper | empty |
| `0x0b` | `SERVER_READY` | server→shipper | empty — session accepted |
| `0x0c` | `SESSION_DENIED` | server→shipper, shipper→plugin | string block message — policy denial |

CHUNK stream types: `0x00` stdin, `0x01` stdout, `0x02` stderr, `0x03` tty-in, `0x04` tty-out.

---

## ACK signing

The server signs every ACK with an **ed25519 private key** (`/etc/sudo-logger/ack-sign.key`). The shipper verifies signatures using the corresponding public key (`/etc/sudo-logger/ack-verify.key`). The signed message is:

```
sessionID || 0x00 || seq_be(8) || ts_ns_be(8)
```

The session ID in the signature prevents a valid ACK from one session being replayed to satisfy the freeze check of another. A compromised shipper cannot forge ACKs for sessions it does not own.

---

## Cgroup isolation

The shipper places each sudo session in a dedicated cgroup subtree under the shipper's delegated cgroup. This enables two things:

1. **Atomic freeze** — `echo 1 > cgroup.freeze` suspends every process in the subtree simultaneously, including GUI applications that re-parent to init.

2. **Escape prevention** — the plugin calls `unshare(CLONE_NEWCGROUP)` immediately after receiving `SESSION_READY`. All child processes see the session cgroup as the root of the cgroup hierarchy. Writing a PID to `/sys/fs/cgroup/../../escape/cgroup.procs` resolves only within the private subtree and fails — even with `CAP_SYS_ADMIN`.

For processes that escape to foreign cgroups before the namespace is established (e.g. GNOME or systemd moving a GUI process to an app scope), the shipper tracks them via `/proc/<pid>/cgroup` polling and sends `SIGSTOP`/`SIGCONT` as a fallback.

---

## Session storage

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

---

## Replay server

The replay server is a self-contained HTTP server that embeds a single-page application (vanilla JavaScript + vendored xterm.js). It reads session data directly from the log directory on disk — there is no API between the log server and the replay server.

### Session index

Sessions are discovered by scanning the two-level directory tree. The index is rebuilt at most once per 30 seconds and cached in memory. A file-system watcher (`fsnotify`) triggers an immediate rebuild when new session directories appear.

### Risk scoring

A YAML rules file (`/etc/sudo-logger/risk-rules.yaml`) defines scoring rules. Each rule can match on command name, terminal output content, run-as user, session duration, time of day, and whether the session ended cleanly. Scores accumulate across matching rules (capped at 100). Computed scores are cached in `risk.json` alongside the session and invalidated when the rules change.

### API endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/sessions` | Session list with filtering, sorting, pagination |
| `GET` | `/api/session/events` | Stream playback events for a session |
| `GET` | `/api/access-log` | Audit log of who viewed which sessions |
| `GET` | `/api/report` | Aggregate statistics and anomaly detection |
| `GET/PUT` | `/api/rules` | Risk scoring rules |
| `GET/PUT` | `/api/siem-config` | SIEM forwarding configuration |
| `POST` | `/api/siem-cert` | Upload TLS certificate for SIEM |
| `GET/PUT` | `/api/blocked-users` | Blocked users policy |
| `GET` | `/api/hosts` | Unique host names seen in session history |
| `GET` | `/metrics` | Prometheus metrics |

---

## Block policy

Security teams can block individual users from running sudo without touching sudoers files. The policy is stored in `/etc/sudo-logger/blocked-users.yaml` and shared between the log server (enforcement) and replay server (management UI).

```
security team (browser)
  └─ PUT /api/blocked-users
       └─ replay server writes blocked-users.yaml

log server (background goroutine)
  └─ reloads blocked-users.yaml every 30 s

next sudo attempt by blocked user
  └─ log server sends SESSION_DENIED during startup handshake
       └─ shipper forwards SESSION_DENIED to plugin
            └─ plugin shows red banner + configured message
                 └─ sudo exits without running the command
```

Blocking is per-user and optionally per-host. An empty host list means "all hosts". The block message is configurable from the GUI.

---

## Configuration files

| File | Used by | Hot-reloaded |
|------|---------|--------------|
| `/etc/sudo-logger/server.conf` | log server (systemd env) | No (restart required) |
| `/etc/sudo-logger/shipper.conf` | shipper (systemd env) | No |
| `/etc/sudo-logger/risk-rules.yaml` | replay server | On each request |
| `/etc/sudo-logger/siem.yaml` | replay server, log server | Every 30 s |
| `/etc/sudo-logger/blocked-users.yaml` | log server, replay server | Every 30 s |
| `/etc/sudo-logger/ack-sign.key` | log server | No |
| `/etc/sudo-logger/ack-verify.key` | shipper | No |
| `/etc/sudo-logger/server.crt/.key` | log server | No |
| `/etc/sudo-logger/client.crt/.key` | shipper | No |
| `/etc/sudo-logger/ca.crt` | log server, shipper | No |

---

## Security properties

| Property | Mechanism |
|----------|-----------|
| Sudo blocked if server unreachable | Plugin waits for `SESSION_READY`; times out and returns -1 if shipper is down |
| Session frozen on network loss | Shipper calls `cgroup.freeze` within ~800 ms of last ACK/heartbeat |
| Freeze cannot be escaped by the user | `unshare(CLONE_NEWCGROUP)` in plugin at session start; subtree appears as root to all children |
| ACKs cannot be forged | ed25519 signature over `sessionID‖seq‖ts_ns`; private key stays on log server |
| ACKs cannot be replayed across sessions | Session ID is included in every signed message |
| Host identity verified | Log server checks that claimed `host` in SESSION_START matches the TLS client certificate CN/SAN |
| Plugin socket access restricted | Shipper verifies `SO_PEERCRED`; only root (sudo) can connect |
| Block policy enforced centrally | Policy check happens at the log server during startup handshake, before sudo forks the child |
