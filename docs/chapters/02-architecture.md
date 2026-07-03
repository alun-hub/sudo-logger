# Architecture

## System overview

sudo-logger consists of three cooperating processes and a kernel-space C
plugin. The plugin runs inside sudo's address space on every monitored host.
The agent runs as a daemon on the same host. The log server and replay server
run centrally.

```
┌─────────────────────────────────────────────────────────────────────┐
│  Monitored Host                                                     │
│                                                                     │
│  ┌──────────────────┐  Unix socket            ┌──────────────────┐ │
│  │  sudo            │◄────────────────────────►│ sudo-logger-     │ │
│  │                  │  /run/sudo-logger/        │ agent (Go)       │ │
│  │  plugin.so (C)   │  plugin.sock             │                  │ │
│  │                  │                          │  Unix socket     │ │
│  │  log_ttyin       │                          │  server          │ │
│  │  log_ttyout      │                          │  eBPF recorder   │ │
│  │  log_stdin       │                          │  cgroup manager  │ │
│  │  log_stdout      │                          │  divergence det. │ │
│  │  log_stderr      │                          │  D-Bus monitor   │ │
│  └──────────────────┘                          │  sandbox (LSM)   │ │
│                                                └────────┬─────────┘ │
└─────────────────────────────────────────────────────────┼───────────┘
                                                          │ mTLS :9876
                                                          ▼
                                         ┌────────────────────────────┐
                                         │  sudo-logger-server (Go)  │
                                         │                            │
                                         │  TLS listener :9876        │
                                         │  ed25519 ACK signing       │
                                         │  JIT approval manager      │
                                         │  /healthz :9877            │
                                         └────────────┬───────────────┘
                                                      │
                         ┌────────────────────────────┼────────────────┐
                         │                            │                │
                  ┌──────▼──────┐         ┌───────────▼───┐  ┌────────▼─────┐
                  │ Local disk  │         │  PostgreSQL   │  │  MinIO / S3  │
                  │ /var/log/   │         │  (metadata,   │  │  (cast files)│
                  │ sudoreplay/ │         │   users, RBAC)│  └──────────────┘
                  └─────────────┘         └───────────────┘

                                         ┌────────────────────────────┐
                                         │  sudo-logger-replay (Go)  │ ◄── browser :8080
                                         │                            │
                                         │  HTTP + embedded React SPA │
                                         │  asciinema-player          │
                                         │  RBAC + OIDC / proxy auth  │
                                         └────────────────────────────┘
```

Data flows left to right: the plugin captures I/O on the monitored host,
the agent buffers and forwards frames to the server over mutual TLS, the
server stores them, and the replay server serves them back to auditors via
a browser.

---

## C plugin (plugin/plugin.c)

### How sudo loads the plugin

sudo reads `/etc/sudo.conf` at startup. A `Plugin` line names the shared
library and the exported symbol:

```
Plugin sudo_logger_plugin /usr/libexec/sudo/sudo_logger_plugin.so
```

sudo calls `dlopen()` on the `.so` file, resolves the `sudo_logger_plugin`
symbol (declared `__attribute__((visibility("default")))`), and calls the
`open` hook. The plugin declares `SUDO_API_VERSION` compatibility via the
`.version` field of the `io_plugin` struct from `sudo_plugin.h`.

### Plugin lifecycle

```
sudo starts
    │
    ├── plugin_open()
    │     connect to /run/sudo-logger/plugin.sock  (connect_to_agent)
    │     send SESSION_START (JSON)
    │     wait for SESSION_READY or SESSION_ERROR or SESSION_DENIED
    │     SESSION_ERROR  → return 0 (sudo blocked)
    │     SESSION_DENIED → print block message, return 0
    │     SESSION_READY  → start monitor thread, return 1
    │
    ├── [sudo executes command]
    │     log_ttyin(buf, len)  → ship_chunk(STREAM_TTYIN, buf, len)
    │     log_ttyout(buf, len) → ship_chunk(STREAM_TTYOUT, buf, len)
    │     log_stdin(buf, len)  → ship_chunk(STREAM_STDIN, buf, len)
    │     log_stdout(buf, len) → ship_chunk(STREAM_STDOUT, buf, len)
    │     log_stderr(buf, len) → ship_chunk(STREAM_STDERR, buf, len)
    │
    └── plugin_close(exit_status, error)
          atomic_store(&g_monitor_stop, 1)
          pthread_join(g_monitor_thread, NULL)   ← wait for thread exit
          send SESSION_END (final_seq + exit_code)
          close(g_agent_fd)
          close(g_tty_fd)
```

### Hook functions

| Function | When called | What it does | Data forwarded |
|---|---|---|---|
| `plugin_open` | Session start | Connects to agent, sends `SESSION_START`, starts monitor thread | JSON session metadata |
| `log_ttyin` | User keystroke | Calls `ship_chunk(STREAM_TTYIN, ...)` | Raw terminal input bytes |
| `log_ttyout` | Terminal output to PTY | Calls `ship_chunk(STREAM_TTYOUT, ...)` | Raw terminal output bytes |
| `log_stdin` | Non-tty stdin data | Calls `ship_chunk(STREAM_STDIN, ...)` | stdin bytes |
| `log_stdout` | Non-tty stdout data | Calls `ship_chunk(STREAM_STDOUT, ...)` | stdout bytes |
| `log_stderr` | Non-tty stderr data | Calls `ship_chunk(STREAM_STDERR, ...)` | stderr bytes |
| `plugin_close` | Session end | Stops monitor thread, sends `SESSION_END`, closes fds | Exit status + final sequence number |
| `show_version` | `sudo -V` | Prints "sudo-logger plugin v1.0" via `g_printf` | None |

### Unix socket connection

At `plugin_open()` the plugin calls `connect_to_agent()`, which creates an
`AF_UNIX`/`SOCK_STREAM` socket and connects to `AGENT_SOCK_PATH`
(`/run/sudo-logger/plugin.sock`).

After connecting it sends a `SESSION_START` frame whose payload is a JSON
object. Then it blocks in a `select()` loop (with `ACK_QUERY_TIMEOUT_MS`=100
ms timeout) waiting for either `SESSION_READY` (0x07), `SESSION_ERROR`
(0x08), or `SESSION_DENIED` (0x0c). If `SESSION_ERROR` arrives, `plugin_open`
returns 0, which causes sudo to abort the session before executing any
command. If `SESSION_DENIED` arrives, the block message is printed to the
user's terminal and sudo exits.

### CHUNK frame format

Every call to `ship_chunk` constructs and sends a `CHUNK` frame. The 5-byte
frame header (`send_msg`) is followed by the binary payload assembled in
`ship_chunk`:

```
Byte offset  Size  Field
──────────────────────────────────────────────────────────
0            1     Message type (0x02 = MsgChunk)
1            4     Payload length, big-endian uint32
── payload starts at offset 5 ─────────────────────────
5            8     Sequence number, uint64 big-endian  (g_seq, pre-incremented)
13           8     Timestamp nanoseconds, int64 big-endian (CLOCK_REALTIME via now_ns())
21           1     Stream identifier
22           4     Data length, uint32 big-endian
26           N     Raw terminal data bytes
```

Stream identifier values (must match `protocol.go` constants):

| Value | Constant | Meaning |
|---|---|---|
| 0 | `STREAM_STDIN` | Non-tty stdin |
| 1 | `STREAM_STDOUT` | Non-tty stdout |
| 2 | `STREAM_STDERR` | Non-tty stderr |
| 3 | `STREAM_TTYIN` | TTY input (keystrokes) |
| 4 | `STREAM_TTYOUT` | TTY output (terminal writes) |

### ACK monitor thread

`plugin_open` starts a POSIX thread (`pthread_create`) running
`monitor_thread_fn`. The thread loops with a 150 ms sleep between iterations
and calls `refresh_ack_cache()`. `refresh_ack_cache` sends `ACK_QUERY`
(0x05) — an empty-payload frame — to the agent, then reads back an
`ACK_RESPONSE` (0x06) containing the 8-byte last ACK timestamp and 8-byte
last sequence number.

The thread tracks `g_last_ack_time`. If the last ACK timestamp is more than
`ACK_TIMEOUT_SECS` (2 seconds) old, it writes a freeze banner to `g_tty_fd`
(the `/dev/tty` file descriptor opened separately at session start). When a
fresh ACK arrives again it writes an unfreeze banner. The banner strings are
ANSI sequences written directly to `/dev/tty` so they appear on the user's
terminal regardless of the command's stdout/stderr redirection.

If `send_msg` within `refresh_ack_cache` returns `EPIPE` or `ECONNRESET`, or
if the read returns EOF, the monitor thread sets `g_agent_dead = 1` and sends
`SIGTERM` to the sudo process group (`kill(-g_sudo_pgrp, SIGTERM)`) within
the next 150 ms poll interval. Subsequent `ship_chunk` calls check
`g_agent_dead` atomically and return immediately without attempting further
socket writes.

The actual process-level freeze is performed by the agent using cgroup v2
(described below). The plugin does not send any signals to freeze processes;
it only displays banners to inform the user.

### Mutex: g_send_mu

`g_send_mu` is a `PTHREAD_MUTEX_INITIALIZER`-initialised `pthread_mutex_t`
that serialises all writes to `g_agent_fd`. Two threads write to the socket
concurrently:

- The **main thread** from within `ship_chunk`, called by `log_ttyin`,
  `log_ttyout`, `log_stdin`, `log_stdout`, and `log_stderr` during normal
  I/O forwarding.
- The **monitor thread** from within `refresh_ack_cache`, which sends
  `ACK_QUERY` frames.

Without the mutex these concurrent `write_all` calls interleave and corrupt
the frame stream, causing "chunk data truncated" errors and agent freezes.
The mutex was introduced in commit `cba194f`.

---

## Agent (go/cmd/agent/)

### File-by-file overview

| File | Role |
|---|---|
| `main.go` | Entry point: parses flags, loads config, starts Unix socket server, eBPF recorder, D-Bus monitor, heartbeat loop |
| `plugin.go` | Unix socket server: one goroutine per plugin connection, session context management, frame proxy to server, inline `ACK_QUERY` handling |
| `ebpf.go` | eBPF ring buffer consumer, pkexec detection, cgroup tracking registration |
| `divergence.go` | Correlates eBPF execve events against plugin `SESSION_START` messages; fires `MsgDivergenceAlert` on mismatch |
| `cgroup.go` | Per-session cgroup v2 subtree management; freeze/unfreeze via `cgroup.freeze`; escaped-process tracking |
| `config.go` | Parses agent config YAML |
| `sandbox.go` | Loads and attaches the eBPF LSM program; registers/deregisters cgroups and PIDs in BPF maps |
| `sandbox_config.go` | Parses `sandbox.yaml`; resolves path → device+inode pair using `/proc/self/mountinfo` |
| `sandbox_watch.go` | inotify watcher on protected files; refreshes inode map when a file is atomically replaced |
| `sandbox_poll.go` | Fetches `sandbox.yaml` from the server via `MsgFetchConfig`/`MsgConfigData` |
| `redaction.go` | Applies output-redaction regex patterns to session streams before forwarding |
| `sudoers.go` | Polls/pushes sudoers snapshots (`MsgSudoersSnapshot`/`MsgSudoersError`/`MsgHeartbeatAgent`); validates with `visudo -c` |
| `tls.go` | mTLS client configuration helpers |
| `groups.go` | Local group membership resolution |
| `ebpf_session.go` | Session writer for eBPF-sourced sessions (`ebpf-tty`, `ebpf-pkexec`) |
| `bpf/recorder.c` | eBPF C source: three tracepoint hooks, three maps |
| `bpf/sandbox.bpf.c` | eBPF LSM C source: 18 LSM hooks + 2 tracepoints (`sched_process_fork`, `sched_process_exit`) — 20 hooks total |

### Unix socket server (plugin.go)

The agent calls `net.Listen("unix", "/run/sudo-logger/plugin.sock")` and
accepts connections in a loop. Each accepted connection is handed to a new
goroutine (`handlePluginConn`). That goroutine:

1. Reads the first frame and expects `MsgSessionStart` (0x01).
2. Unmarshals the JSON `SessionStart` payload: `session_id`, `user`, `host`,
   `command`, `ts` (Unix seconds), `pid` (sudo process PID used for cgroup
   setup), `rows`, `cols`, plus extended fields from plugin v1.7.0+
   (`resolved_command`, `runas_user`, `runas_uid`, `runas_gid`, `cwd`,
   `flags`, `tty_path`, `user_uid`, `user_gid`).
3. Creates a `cgroupSession` for the sudo PID, adding the process to the
   agent's cgroup subtree.
4. Forwards the `SESSION_START` frame to the persistent server connection.
5. Waits for `MsgServerReady` (0x0b) or `MsgSessionDenied` (0x0c) from the
   server.
6. On `MsgServerReady`: sends `MsgSessionReady` (0x07) to the plugin.
7. On `MsgSessionDenied`: relays the denial frame (with its payload) to the
   plugin.
8. Enters the main proxy loop: reads `MsgChunk` (0x02) and `MsgSessionEnd`
   (0x03) frames from the plugin and forwards them verbatim to the server.
   Handles `MsgAckQuery` (0x05) inline by calling `readAck()` and responding
   with `MsgAckResponse` (0x06) containing the cached last ACK state.

### Server connection

The agent maintains a single persistent mTLS connection to the log server,
reconnecting with exponential back-off on disconnect. All active plugin
sessions are multiplexed over this one connection — each session is
distinguished by its `session_id`. A dedicated reader goroutine dispatches
inbound frames (ACKs, `HEARTBEAT_ACK`, `MsgServerReady`, `MsgSessionDenied`,
`MsgFreezeTimeout`, `MsgConfigData`) to the correct session by looking up the
`session_id` in a map.

A heartbeat goroutine sends `MsgHeartbeat` (0x09) every 400 ms and calls
`markDead()` if no `MsgHeartbeatAck` (0x0a) arrives within 800 ms. Recovery
is automatic: when `markAlive()` is called on receipt of any server message,
`serverConnAlive` is set to true and `cg.unfreeze()` is called on all frozen
sessions.

The `readAck()` function returns:

1. `(0, lastSeq)` if `serverConnAlive == false` (connection declared dead).
2. `(0, lastSeq)` if unACKed chunks exist and the oldest unACKed chunk's age
   exceeds `ackLagLimit` (5 seconds).
3. `(time.Now(), lastSeq)` otherwise — server is alive and responding.

### eBPF recorder (ebpf.go + bpf/recorder.c)

`recorder.c` contains three tracepoint programs compiled with `bpf2go` into
Go bindings:

| # | Tracepoint | BPF function | Purpose |
|---|---|---|---|
| 1 | `tracepoint/syscalls/sys_enter_write` | `sl_io_event` | Captures PTY I/O from all processes in tracked cgroups |
| 2 | `tracepoint/syscalls/sys_enter_execve` | `exec_event` | Detects sudo and pkexec execution in any cgroup |
| 3 | `tracepoint/sched/sched_process_exit` | `exit_event` | Signals process exit for processes in tracked cgroups |

Three BPF maps:

| Map name | BPF type | Max entries | Key | Value | Purpose |
|---|---|---|---|---|---|
| `tracked_cgroups` | `BPF_MAP_TYPE_HASH` | 256 | cgroup inode (u64) | session ID (u8[64]) | Which cgroup subtrees are being recorded |
| `tracked_sudo_pids` | `BPF_MAP_TYPE_HASH` | 256 | PID (u32) | session ID (u8[64]) | Track individual sudo/pkexec PIDs for execve detection |
| `events` | `BPF_MAP_TYPE_RINGBUF` | 8 MB | — | event bytes | Shared ring buffer for all event types |

The `sl_io_event` hook fires on every `write(2)` syscall. It checks the file
descriptor's device major number against the PTY range
(`PTY_SLAVE_MAJOR_MIN`=136 to `PTY_SLAVE_MAJOR_MAX`=143) and looks up the
calling process's cgroup inode in `tracked_cgroups`. Only matching writes are
emitted to the ring buffer. The first byte of each ring buffer entry is always
an `event_type` discriminator so userspace can dispatch without additional
framing.

The `exec_event` hook fires on every `execve(2)` and matches the executable
name against `"sudo"` and `"pkexec"`. Sudo events are handed to the
`divergenceTracker`; pkexec events additionally create `"ebpf-pkexec"` source
sessions in the agent.

A dedicated consumer goroutine in `ebpf.go` reads events from the ring buffer
using `cilium/ebpf`'s `RingBuffer` API. I/O events are forwarded as CHUNK
frames on the matching session's server connection; exec events are handed to
the divergence detector.

The eBPF subsystem degrades gracefully: if `/sys/kernel/btf/vmlinux` is
absent (kernel BTF not available), the agent starts in plugin-only mode with
no eBPF recorder loaded.

### Divergence detection (divergence.go)

`divergenceTracker` correlates eBPF `exec_event` records with plugin
`SESSION_START` messages to detect cases where sudo ran but the plugin did
not log it.

```go
type divergenceTracker struct {
    mu       sync.Mutex
    hostname string
    pending  map[string][]*pendingSudoExec   // key = "user|host"
    alertFn  func(user, host, comm string, ts time.Time)
}

type pendingSudoExec struct {
    pid       uint32
    comm      string    // "sudo" or "pkexec"
    wallTime  time.Time
    timer     *time.Timer
    cancelled bool
}
```

When the eBPF `exec_event` for sudo or pkexec arrives, `trackExec` creates a
`pendingSudoExec` and starts a 30-second `time.Timer`. When a plugin
`SESSION_START` arrives, `confirmPlugin` cancels the matching pending entry
(matched by `user|shortHost` key). If the timer fires before cancellation,
`alertFn` is called, which sends `MsgDivergenceAlert` (0x10) to the server.
The server records a visible "no plugin" divergence session in the store.

The `DivergenceStatus` field on session records takes these values:

| Value | Meaning |
|---|---|
| `"confirmed"` | Both eBPF and plugin recorded the session |
| `"unwitnessed"` | Plugin session with no matching eBPF event (eBPF may not be loaded) |
| `"missing_plugin"` | eBPF saw sudo exec but no plugin `SESSION_START` arrived within 30 s |

### D-Bus/polkit monitoring

At startup the agent opens a `BecomeMonitor` connection to the system D-Bus
and watches for polkit `CheckAuthorization` calls. It uses serial number
correlation: the D-Bus monitor records the serial number and calling PID of
each method call. When the authorization response arrives on the same serial,
the agent maps the result back to the originating process and creates a
`"dbus-polkit"` source session in the store (no I/O, event-only record).

### pkexec tracking

When the eBPF `exec_event` hook detects a `pkexec` execution, the agent
creates an `"ebpf-pkexec"` source session. If the pkexec invocation runs a
background service without a TTY (`has_io=false`), the replay UI renders it
as an event card rather than a terminal player. The session's
`parent_session_id` field links it to the enclosing login session when one is
active.

### Cgroup management (cgroup.go)

At startup, `init()` in `cgroup.go` reads `/proc/self/cgroup` to locate the
agent's delegated cgroup v2 subtree under `/sys/fs/cgroup`. Session cgroup
directories are created as children of this subtree.

```go
type cgroupSession struct {
    path      string       // absolute path, e.g. /sys/fs/cgroup/.../sess-<id>
    sudoPid   int
    cgName    string       // session ID (validated: /^[a-zA-Z0-9._-]{1,255}$/)
    cgroupID  uint64       // cgroup v2 inode — used as key in tracked_cgroups BPF map

    mu          sync.Mutex
    frozen      bool
    readyToFork bool        // set true when SESSION_READY is sent to plugin

    serverW     *protocol.Writer   // for sending sandbox/divergence alerts

    escapedMu   sync.Mutex
    escaped     map[int]bool       // PIDs that escaped the session cgroup

    stopTrack   chan struct{}
    trackDone   chan struct{}
    removeOnce  sync.Once
}
```

`newCgroupSession` creates the cgroup directory and writes the sudo PID to
`cgroup.procs`. The cgroup inode is read back and registered in the BPF
`tracked_cgroups` map so the eBPF `sl_io_event` hook starts capturing that
cgroup's PTY writes.

**Freeze**: `cgroupSession.freeze()` writes `"1\n"` to
`<cgroup_path>/cgroup.freeze`. The kernel suspends all processes in the cgroup
atomically, including any children forked after the freeze call is issued.
This is superior to `SIGSTOP` because it covers all descendants without
racing against `fork(2)`.

For processes that have escaped the session cgroup (GNOME Shell or systemd
may move processes to `app-*.scope` units), `escaped` tracks their PIDs.
Shell-like processes (sharing the sudo process group or holding a TTY) are
reclaimed back into the session cgroup via `cgroup.procs`. Isolated GUI
application processes (own process group leader) receive `SIGSTOP` directly.

**Unfreeze**: `cgroupSession.unfreeze()` writes `"0\n"` to `cgroup.freeze`
and sends `SIGCONT` to any processes that received `SIGSTOP`. This is called
by `markAlive()` when a `HEARTBEAT_ACK` or `ACK` arrives after a dead period.

### Sandbox (sandbox.go + sandbox_config.go + sandbox_watch.go)

An optional eBPF LSM subsystem (`bpf/sandbox.bpf.c`) enforces kernel-level
restrictions on all processes running inside session cgroups. The LSM program
is loaded and attached by `sandbox.go` at agent startup.

The LSM source implements 18 LSM hooks plus 2 tracepoints (20 total):

- File access: `file_open`, `path_truncate`, `file_permission`
- Inode operations: `inode_create`, `inode_mkdir`, `inode_mknod`,
  `inode_symlink`, `inode_rename`, `inode_unlink`, `inode_setattr`
- Process control: `task_kill`, `ptrace_access_check`, `bprm_check_security`
- Capabilities: `capable`
- Networking: `socket_create`, `unix_stream_connect`
- Filesystem: `sb_mount`
- BPF: `bpf` (restricts BPF program loading from inside sandboxed sessions)

Plus two tracepoints: `sched_process_fork` (to propagate sandbox membership
to child processes) and `sched_process_exit` (cleanup).

Verify the hook count directly against the source with:
`grep -c 'SEC("lsm/\|SEC("tp_btf/' go/cmd/agent/bpf/sandbox.bpf.c`.

`sandbox_config.go` parses `sandbox.yaml` — a policy file listing protected
paths and allowed/blocked operation rules. Path resolution uses
`/proc/self/mountinfo` to derive the device number and inode for each path.
This is bind-mount-aware: two different paths pointing to the same underlying
inode (same device + inode pair) are treated as equivalent, preventing policy
bypasses via alternate mount points.

`sandbox_watch.go` registers inotify watches on each protected file. When a
file is atomically replaced — for example, vim's write-to-temp-then-rename
pattern — the inotify `IN_MOVED_TO` event fires and the agent re-resolves the
path to obtain the new inode, updating the BPF map so protection follows the
new inode.

---

## Log server (go/cmd/server/)

### main.go structure

The server runs two listeners concurrently:

1. **TLS listener on `:9876`**: accepts agent connections with mutual TLS
   (`tls.RequireAndVerifyClientCert`, minimum `tls.VersionTLS13`). One
   goroutine per agent connection handles the entire frame stream for that
   agent.
2. **Plain HTTP listener** on `--health-listen` (e.g. `:9877`): serves
   `/healthz`, Prometheus `/metrics`, and the JIT approval REST API. Intended
   for internal/cluster access only — no client certificates required.

Per-connection goroutine flow:

```
accept TLS connection
    │
    ├── (if --strict-cert-host)
    │     extract CN/SAN from validated client cert
    │     compare to SESSION_START host field; reject on mismatch
    │
    ├── read SESSION_START
    │     → ApprovalManager.Check()
    │         allow    → create SessionWriter, send MsgServerReady
    │         denied   → send MsgSessionDenied (reason string)
    │         pending  → send MsgSessionDenied (request ID for challenge flow)
    │
    ├── read MsgChunk frames
    │     → SessionWriter.WriteOutput / WriteInput / WriteResize
    │     → sign ACK: ed25519.Sign(key, seq_be || ts_ns_be) → send MsgAck
    │
    ├── read MsgSessionEnd
    │     → SessionWriter.MarkDone(exit_code)
    │
    └── read MsgHeartbeat → send MsgHeartbeatAck (immediate, unsigned)
```

### buildTLSConfig()

```go
func buildTLSConfig() (*tls.Config, error) {
    cert, _ := tls.LoadX509KeyPair(*flagCert, *flagKey)
    caPEM, _ := os.ReadFile(*flagCA)
    pool := x509.NewCertPool()
    pool.AppendCertsFromPEM(caPEM)
    return &tls.Config{
        Certificates: []tls.Certificate{cert},
        ClientCAs:    pool,
        ClientAuth:   tls.RequireAndVerifyClientCert,
        MinVersion:   tls.VersionTLS13,
    }, nil
}
```

The CA pool validates agent client certificates. The server's own certificate
(`--cert`/`--key`) is presented to agents for server-side verification.

### ACK signing

For each CHUNK frame received, the server computes an ed25519 signature over
the concatenation of the big-endian encoded sequence number and timestamp:

```
sign_input = seq_be (8 bytes) || ts_ns_be (8 bytes)
signature  = ed25519.Sign(signKey, sign_input)   // 64 bytes
```

The MsgAck payload is:

```
[8]   seq        uint64 big-endian
[8]   ts_ns      uint64 big-endian
[64]  signature  ed25519 signature
```

The signing key is loaded from the path given to `--signkey` as a
PEM-encoded PKCS8 ed25519 private key via `loadEd25519PrivKey`. This
allows offline forensic verification that ACKs were issued by the genuine
server and not spoofed.

### Approval manager (approval.go)

The `ApprovalManager` implements JIT (just-in-time) sudo approval. Policy is
loaded from a YAML file and reloaded every 30 seconds.

```go
type approvalPolicy struct {
    Enabled       bool          `yaml:"enabled"`
    DefaultWindow time.Duration `yaml:"default_window"`
    PendingTTL    time.Duration `yaml:"pending_ttl"`
    // webhook, exempt lists, matching rules...
}
```

Flow at `SESSION_START`:

1. `ApprovalManager.Check()` is called with the session metadata.
2. If approval is disabled or the user is on the exempt list:
   `ApprovalResultAllow`.
3. If an active approval window exists for `user@host`:
   `ApprovalResultAllow`.
4. If a justification string was provided in the session challenge:
   creates a pending approval request, fires a webhook, returns
   `ApprovalResultPending` — server sends `MsgSessionDenied` with the
   request ID embedded in the message.
5. If no justification provided: returns `ApprovalResultNeedReason` —
   server sends `MsgSessionDenied` asking the user to supply a reason
   (the plugin can surface this via `MsgSessionChallenge`).

REST API (mounted on the health listener):

| Method | Path | Action |
|---|---|---|
| `GET` | `/api/approvals` | List pending approval requests |
| `POST` | `/api/approvals/{id}/approve?window=` | Grant a time-limited window |
| `POST` | `/api/approvals/{id}/deny` | Deny (optional reason in request body) |

Every approve/deny decision is written to the audit log in the session store.

---

## Replay server (go/cmd/replay-server/)

### Role

HTTP server that embeds a pre-built React SPA. The Go binary uses
`//go:embed` to embed the `static/` directory at compile time. The React app
is built with Vite into `static/` before the Go binary is compiled. The
server reads sessions from the same storage backend as the log server.

### Session player

The frontend uses `asciinema-player` (npm package `asciinema-player@^3.15.1`)
as the terminal replay component, implemented as `TerminalPlayer.tsx`. Cast
files are served by the Go backend at `GET /api/session/cast?tsid=<tsid>` and
streamed directly to the player. Player options include `autoPlay`, `speed`
(default 1x), `idleTimeLimit` (2 seconds), configurable `theme`, and
`fit: "both"` to fill the container dimensions.

### RBAC (rbac.go)

The replay server uses a two-tier permission model. The `Role` type is a
string alias (`type Role = string`). Two built-in roles exist:

- `"admin"` — receives all permissions unconditionally (built by iterating
  `store.AllPermissions` in `builtinAdminPerms`).
- `"viewer"` — seeded with `PermSessionsListOwn` and `PermSessionsReplayOwn`
  on first start via `defaultViewerPerms`.

Custom roles can be defined in `roles.yaml` (LocalStore) or PostgreSQL
(DistributedStore) with any subset of the 12 permissions.

The 12 defined permissions (constants in `go/internal/store/store.go`):

| Constant | String value | Grants |
|---|---|---|
| `PermSessionsListOwn` | `"sessions:list_own"` | List sessions belonging to the authenticated user |
| `PermSessionsListAll` | `"sessions:list_all"` | List all sessions |
| `PermSessionsReplayOwn` | `"sessions:replay_own"` | Replay own sessions |
| `PermSessionsReplayAll` | `"sessions:replay_all"` | Replay all sessions |
| `PermSessionsDelete` | `"sessions:delete"` | Delete sessions (GDPR) |
| `PermUsersRead` | `"users:read"` | Read user accounts |
| `PermUsersWrite` | `"users:write"` | Create, modify, or delete users |
| `PermAuditLogRead` | `"audit_log:read"` | Read the access and audit log |
| `PermApprovalsRead` | `"approvals:read"` | View pending JIT approval requests |
| `PermApprovalsDecide` | `"approvals:decide"` | Approve or deny JIT requests |
| `PermConfigRead` | `"config:read"` | Read server configuration |
| `PermConfigWrite` | `"config:write"` | Modify server configuration |

User identity is resolved by `accessLogMiddleware`, which checks for:
- A local session cookie (form-based login with username/password).
- An `X-Remote-User` header injected by a reverse proxy (SSO/proxy auth).
- An OIDC `id_token` cookie (OpenID Connect authentication flow).

The resolved role and permission map are injected into the request context
(keys `ctxRole = 1`, `ctxPermissions = 2`). Handler functions retrieve them
with `roleFromContext(r)` and `permsFromContext(r)`, and gate access with
`can(r, PermXxx)` or `require(w, r, PermXxx)` (which writes a 403 on
failure).

---

## Wire protocol deep dive

### Frame format

Every message in both directions and across all three process boundaries uses
the same 5-byte frame header, implemented in `go/internal/protocol/protocol.go`
(`protocol.Writer.Write` / `protocol.Reader.ReadFrame`) and inline in
`plugin.c` (`send_msg` / `recv_msg`):

```
┌────────────┬──────────────────────────┬─────────────────────────────┐
│ type (1 B) │ payload_len (4 B, BE)    │ payload (payload_len bytes) │
└────────────┴──────────────────────────┴─────────────────────────────┘
```

All integer fields in payloads are big-endian unless noted.

### Message types

| Constant | Hex | Direction | Payload format |
|---|---|---|---|
| `MsgSessionStart` | `0x01` | plugin→agent→server | JSON `SessionStart` struct |
| `MsgChunk` | `0x02` | plugin→agent→server | Binary: seq(8)+ts_ns(8)+stream(1)+len(4)+data(N) |
| `MsgSessionEnd` | `0x03` | plugin→agent→server | Binary: final_seq(8)+exit_code(4) |
| `MsgAck` | `0x04` | server→agent | Binary: seq(8)+ts_ns(8)+sig(64) |
| `MsgAckQuery` | `0x05` | plugin→agent | Empty |
| `MsgAckResponse` | `0x06` | agent→plugin | Binary: last_ack_ts_ns(8)+last_seq(8) |
| `MsgSessionReady` | `0x07` | agent→plugin | Empty, or JSON `SessionReadyBody` (disclaimer, session_ttl, freeze_timeout_secs) when any of those are non-default — server connection OK |
| `MsgSessionError` | `0x08` | agent→plugin | UTF-8 error string — server connection failed |
| `MsgHeartbeat` | `0x09` | agent→server | Empty — keepalive probe |
| `MsgHeartbeatAck` | `0x0a` | server→agent | Empty — keepalive reply |
| `MsgServerReady` | `0x0b` | server→agent | JSON `ServerReadyBody` (session_ttl) — session accepted, proceed |
| `MsgSessionDenied` | `0x0c` | server→agent AND agent→plugin | UTF-8 block/reason message |
| `MsgFreezeTimeout` | `0x0d` | agent→plugin | Empty — agent signals the plugin that the server has been unreachable too long and the session will be terminated |
| `MsgSessionAbandon` | `0x0e` | agent→server (new connection) | UTF-8 session ID — freeze-timeout fired; abandons the session |
| `MsgSessionFreezing` | `0x0f` | agent→server (new connection) | UTF-8 session ID — confirms cgroup freeze was applied due to network loss |
| `MsgDivergenceAlert` | `0x10` | agent→server | JSON divergence metadata |
| `MsgSandboxAlert` | `0x11` | agent→server | JSON sandbox violation event |
| `MsgFetchConfig` | `0x12` | agent→server | UTF-8 config key (e.g. `"sandbox.yaml"`) |
| `MsgConfigData` | `0x13` | server→agent | UTF-8 YAML payload (empty = not found) |
| `MsgSessionChallenge` | `0x14` | server→agent→plugin | JSON `SessionChallenge` — justification required for JIT approval |
| `MsgSessionChallengeResponse` | `0x15` | plugin→agent→server | JSON `SessionChallengeResponse` — user-supplied justification |
| `MsgSessionExpired` | `0x16` | agent→plugin | Empty — JIT approval window expired mid-session |
| `MsgSessionWarning` | `0x17` | agent→plugin | UTF-8 seconds-left string — session will be terminated soon |
| `MsgSudoersSnapshot` | `0x18` | agent→server | JSON `SudoersSnapshot` — sudoers state snapshot |
| `MsgSudoersError` | `0x19` | agent→server | JSON `SudoersError` — failed to apply a pushed sudoers config |
| `MsgHeartbeatAgent` | `0x1a` | agent→server | UTF-8 hostname — periodic liveness signal (drives the Sudoers tab online/offline badge) |
| `MsgResize` | `0x1b` | plugin→agent→server | Binary: ts_ns(8BE)+cols(2BE)+rows(2BE) — terminal resize event |

> **Security note:** `MsgFetchConfig` is restricted to an allowlist enforced by
> the server (`agentFetchableConfigKey` in `go/cmd/server/handler.go`): only
> the literal keys `"sandbox.yaml"` and `"redaction_config"`, plus any key with
> the `"sudoers/"` prefix, are served. Any other key (e.g. `approval-policy.yaml`,
> `jit-policy`, `siem.yaml`) is refused and logged as a `SECURITY:` event —
> a compromised agent cannot pull server-side secrets or policy files it has
> no legitimate need for.

### Normal session sequence diagram

```
plugin                  agent                   server
  │                       │                       │
  │──SESSION_START────────►│──SESSION_START────────►│
  │                       │                       │ JIT policy check
  │                       │◄──────SERVER_READY─────│
  │◄──────SESSION_READY───│                       │
  │                       │                       │
  │──CHUNK(seq=1)─────────►│──CHUNK(seq=1)─────────►│
  │──CHUNK(seq=2)─────────►│──CHUNK(seq=2)─────────►│
  │                       │◄──────ACK(1,sig)───────│
  │                       │◄──────ACK(2,sig)───────│
  │                       │                       │
  │──ACK_QUERY────────────►│                       │  (plugin polls every 150 ms)
  │◄──ACK_RESPONSE(ts,seq)─│                       │  (ts=now → fresh ACK)
  │                       │                       │
  │──SESSION_END(seq,code)─►│──SESSION_END──────────►│
  │                       │                       │  SessionWriter.MarkDone
```

### Heartbeat sequence

```
agent ──HEARTBEAT (empty) ──────────────► server
agent ◄──HEARTBEAT_ACK (empty) ─────────  server   (immediate)
```

Sent by the agent heartbeat goroutine every 400 ms. If no `HEARTBEAT_ACK`
arrives within 800 ms, `markDead()` sets `serverConnAlive = false` and all
active sessions begin returning `ts=0` from `readAck()`.

### Freeze scenario sequence diagram

```
plugin              agent               server (offline)
  │                   │                      ✗
  │──CHUNK────────────►│──CHUNK ─────────────►✗ (write fails)
  │                   │                      │
  │                   │  [no HEARTBEAT_ACK within 800ms]
  │                   │  markDead()           │
  │                   │                      │
  │──ACK_QUERY────────►│                      │
  │◄──ACK_RESP(ts=0)───│                      │  (stale → ts=0)
  │                   │                      │
  │  write freeze      │                      │
  │  banner to         │                      │
  │  /dev/tty         │                      │
  │                   │  cg.freeze()          │
  │                   │  (write "1"→          │
  │                   │   cgroup.freeze)      │
  │                   │                      │
  │  [sudo + children suspended by kernel]   │
  │                   │                      │
  │                   │  [server comes back]  │
  │                   │──HEARTBEAT────────────►│
  │                   │◄──HEARTBEAT_ACK───────│
  │                   │  markAlive()          │
  │                   │  cg.unfreeze()        │
  │                   │                      │
  │──ACK_QUERY────────►│                      │
  │◄──ACK_RESP(ts=now)─│                      │  (fresh → real timestamp)
  │                   │                      │
  │  write resume      │                      │
  │  banner to         │                      │
  │  /dev/tty         │                      │
  │                   │                      │
  │  [sudo + children resumed by kernel]     │
```

---

## Storage backends

### SessionStore interface

`go/internal/store/store.go` defines two interfaces. `SessionWriter` handles
the write path for a single active session. `SessionStore` covers session
lifecycle, retrieval, policy, configuration, and user management.

**SessionWriter** (one instance per active session, created by `CreateSession`):

| Method | Description |
|---|---|
| `WriteOutput(data []byte, ts int64)` | Append terminal output event (`"o"`) |
| `WriteInput(data []byte, ts int64)` | Append terminal input event (`"i"`) |
| `WriteResize(cols, rows int, ts int64)` | Append terminal resize event (`"r"`) |
| `MarkActive()` | Mark session as actively recording |
| `MarkIncomplete()` | Mark session as truncated (no clean `SESSION_END` received) |
| `MarkDone(exitCode int32)` | Mark session as cleanly finished with exit code |
| `WriteExitCode(code int32)` | Write exit code field without marking done |
| `Flush()` | Flush write buffer to underlying storage |
| `Close()` | Flush and release all resources |
| `TSID() string` | Return the unique session storage identifier |

**SessionStore** (grouped by category):

*Session lifecycle:*
- `CreateSession(ctx, start SessionStart, tsid string) (SessionWriter, error)`
- `WatchSessions(ctx) (<-chan SessionInfo, error)`

*Data retrieval:*
- `ListSessions(ctx, filter) ([]SessionInfo, error)`
- `ReadEvents(ctx, tsid string) ([]RawEvent, error)`
- `OpenCast(ctx, tsid string) (io.ReadCloser, error)`

*Risk scoring:*
- `GetRiskCache(ctx, tsid string) (*RiskCache, error)`
- `SaveRiskCache(ctx, tsid string, cache RiskCache) error`

*Access control:*
- `IsBlocked(ctx, user string) (bool, error)`
- `GetBlockedPolicy(ctx) (*BlockedPolicy, error)`
- `SaveBlockedPolicy(ctx, p BlockedPolicy) error`
- `IsWhitelisted(ctx, user string) (bool, error)`
- `GetWhitelistPolicy(ctx) (*WhitelistPolicy, error)`
- `SaveWhitelistPolicy(ctx, p WhitelistPolicy) error`

*Configuration:*
- `GetConfig(ctx, key string) (string, error)`
- `SetConfig(ctx, key, value string) error`
- `GetAuthConfig(ctx) (*AuthConfig, error)`
- `SetAuthConfig(ctx, cfg AuthConfig) error`

*Users and roles:*
- `GetUser(ctx, username string) (*UserInfo, error)`
- `UpsertUser(ctx, u UserInfo) error`
- `ListUsers(ctx) ([]UserInfo, error)`
- `DeleteUser(ctx, username string) error`
- `GetRoles(ctx) ([]RoleDefinition, error)`
- `GetRole(ctx, name string) (*RoleDefinition, error)`
- `UpsertRole(ctx, r RoleDefinition) error`
- `DeleteRole(ctx, name string) error`

*Miscellaneous:*
- `RecordView(ctx, tsid, user string) error`
- `ListAccessLog(ctx, filter) ([]AccessLogEntry, error)`
- `UpdateDivergenceStatus(ctx, tsid, status string) error`
- `RecordSandboxViolation(ctx, tsid string, v SandboxViolation) error`
- `SaveSudoersSnapshot(ctx, r SudoersSnapshotRecord) error`
- `SaveHeartbeat(ctx, host string, ts time.Time) error`
- `DeleteSession(ctx, tsid string) error`

### LocalStore

`go/internal/store/local.go` stores everything on the local filesystem. Each
session occupies a directory under `--logdir` (default `/var/log/sudoreplay`),
named by TSID:

```
/var/log/sudoreplay/
└── <TSID>/
    ├── session.json    — session metadata (JSON)
    ├── session.cast    — asciicast v2 format (newline-delimited JSON)
    └── risk.json       — cached risk score
```

Policy and configuration files are read from YAML files in `/etc/sudo-logger/`:

| File | Purpose |
|---|---|
| `blocked-users.yaml` | Users whose sessions are blocked |
| `whitelisted-users.yaml` | Users that bypass JIT approval |
| `users.yaml` | User accounts and role assignments |
| `roles.yaml` | Custom role definitions |
| `auth.yaml` | Authentication configuration (OIDC, proxy headers) |

### DistributedStore

`go/internal/store/distributed.go` splits storage across two backends:

- **PostgreSQL** (`--db-url`): session metadata, users, roles, RBAC
  configuration, access log, approval records, config key/value store.
  Connected via `github.com/jackc/pgx/v5`.
- **S3 / MinIO** (`--s3-bucket`, `--s3-endpoint`): cast files (binary content
  of `session.cast`) uploaded after session completion. S3 access uses
  `github.com/aws/aws-sdk-go-v2`.

A local write buffer (`--buffer-dir`, default `/var/lib/sudo-logger/buffer`)
stages cast data on disk while a session is in progress. After `SESSION_END`,
the buffer file is uploaded to S3 and removed locally.

The distributed backend allows the log server and replay server to run as
separate horizontally scalable deployments that share the same PostgreSQL and
S3 backend. The `migrate-sessions` tool (`go/cmd/migrate-sessions/main.go`)
migrates existing LocalStore sessions to a DistributedStore.

### asciicast v2 format

`session.cast` is a newline-delimited JSON file in asciicast v2 format — the
native input format consumed by `asciinema-player`.

```
Line 1 — header:
{"version": 2, "width": 220, "height": 50, "timestamp": 1718000000,
 "title": "alice@host: /usr/bin/vim /etc/sudoers",
 "env": {"TERM": "xterm-256color"}}

Subsequent lines — events:
[<relative_time_float>, "<event_type>", "<data>"]
```

Event types used:

| Type string | Meaning | Source stream |
|---|---|---|
| `"o"` | Terminal output | `STREAM_TTYOUT` / `STREAM_STDOUT` |
| `"i"` | Terminal input | `STREAM_TTYIN` / `STREAM_STDIN` |
| `"r"` | Terminal resize | `WriteResize` call |

Relative time is a `float64` representing seconds since the header
`timestamp`. The `asciinema-player` reads this file via `GET
/api/session/cast?tsid=<tsid>` and drives playback, including idle-time
collapsing (`idleTimeLimit: 2`) and variable speed control.
