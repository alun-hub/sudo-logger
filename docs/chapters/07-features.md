# Features in Detail

## Session recording

### What gets recorded

Every sudo session that passes through the plugin produces a complete terminal transcript. Recorded data:

| Data | How captured | Where stored |
|------|-------------|-------------|
| Terminal input (keystrokes) | `log_ttyin` hook → `CHUNK` frame, stream `3` | `session.cast` |
| Terminal output | `log_ttyout` hook → `CHUNK` frame, stream `4` | `session.cast` |
| Non-tty stdin | `log_stdin` hook → `CHUNK` frame, stream `0` | `session.cast` |
| Non-tty stdout | `log_stdout` hook → `CHUNK` frame, stream `1` | `session.cast` |
| Non-tty stderr | `log_stderr` hook → `CHUNK` frame, stream `2` | `session.cast` |
| Session metadata | `SESSION_START` JSON payload | `session.json` |
| Exit code | `SESSION_END` binary payload | `session.json` |

Session metadata captured in `SESSION_START`:

```json
{
  "session_id": "abc123",
  "user": "alice",
  "host": "web01.example.com",
  "command": "vim /etc/nginx/nginx.conf",
  "runas": "root",
  "ts": 1750000000,
  "pid": 12345,
  "rows": 48,
  "cols": 220
}
```

### asciicast v2 format

Session I/O is stored as an asciicast v2 file (`session.cast`). The format is:

**Line 1 — header (JSON):**

```json
{"version":2,"width":220,"height":48,"timestamp":1750000000,"env":{"TERM":"xterm-256color"},"title":"alice@web01: vim /etc/nginx/nginx.conf"}
```

**Subsequent lines — events:**

```json
[0.0, "o", "[?1049h[22;0;0t"]
[0.121, "o", "~\r\n~\r\n"]
[5.432, "i", "G"]
[5.450, "o", "[?25l"]
```

Each line is a tuple: `[seconds_since_start (float), type, data]`. Type `"o"` is output (ttyout), `"i"` is input (ttyin). Binary-safe: non-UTF-8 bytes are encoded as JSON unicode escapes by the `iolog` package (`go/internal/iolog/iolog.go`).

### asciinema-player integration

The replay UI uses `asciinema-player` (npm package) to play back cast files. The React component `TerminalPlayer.tsx` instantiates it as:

```typescript
AsciinemaPlayer.create(
  `/api/session/cast?tsid=${tsid}`,
  containerElement,
  {
    autoPlay: false,
    speed: 1,
    idleTimeLimit: 2,   // compress gaps > 2 s
    theme: 'asciinema',
    fit: 'both',
  }
)
```

Cast files are served verbatim at `GET /api/session/cast?tsid=`. Speed control (0.25×–16×) and scrubbing are handled by the player. Keyboard shortcuts: `Space` play/pause, `f` fullscreen.

### Integrity guarantees

- Every `CHUNK` carries a monotonically increasing sequence number (uint64)
- The log server ACKs chunks with an ed25519 signature over `(seq, ts_ns)` — the agent verifies each ACK against `VerifyKey` before releasing any cgroup freeze
- Sessions without a clean `SESSION_END` are marked `INCOMPLETE` (marker file on local storage, status flag in PostgreSQL)
- The agent sends `SIGTERM` to sudo within 150 ms if the plugin socket drops mid-session (prevents unrecorded tail activity)

---

## eBPF session tracking

### Why eBPF supplements the plugin

The sudo I/O plugin only captures sessions routed through the `sudo` binary with the plugin loaded. Three bypass paths exist:

1. **`pkexec`** — PolicyKit's execution tool, separate binary, does not load the sudo plugin
2. **Direct root login** — SSH as root, `su -`, console login as root — no sudo involved
3. **D-Bus privilege grants** — processes acquiring elevated privileges via polkit's D-Bus API

The agent loads eBPF programs at startup to cover these gaps.

### Tracepoint hooks (bpf/recorder.c)

Three `tracepoint` hooks are loaded via `bpf2go`:

| Hook | Tracepoint | Handler | Purpose |
|------|-----------|---------|---------|
| 1 | `syscalls/sys_enter_write` | `sl_io_event` | Capture TTY writes from processes in tracked cgroups |
| 2 | `syscalls/sys_enter_execve` | `exec_event` | Detect `pkexec` and `sudo` executions |
| 3 | `sched/sched_process_exit` | `exit_event` | Clean up tracking state on process exit |

**`sl_io_event`** checks whether the writing process is in the `tracked_cgroups` map. If yes, and if the target fd is a TTY, it copies up to 4096 bytes of data into the `events` ring buffer.

**`exec_event`** checks whether the executed binary basename is `pkexec`. If so, it records the PID in `tracked_sudo_pids` and emits an `ebpf-pkexec` event. This is how the agent detects pkexec sessions without a plugin.

**`exit_event`** removes the exiting PID from `tracked_sudo_pids` to prevent stale entries.

### eBPF maps

| Map name | Type | Max entries | Purpose |
|----------|------|-------------|---------|
| `tracked_cgroups` | `BPF_MAP_TYPE_HASH` | 256 | Maps cgroup v2 IDs to session IDs |
| `tracked_sudo_pids` | `BPF_MAP_TYPE_HASH` | 256 | Tracks PIDs of pkexec processes |
| `events` | `BPF_MAP_TYPE_RINGBUF` | 8 MB | Shared ring buffer: kernel → user space |

The agent's Go ring buffer consumer goroutine (`ebpf.go`) polls the `events` ring buffer and dispatches events to the appropriate session handler.

### D-Bus/polkit monitoring

The agent opens a D-Bus `BecomeMonitor` connection at startup. This is a passive, non-intrusive monitoring mode — the agent receives copies of all D-Bus messages without intercepting them.

What is monitored:
- `CheckAuthorization` calls to `org.freedesktop.PolicyKit1.Authority`
- Authorization result messages

**Serial correlation:** The agent matches D-Bus call serials to replies to determine which process requested which authorization. The polkit serial number in the call is stored and matched when the reply arrives.

Sessions created from polkit events:
- `source = "dbus-polkit"`
- Shown in UI with a "polkit" badge
- No terminal I/O (no cast file) — event-only records
- Scored by risk rules: `dbus_polkit` (score 25), `dbus_polkit_high_value` (score 40), `dbus_polkit_denied` (score 50)

### Divergence detection (divergence.go)

The `divergenceTracker` in `divergence.go` correlates eBPF events with plugin connections. A 30-second background timer checks for mismatches:

| `divergence_status` | Meaning | Likely cause |
|---------------------|---------|-------------|
| `"ok"` | Both eBPF and plugin data present | Normal operation |
| `"missing_plugin"` | eBPF saw a sudo exec, no plugin connected | Plugin not installed or failed to load |
| `"missing_ebpf"` | Plugin connected, no eBPF events | eBPF not loaded (kernel too old, BTF missing) |

The status is stored in session metadata and shown as a warning icon on affected session cards in the UI.

---

## Cgroup freeze mechanism

### Purpose

If the log server becomes unreachable mid-session, the agent cannot confirm that session data has been persisted. The freeze mechanism pauses the sudo process tree atomically until the connection is restored — ensuring no privileged command executes without a corresponding audit record.

### Implementation (cgroup.go)

At `SESSION_READY`, the agent calls `newCgroupSession()`:

1. Reads its own cgroup path from `/proc/self/cgroup` line `0::/<path>` to find the delegated subtree root (`cgroupBase`)
2. Creates a new cgroup subdirectory: `cgroupBase/<session-id>/`
3. Writes the sudo PID to `cgroup.procs` to move sudo into the new cgroup

```go
type cgroupSession struct {
    path     string   // /sys/fs/cgroup/<subtree>/<session-id>/
    sudoPid  int
    cgName   string
    cgroupID uint64   // inode of cgroup dir = bpf_get_current_cgroup_id()
    frozen   bool
    // ...
}
```

The `cgroupID` (inode number of the cgroup directory) is the same value returned by `bpf_get_current_cgroup_id()` in BPF programs — this links the Go-side cgroup management with the eBPF-side tracking.

**Freeze:** Agent writes `"1"` to `<cgroup-path>/cgroup.freeze`. The kernel suspends all processes in the cgroup atomically — including forked children that joined after the cgroup was created.

**Unfreeze:** Agent writes `"0"` to `<cgroup-path>/cgroup.freeze`.

**Why cgroup freeze instead of SIGSTOP:** SIGSTOP sent to the parent does not affect already-forked children. Cgroup freeze is atomic across the entire process tree.

### Freeze trigger and timeout

The agent monitors the last ACK timestamp from the server. If no ACK has been received within `FreezeTimeout` (configured in `agent.conf`, typical default 3 minutes), the agent:

1. Freezes the cgroup
2. Sends `FREEZE_TIMEOUT` (message `0x0d`) to the plugin
3. Plugin writes a freeze banner to `/dev/tty`: the user sees their terminal appear to hang

When the server reconnects and ACKs resume, the agent unfreezes immediately.

If the session remains frozen beyond `FreezeTimeout`, the agent sends `SIGTERM` to the sudo process. The session is marked `INCOMPLETE`.

### What the user sees

```
⚠ sudo-logger: session paused — log server unreachable
  Your session is frozen. Waiting for connection to be restored.
  Session will be terminated in 3m00s if connection is not restored.
```

When the server reconnects:

```
✓ sudo-logger: session resumed — log server reconnected
```

---

## Risk scoring

### Overview

Every completed session is scored 0–100 against the rules in `risk-rules.yaml`. Matching rules contribute their `score` values additively (capped at 100). The total determines the risk level badge shown in the UI.

| Level | Score | Badge color |
|-------|-------|-------------|
| Low | 0–24 | Green |
| Medium | 25–49 | Yellow |
| High | 50–74 | Orange |
| Critical | 75–100 | Red |

### Scoring pipeline

1. `SESSION_END` received — session is marked complete in storage
2. Replay server loads the session on next request
3. Risk engine checks `risk.json` (cached score): if `rules_hash` matches current rules file hash, use cached score
4. If cache miss or stale: evaluate all rules against session metadata + cast file terminal output
5. Write updated `risk.json` with score, matching rule IDs, and current rules file hash

`risk.json` structure:
```json
{
  "score": 65,
  "level": "high",
  "reasons": ["visudo", "sshd_config"],
  "rules_hash": "sha256:abc123..."
}
```

### Match logic

Within a single rule, all present conditions are AND-ed (all must match). `command` and `content` are OR-ed at the rule level: the rule fires if the command OR the content matches. Within `command` and `content`, `contains_any` and `also_any` are AND-ed.

`content` matching scans the full terminal output in the cast file (ttyout stream). This is powerful but expensive for large sessions — use `also_any` to narrow false positives.

### Cache invalidation

When `risk-rules.yaml` changes on disk, the stored `rules_hash` in `risk.json` no longer matches. On the next session access, the replay server discards the cache and re-scores. This means a rule change causes automatic retroactive re-scoring of all sessions.

---

## JIT Approval (Just-in-Time)

### Overview

JIT approval requires an authorized approver to explicitly permit a sudo session before it executes. The user's process is frozen (via the cgroup mechanism) from the moment they run `sudo` until an approver acts.

### Approval outcomes

The `ApprovalManager.Check()` method returns one of five outcomes:

| Result | Meaning | User sees |
|--------|---------|-----------|
| `ApprovalResultAllow` | Policy permits the session | Session proceeds normally |
| `ApprovalResultPending` | Approval request created | "Awaiting approval..." message; session frozen |
| `ApprovalResultNeedReason` | User must provide justification | Prompt for reason before approval request is sent |
| `ApprovalResultChallenge` | Challenge-response required | OPA policy challenge question presented |
| `ApprovalResultDeny` | Hard deny (OPA policy) | Error message; sudo exits non-zero immediately |

### End-to-end flow

```
user             plugin          agent           log server      approver
  │                │               │                  │               │
  │  sudo <cmd>    │               │                  │               │
  ├───────────────►│               │                  │               │
  │                │  SESSION_START│                  │               │
  │                ├──────────────►│   SESSION_START   │               │
  │                │               ├─────────────────►│               │
  │                │               │                  │ check policy  │
  │                │               │                  │ create request│
  │                │               │  SESSION_DENIED   │               │
  │                │               │◄─────────────────│               │
  │                │ SESSION_DENIED│                  │ webhook →─────►│
  │                │◄──────────────│                  │               │
  │ "Awaiting..."  │               │                  │               │
  │◄───────────────│               │                  │               │
  │ (frozen)       │               │                  │               │
  │                │               │                  │               │
  │                │               │                  │  Approve ─────►│
  │                │               │                  │◄──────────────│
  │                │               │                  │ create window │
  │                │               │  SESSION_READY    │               │
  │                │               │◄─────────────────│               │
  │                │  SESSION_READY│                  │               │
  │                │◄──────────────│                  │               │
  │ session runs   │               │                  │               │
  ├───────────────►│               │                  │               │
```

### Configuration requirements

On the log server:
- `--approval-policy /etc/sudo-logger/approval-policy.yaml` (JIT disabled if file absent)
- `--approval-token <secret>` (enables the approval REST API)
- `--health-listen :9877` (required for the approval API to be reachable)

On the replay server:
- `--logserver-admin http://logserver:9877`
- `--logserver-admin-token <same secret>`

### Webhook notification

When a pending approval is created, the log server fires a Mattermost-compatible webhook:

```json
{
  "channel": "sudo-approvals",
  "text": "@charlie requested sudo approval on db01.example.com\nCommand: `psql -U postgres production`\n[Approve](https://replay.example.com/approvals/req_abc123) | [Deny](https://replay.example.com/approvals/req_abc123)"
}
```

`webhook_secret` is used to compute an HMAC-SHA256 signature over the request body, sent as `X-Webhook-Signature`. The receiving system can verify authenticity with this secret.

### Exempt and whitelisted users

- **`exempt[]` in approval policy:** Users bypass approval for all hosts (or specific hosts if `hosts` is non-empty). Managed in `approval-policy.yaml`.
- **`whitelisted-users.yaml`:** Managed via UI (`PUT /api/whitelisted-users`). Also bypasses JIT approval. Reloaded every 30 seconds.

Difference: `exempt[]` is part of the approval policy (admin-managed YAML), while whitelisted users are managed by operators via the UI at runtime.

### Pending TTL

If no approver acts within `pending_ttl` (default: 24 hours), the pending request is automatically expired. The frozen session is terminated and the user sees a "request expired" message.

---

## RBAC (Role-Based Access Control)

### Permission model

Every API call and UI page checks the caller's permissions. There are 12 permissions:

| Permission | Value | What it allows |
|------------|-------|---------------|
| `PermSessionsListOwn` | `sessions:list_own` | List/search own sessions only |
| `PermSessionsListAll` | `sessions:list_all` | List/search all users' sessions |
| `PermSessionsReplayOwn` | `sessions:replay_own` | Replay own sessions |
| `PermSessionsReplayAll` | `sessions:replay_all` | Replay any session |
| `PermSessionsDelete` | `sessions:delete` | Delete sessions (GDPR) |
| `PermUsersRead` | `users:read` | List users, roles, group mappings |
| `PermUsersWrite` | `users:write` | Create/modify/delete users and roles |
| `PermAuditLogRead` | `audit_log:read` | Read access log |
| `PermApprovalsRead` | `approvals:read` | View pending JIT approvals |
| `PermApprovalsDecide` | `approvals:decide` | Approve or deny JIT requests |
| `PermConfigRead` | `config:read` | Read rules, SIEM, sandbox, auth config |
| `PermConfigWrite` | `config:write` | Modify all configuration |

### Built-in roles

**`admin`:** Holds all 12 permissions. Cannot be modified. Created via `--admin-users` flag at startup.

**`viewer`:** Holds `sessions:list_own` and `sessions:replay_own` by default. Can be modified by an admin.

### Custom roles

Any admin can create custom roles (`POST /api/roles`) with any subset of permissions they themselves hold. This prevents privilege escalation: you cannot grant a permission you do not have.

Example role for an on-call engineer:

```json
{
  "name": "on-call",
  "permissions": [
    "sessions:list_all",
    "sessions:replay_all",
    "approvals:read",
    "approvals:decide"
  ]
}
```

### Group-to-role mapping

For OIDC and proxy-header auth, user groups can be mapped to roles:

```json
[
  { "group": "ops-team", "role": "admin" },
  { "group": "dev-team", "role": "viewer" }
]
```

First matching mapping wins. Configured via `PUT /api/auth-mapping` or inside `PUT /api/auth-config`.

### Bootstrap mode

When no user accounts exist and auth source is `"local"`, the server enters bootstrap mode. In this mode, any request is allowed to create the first admin account without credentials. Bootstrap mode exits as soon as the first user is created.

### How permissions are checked

The `rbac.go` middleware (`accessLogMiddleware`) resolves the user identity from the request (cookie, Basic Auth header, or trusted proxy header), looks up the user's role in the store, and injects `(role, permissions)` into the request context. Handler functions call `require(w, r, PermXxx)` which reads from context and returns 403 if the permission is absent.

---

## SIEM Forwarding

### Overview

When a session ends, the replay server asynchronously forwards an event to the configured SIEM. This does not block session recording — failures are logged and retried according to the configured transport.

### Event fields

The `siem.Event` struct (populated from session metadata + risk scoring results):

| Field | JSON key | Description |
|-------|----------|-------------|
| `SessionID` | `session_id` | Unique session identifier |
| `TSID` | — | Not in JSON directly; used in replay URL |
| `User` | `user` | Requesting user |
| `Host` | `host` | Hostname of monitored host |
| `RunasUser` | `runas` | User the command ran as |
| `RunasUID` | `runas_uid` | UID of runas user |
| `RunasGID` | `runas_gid` | GID of runas user |
| `Cwd` | `cwd` | Working directory |
| `Command` | `command` | Full command with arguments |
| `ResolvedCommand` | `resolved_command` | Resolved binary path (if available) |
| `Flags` | `flags` | sudo flags: `login_shell`, `preserve_env`, `implied_shell` |
| `StartTime` | `start_time` | RFC 3339 UTC |
| `EndTime` | `end_time` | RFC 3339 UTC |
| `ExitCode` | `exit_code` | Process exit code |
| `Incomplete` | `incomplete` | `true` if session ended without `SESSION_END` |
| `RiskScore` | `risk_score` | 0–100 |
| `RiskReasons` | `risk_reasons` | Array of matching rule IDs |
| `ReplayURL` | `replay_url` | Link to session in replay UI (requires `replay_url_base`) |

### JSON format example

```json
{
  "session_id": "abc123def456",
  "user": "alice",
  "host": "web01.example.com",
  "runas": "root",
  "runas_uid": 0,
  "runas_gid": 0,
  "command": "vim /etc/nginx/nginx.conf",
  "cwd": "/home/alice",
  "start_time": "2026-06-15T14:30:22Z",
  "end_time": "2026-06-15T14:35:11Z",
  "duration_s": 289,
  "exit_code": 0,
  "incomplete": false,
  "risk_score": 20,
  "risk_reasons": ["sshd_config"],
  "replay_url": "https://replay.example.com/?tsid=alice%2Fweb01_20260615-143022"
}
```

### CEF format

```
CEF:0|sudo-logger|sudo-logger|1.0|sudo_session|sudo session|3|rt=1750000000000 shost=web01.example.com suser=alice duser=root duid=0 dgid=0 dproc=vim /etc/nginx/nginx.conf cs1=abc123def456 cs1Label=sessionId cs2=/home/alice cs2Label=cwd cn1=0 cn1Label=exitCode cn2=289 cn2Label=durationSec
```

CEF severity mapping: `incomplete=true` → 6 (Medium-High); `exit_code≠0` → 5 (Medium); otherwise → 3 (Low).

CEF extension fields use standard ArcSight keys: `rt` (receive time ms), `shost` (source host), `suser` (source user), `duser` (destination/runas user), `dproc` (command), plus custom `cs`/`cn` labels for session ID, cwd, exit code, and duration.

### OCSF format

Events are mapped to OCSF class `Process Activity` (class UID 1007) with activity `Execute` (activity ID 1). Key field mappings follow the OCSF schema; the replay URL is included in `unmapped.replay_url`.

### Transport modes

**`https`**: HTTP POST to the configured URL. Optional `token` sent as `Authorization: Bearer <token>` (or `Splunk <token>` for Splunk HEC endpoints). Full TLS support including client certificates.

**`syslog`**: RFC 5424 syslog. Supports UDP, TCP, or TCP-TLS. The formatted event (JSON, CEF, or OCSF) is the syslog message body.

**`stdout`**: Prints to replay-server stdout. For debugging only — do not use in production.

### Live reload

`siem.yaml` is polled every 30 seconds. Configuration changes (including enabling/disabling SIEM forwarding) take effect without a server restart. Certificates uploaded via `POST /api/siem-cert` are written to disk alongside `siem.yaml` and referenced in the TLS config.

---

## eBPF Sandbox (LSM)

### Overview

The agent loads an eBPF LSM (Linux Security Module) program (`sandbox.bpf.c`) that runs inside the kernel and enforces restrictions on processes inside a sudo session's cgroup. Unlike seccomp, the sandbox operates at the LSM hook level (after syscall argument validation) and is keyed to the session's cgroup — not to the process image.

### Requirements

- Kernel ≥ 5.7 with `CONFIG_BPF_LSM=y` and `lsm=bpf` in kernel boot parameters
- Agent capability: `CAP_BPF` and `CAP_PERFMON`
- `SandboxConfig = /path/to/sandbox.yaml` in `agent.conf` (sandbox is disabled when this key is absent)
- `Ebpf = true` in `agent.conf` (default)

### LSM hooks

The `sandbox.bpf.c` program attaches 16 LSM hooks:

| Hook | What it blocks |
|------|---------------|
| `lsm/file_open` | Opening protected inodes for writing (`O_WRONLY`/`O_RDWR`) |
| `lsm/file_permission` | Write/append access to protected inodes |
| `lsm/path_truncate` | Truncation of protected paths (`truncate()` + `open O_TRUNC`) |
| `lsm/inode_setattr` | Attribute changes (`chmod`, `chown`, `truncate`) on protected inodes |
| `lsm/inode_unlink` | Deletion of protected inodes |
| `lsm/inode_rename` | Renaming of or onto protected inodes (prevents atomic replacement attacks) |
| `lsm/inode_mkdir` | Creating directories inside protected directories |
| `lsm/inode_create` | Creating files inside protected directories |
| `lsm/inode_mknod` | Creating device nodes inside protected directories |
| `lsm/inode_symlink` | Creating symlinks inside protected directories |
| `lsm/task_kill` | Sending signals to processes with protected names |
| `lsm/socket_create` | Creating `AF_NETLINK` sockets (route/firewall/audit tampering) |
| `lsm/ptrace_access_check` | Ptrace of processes outside the sandbox cgroup |
| `lsm/sb_mount` | Mounting over protected inodes (bind-mount bypass) |
| `lsm/capable` | Capability use: `CAP_AUDIT_CONTROL`, `CAP_NET_ADMIN`, `CAP_SYS_MODULE`, `CAP_MAC_ADMIN`, `CAP_SYS_RAWIO`, `CAP_SYS_BOOT` |
| `lsm/bprm_check_security` | Executing forbidden binaries or binaries from noexec directories |

Additionally, `sched_process_fork` and `sched_process_exit` tracepoints track child processes entering and leaving the sandboxed cgroup.

### eBPF maps (sandbox)

The sandbox uses separate maps from the recorder:

| Map | Purpose |
|-----|---------|
| `sandboxed_cgroups` | Set of cgroup IDs currently under sandbox enforcement |
| `sandboxed_pids` | PID-level tracking for processes that forked before cgroup assignment |
| `protected_inodes` | Device+inode pairs of files in `protect.files[]` |
| `forbidden_binaries` | Basenames of forbidden executables (`protect.forbidden[]`) |
| `noexec_inodes` | Inodes of directories where execution is denied (`protect.noexec[]`) |
| `protected_procs` | Process name strings in `protect.processes[]` |
| `systemd_ipc_inodes` | Inodes for systemd/dbus sockets (used by `deny_systemd_ipc`) |
| `sandbox_config` | Feature flag bitmask (single-element array) |
| `sandbox_alerts` | Ring buffer for sandbox violation events → user space |

### Inode-based protection

Protection is keyed on device+inode pairs, not paths. `sandbox_config.go` resolves paths using `/proc/self/mountinfo` to correctly handle bind mounts: a file bind-mounted to two different paths under different devices gets both inodes tracked.

This means:
- Renaming a protected file does not unprotect it (inode unchanged)
- Moving a new file into the same path as a protected file does not automatically protect the new file (different inode)

### Atomic file replacement (sandbox_watch.go)

Many text editors (vim, nano, emacs) write to a temporary file and then `rename()` it over the target. Without special handling, this would replace a protected inode with an unprotected one.

`sandbox_watch.go` sets an `inotify` watch on the parent directories of all protected files. When an `IN_MOVED_TO` or `IN_CREATE` event fires for a protected filename, `sandbox_config.go` re-resolves the inode and updates the `protected_inodes` eBPF map. Protection is continuously maintained even through atomic replacement.

### Violation alerts

When the sandbox blocks an operation, it writes to the `sandbox_alerts` ring buffer. The agent reads these events and:
1. Logs the violation to the session record (`RecordSandboxViolation`)
2. Sends a risk event back to the log server (if `serverW` is configured)
3. Increments the session's risk score contribution

---

## GDPR / Session deletion

### What is deleted

| Storage | What gets removed |
|---------|------------------|
| Local (`--storage=local`) | Entire session directory: `session.cast`, `session.json`, `risk.json`, `ACTIVE`/`INCOMPLETE` markers |
| Distributed (`--storage=distributed`) | PostgreSQL session row + all MinIO/S3 objects for the session |
| Access log | Access log entries referencing the deleted session are also removed |

The `DeleteSession(ctx, tsid, reason, deletedBy)` store method is the single authoritative deletion path, used by both the replay-server API and the log-server API.

### How to delete

**Via replay UI:** Sessions tab → session menu → Delete (requires `sessions:delete` permission).

**Via replay server API:** `DELETE /api/sessions/{tsid}` (admin auth).

**Via log server API:** `DELETE /api/sessions/{tsid}` (Bearer token).

### Audit trail

The deletion itself is recorded in the config/audit log with: `actor`, `action = "delete_session"`, `tsid`, `reason`, `deleted_by`, `timestamp`. This audit entry is stored separately from the session and is not deleted.

---

## Config change audit log

### What is logged

Every write operation on a configuration endpoint is recorded:

| Action | Trigger |
|--------|---------|
| `update_rules` | `PUT /api/rules` |
| `update_siem_config` | `PUT /api/siem-config` |
| `update_sandbox` | `PUT /api/sandbox` |
| `update_approval_config` | `PUT /api/approval-config` |
| `update_jit_policy` | `PUT /api/jit-policy` |
| `update_auth_config` | `PUT /api/auth-config` |
| `upsert_user` | `PUT /api/users` |
| `delete_user` | `DELETE /api/users/{id}` |
| `upsert_role` | `POST/PUT /api/roles` |
| `delete_role` | `DELETE /api/roles/{id}` |
| `delete_session` | `DELETE /api/sessions/{tsid}` |
| `update_blocked_users` | `PUT /api/blocked-users` |
| `update_whitelisted_users` | `PUT /api/whitelisted-users` |

### Format and access

Audit entries are stored alongside sessions in the store (`RecordView` for session views; config changes via the store's config audit methods). Access via:

- **UI:** Settings → Audit Log tab (if available, check current UI)
- **API:** `GET /api/access-log` (requires `audit_log:read`)

Each entry: `{ time, viewer/actor, action, tsid/resource, detail }`.

---

## Sudoers snapshots

### Overview

The replay server can store periodic snapshots of `/etc/sudoers` (and sudoers include files) per host. This provides an audit trail of privilege grants: who had what sudo privileges at which point in time.

### How agents deliver snapshots

The agent periodically reads `/etc/sudoers` and its includes, hashes the content, and sends the snapshot to the log server via the session stream protocol if the hash has changed since the last snapshot. Snapshots are stored in the session store per host+timestamp.

### Viewing snapshots

**Via API:**

```
GET /api/sudoers/hosts                        → list of hosts
GET /api/sudoers/snapshots?host=web01         → list of timestamped snapshots
GET /api/sudoers/config?host=web01&timestamp= → raw sudoers content
```

**Via UI:** Admin → Sudoers section (where available in the current navigation).

---

## Redaction (output masking)

### Agent-side redaction (MaskPatterns)

`MaskPatterns` in `agent.conf` is a list of Go regular expressions applied to the raw terminal output byte stream **in the agent before data reaches the log server**. Matching regions are replaced with `[REDACTED]`.

```ini
# agent.conf
MaskPatterns = [Pp]assword\s*[:=]\s*\S+
MaskPatterns = AWS_SECRET_ACCESS_KEY=[A-Za-z0-9+/=]+
MaskPatterns = -----BEGIN [A-Z]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z]+ PRIVATE KEY-----
```

Because redaction happens in the agent, the log server and replay server never receive or store the sensitive bytes.

### Server-side redaction config

`PUT /api/redaction-config` stores an additional set of patterns on the server side. These patterns are applied when cast files are served via `GET /api/session/cast` — they filter the output stream at read time without modifying the stored cast file. This allows redaction rules to be added retroactively without re-recording sessions.

### Best practices

- Use `MaskPatterns` (agent-side) for secrets with consistent formats — the sensitive bytes never leave the host
- Use `/api/redaction-config` (server-side) for retroactive redaction of already-recorded sessions
- Test patterns with `echo 'sample output' | grep -oP '<your-pattern>'` before deploying
- Overly broad patterns (e.g., matching single common words) can corrupt legitimate output — test on a sample of real session casts first
- Patterns are Go `regexp/syntax` — use `\b` for word boundaries and anchors to reduce false positives
