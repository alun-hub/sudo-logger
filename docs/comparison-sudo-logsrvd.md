# sudo-logger vs sudo-logsrvd

Both tools centralise sudo session recordings over TLS. Their design goals differ in one fundamental way: `sudo-logsrvd` is an optional audit aid, while `sudo-logger` is a mandatory enforcement control. Everything else follows from that.

---

## What they do the same

| Capability | sudo-logsrvd | sudo-logger |
|------------|:---:|:---:|
| Capture stdin / stdout / tty I/O | ✅ | ✅ |
| Centralise logs on a remote server | ✅ | ✅ |
| TLS transport | ✅ | ✅ |
| Mutual TLS (client certificate) | ✅ optional | ✅ mandatory |
| Reject session if server unreachable at start | ⚠️ requires `ignore_log_errors=false` | ✅ always |
| Restart / resume interrupted transfers | ✅ | ✅ (TCP retransmit) |
| Session replay | ✅ CLI (`sudoreplay`) | ✅ Web UI + CLI |
| RPM packages | ✅ (ships with sudo) | ✅ |
| Requires sudo 1.9+ | ✅ | ✅ |

---

## Where they differ

### 1. Network-loss enforcement

`sudo-logger` freezes the running process within ~800 ms of losing server acknowledgements, regardless of whether the session is active or idle. The freeze is implemented via `cgroup.freeze=1` — not job-control signals — so it cannot be escaped with `fg`, `bg`, or `kill -CONT`. The user sees a freeze banner and can break out with Ctrl+C, but the session is then terminated. No unacknowledged I/O can proceed during the freeze window.

### 2. Acknowledgement integrity

`sudo-logsrvd` has no per-chunk ACK mechanism. The server stores what it receives; there is no cryptographic proof that the client received a server-side write confirmation.

`sudo-logger` uses **ed25519-signed ACKs** per chunk. The signature binds the session ID, sequence number, and timestamp. This prevents "ACK injection" or replay attacks; an ACK captured from host A cannot be used to unfreeze a session on host B.

### 3. Session format and tooling

`sudo-logsrvd` stores sessions in sudoreplay multi-file format (separate timing, ttyout, stdin files per session). Replay requires the `sudoreplay(8)` CLI.

`sudo-logger` stores sessions as **asciinema v2** (`session.cast`). This is a single self-contained file with an embedded cast header containing all metadata. The replay-server provides a web UI with search, filtering, and risk scoring. The asciinema format is compatible with the broader ecosystem (asciinema.org player, asciinema CLI).

### 4. Risk scoring and SIEM

`sudo-logsrvd` has no built-in risk scoring or SIEM forwarding.

`sudo-logger` scores every session via configurable YAML rules (regex on command, path, arguments). Scores and reasons are stored alongside the session and shown in the replay UI. On session close, the replay server forwards a SIEM event via HTTPS, CEF, OCSF v1.3.0 (Class 3003), or syslog — with the risk score and a replay URL embedded in every event.

### 5. Secret redaction

`sudo-logsrvd` records all I/O verbatim.

`sudo-logger` implements **Surgical Redaction** in the local shipper. It uses a stateful redactor that detects interactive password prompts (e.g., `[sudo] password for ...`) and masks subsequent input until a newline. It also uses a high-performance "trigger regex" fast-path to identify and mask AWS access keys, API tokens, Bearer headers, JWT tokens, and IBAN/SWIFT numbers before they reach the network.

### 6. Wayland screen capture and Linger Mode

`sudo-logsrvd` records terminal I/O only.

`sudo-logger` additionally records GUI programs started under sudo on Wayland desktops by intercepting `wl_surface_commit` via a transparent compositor proxy. Uniquely, it features a **Linger Mode**: if the main `sudo` process exits but backgrounded GUI processes (e.g., `sudo gvim &`) are still running, the shipper continues to track and log their screen updates until the entire process group is empty.

### 7. Host identity binding

`sudo-logsrvd` with `tls_checkpeer` verifies the client certificate is signed by the CA but does not bind the certificate identity to the session's claimed `host` field.

`sudo-logger` provides optional **Strict Identity Binding** (`-strict-cert-host`). When enabled, the server rejects sessions if the claimed `host` field does not match the CN or DNS SANs of the presenting client certificate. This prevents a compromised host from spoofing logs as another host.

### 8. cgroup namespace isolation

`sudo-logsrvd` does no process isolation.

`sudo-logger` calls **`unshare(CLONE_NEWCGROUP)`** at session start. This creates a new cgroup namespace where the child process sees the session cgroup as its private `/sys/fs/cgroup` root. Even with `CAP_SYS_ADMIN`, a process cannot navigate to a parent directory to escape the freeze or move itself to another cgroup.

### 9. Distributed storage

`sudo-logsrvd` stores logs locally (relay mode can forward to another `sudo-logsrvd` instance).

`sudo-logger` supports **Distributed Storage** using S3-compatible object storage (AWS, MinIO, NetApp) and PostgreSQL. This enables a stateless log-server tier that scales horizontally in Kubernetes without requiring shared volumes (ReadWriteMany).

### 10. Relay topology

`sudo-logsrvd` supports hierarchical relay chains (client → relay → relay → server). This allows sudo to log even when the central server is temporarily unreachable by queuing at an intermediate relay.

`sudo-logger` has no relay mode. Network recovery relies on TCP retransmission, the freeze mechanism, and its ability to handle **asynchronous ACK coalescing** to prevent head-of-line blocking during high-volume bursts.


---

## Summary table

| | sudo-logsrvd | sudo-logger |
|--|:--:|:--:|
| **Terminate session on network loss** | ⚠️ not default (`ignore_log_errors=true`) | ✅ always |
| **Freeze (no I/O during detection window)** | ✗ | ✅ cgroup.freeze |
| **Guaranteed detection time** | ✗ write-failure-driven | ✅ ≤800 ms heartbeat |
| **cgroup namespace isolation** | ✗ | ✅ |
| **ed25519-signed per-chunk ACKs** | ✗ | ✅ |
| **Host field bound to TLS cert** | ✗ | ✅ |
| **Web replay UI** | ✗ | ✅ |
| **Risk scoring** | ✗ | ✅ |
| **SIEM forwarding** | ✗ | ✅ CEF / OCSF / syslog |
| **Secret redaction** | ✗ | ✅ |
| **Wayland screen capture** | ✗ | ✅ |
| **Distributed storage (S3 + PG)** | ✗ | ✅ |
| **SELinux policy (shipper)** | ✗ | ✅ |
| **Relay / hierarchical logging** | ✅ | ✗ |
| **Ships with sudo** | ✅ | ✗ |
| **sudoreplay CLI compatible** | ✅ | ✗ (asciinema v2) |

---

## Which to choose

**`sudo-logsrvd`** is the right choice if:
- You want zero additional components (it ships with sudo)
- You need relay support for air-gapped segments or unreliable WAN links
- You already have tooling built around `sudoreplay(8)` format
- Logging is best-effort and local buffering during outages is acceptable

**`sudo-logger`** is the right choice if:
- Audit completeness is mandatory — unacknowledged I/O must never proceed
- You need a web UI, risk scoring, or SIEM integration
- Secret redaction is required before data leaves the client
- You want cryptographic proof that every chunk was received and stored
- You run Kubernetes and need horizontal scaling without shared filesystems
- GUI session recording on Wayland is required
