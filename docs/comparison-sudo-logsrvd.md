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
| Reject session if server unreachable at start | ✅ | ✅ |
| Restart / resume interrupted transfers | ✅ | ✅ (TCP retransmit) |
| Session replay | ✅ CLI (`sudoreplay`) | ✅ Web UI + CLI |
| RPM packages | ✅ (ships with sudo) | ✅ |
| Requires sudo 1.9+ | ✅ | ✅ |

---

## Where they differ

### 1. Network-loss enforcement

`sudo-logsrvd` has no freeze mechanism. If the server becomes unreachable mid-session, the client continues running and sudo buffers I/O locally. The session may never reach the server if the shipper is killed or if the node crashes.

`sudo-logger` freezes the running process within ~800 ms of losing server acknowledgements. The freeze is implemented via `cgroup.freeze=1` — not job-control signals — so it cannot be escaped with `fg`, `bg`, or `kill -CONT`. The user sees a freeze banner and can break out with Ctrl+C, but the session is then terminated. No unacknowledged I/O ever leaves the freeze window without being recorded.

### 2. Acknowledgement integrity

`sudo-logsrvd` has no per-chunk ACK mechanism. The server stores what it receives; there is no cryptographic proof that the client received a server-side write confirmation.

`sudo-logger` uses ed25519-signed ACKs per chunk. The signature binds the session ID, sequence number, and timestamp. A compromised shipper cannot forge ACKs for other sessions or other hosts, and a valid ACK from session A cannot be replayed to unfreeze session B.

### 3. Session format and tooling

`sudo-logsrvd` stores sessions in sudoreplay multi-file format (separate timing, ttyout, stdin files per session). Replay requires the `sudoreplay(8)` CLI.

`sudo-logger` stores sessions as asciinema v2 (`session.cast`). This is a single self-contained file with an embedded cast header containing all metadata. The replay-server provides a web UI with search, filtering, and risk scoring. The asciinema format is compatible with the broader ecosystem (asciinema.org player, asciinema CLI).

### 4. Risk scoring and SIEM

`sudo-logsrvd` has no built-in risk scoring or SIEM forwarding.

`sudo-logger` scores every session via configurable YAML rules (regex on command, path, arguments). Scores and reasons are stored alongside the session and shown in the replay UI. On session close, the replay server forwards a SIEM event via HTTPS, CEF, OCSF v1.3.0 (Class 3003), or syslog — with the risk score and a replay URL embedded in every event.

### 5. Secret redaction

`sudo-logsrvd` records all I/O verbatim.

`sudo-logger` masks AWS access keys, API tokens, Bearer headers, JWT tokens, URL passwords, and other secrets in the terminal stream before they reach the server. Custom regex patterns can be added per deployment.

### 6. Wayland screen capture

`sudo-logsrvd` records terminal I/O only.

`sudo-logger` additionally records GUI programs started under sudo on Wayland desktops by intercepting `wl_surface_commit` via a transparent compositor proxy — no compositor patches required. The replay UI shows an image slideshow for GUI sessions.

### 7. Host identity binding

`sudo-logsrvd` with `tls_checkpeer` verifies the client certificate is signed by the CA but does not bind the certificate identity to the session's claimed `host` field.

`sudo-logger` rejects `SESSION_START` if the `host` field does not match the CN or DNS SANs of the presenting client certificate. A compromised shipper on host A cannot forge log entries attributed to host B.

### 8. cgroup namespace isolation

`sudo-logsrvd` does no process isolation.

`sudo-logger` calls `unshare(CLONE_NEWCGROUP)` at session start so child processes see the session cgroup as their filesystem root for `/sys/fs/cgroup`. They cannot migrate to a parent cgroup to escape the freeze, even with `CAP_SYS_ADMIN`.

### 9. Distributed storage

`sudo-logsrvd` stores logs locally (relay mode can forward to another `sudo-logsrvd` instance).

`sudo-logger` supports S3-compatible object storage (AWS, MinIO, NetApp StorageGRID) for cast files and PostgreSQL for metadata, enabling horizontal scaling with multiple log-server replicas in Kubernetes.

### 10. Relay topology

`sudo-logsrvd` supports hierarchical relay chains (client → relay → relay → server). This allows sudo to log even when the central server is temporarily unreachable by queuing at an intermediate relay.

`sudo-logger` has no relay mode. The shipper connects directly to the server. Network recovery relies on TCP retransmission and the freeze mechanism. If the connection is lost, the session is frozen; if the TCP timeout expires, the session is terminated with a human-readable banner.

---

## Summary table

| | sudo-logsrvd | sudo-logger |
|--|:--:|:--:|
| **Freeze on network loss** | ✗ | ✅ cgroup.freeze |
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
