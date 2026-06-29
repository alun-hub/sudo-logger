# Reddit launch posts — drafts

Post to one subreddit per day. Don't submit to all on the same day.
Be transparent that you built it, answer comments promptly.

---

## r/sysadmin

**Title:** We built mandatory sudo session logging: if the log server is unreachable, sudo freezes. Looking for feedback from sysadmins.

**Body:**

Hey r/sysadmin,

We've been running sudo-logger in production and decided to open source it.
The short version: it's like sudo_logsrvd, but with one key difference —
logging is *enforced*, not optional.

If the central log server is unreachable when you run sudo, the command is
blocked. If the connection drops mid-session, your terminal freezes within
~800 ms. You can exit with Ctrl+C, but you can't keep working. The freeze
is implemented via Linux cgroups (not SIGSTOP, which can be countered).

**Why this matters in practice:** most "we log sudo" setups rely on
`sudo_logsrvd` with default settings. `ignore_log_errors=true` is the
default — network blips, a stopped daemon, or a tampered sudo.conf silently
disables logging. An attacker who already has sudo can disable their own
audit trail.

**Features:**
- Web replay UI with search and risk scoring
- Secret redaction (masks passwords, API keys) before anything leaves the host
- SIEM forwarding (CEF, OCSF, syslog, HTTPS JSON)
- eBPF divergence detection (flags if sudo ran without the plugin)
- JIT sudo approval with Mattermost/Slack notifications
- RPM packages for Fedora/RHEL with SELinux policy
- Kubernetes deployment with S3 + PostgreSQL for horizontal scaling

**Demo:** https://sudo-logger.unixkonsult.se
**Repo:** https://github.com/alun-hub/sudo-logger

Honest limitations: Linux-only, best on Fedora/RHEL. The enforcement model
means you need a reliable log server — if it's down for > 3 min, sessions are
terminated. Not suitable if you need local buffering during extended outages.

Happy to answer any questions about the design or deployment.

---

## r/netsec

**Title:** sudo-logger: mandatory sudo session auditing with ed25519-signed per-chunk ACKs and cgroup.freeze enforcement

**Body:**

Project: https://github.com/alun-hub/sudo-logger

I built this to close a gap I kept seeing in compliance audits: "sudo sessions
are logged" usually means "sudo sessions are logged when the logging service
is available and hasn't been tampered with." Neither PCI-DSS nor ISO 27001
specify what should happen when logging fails.

**The enforcement model:**

1. The sudo C plugin connects to a local agent daemon at session start. If the
   agent can't reach the central log server, sudo is blocked — the command
   never runs.

2. During a session, every I/O chunk gets an ed25519-signed acknowledgement
   from the server. The signature covers `sessionID || seqno || timestamp_ns`,
   so a captured ACK from session A cannot be replayed to unfreeze session B.

3. If ACKs stop arriving (heartbeat misses × 2 = ~800 ms), the agent calls
   `cgroup.freeze=1`. We also `unshare(CLONE_NEWCGROUP)` at session start —
   child processes see the session cgroup as their cgroup root and cannot
   migrate to a parent cgroup even with CAP_SYS_ADMIN.

4. An eBPF subsystem monitors all `sudo` and `pkexec` execve events. If sudo
   runs but the plugin doesn't fire (tampered sudo.conf), the agent alerts
   centrally — "⚠ no plugin" in the replay UI.

**What it doesn't do:** real-time I/O analysis — it records faithfully and
forwards to your SIEM. The SIEM does the detection.

Live demo: https://sudo-logger.unixkonsult.se

---

## r/linux

**Title:** sudo-logger: using the sudo I/O plugin API + cgroup freezing to make audit logging mandatory

**Body:**

I've been building a tool that hooks into sudo's I/O plugin API (the same API
sudo_logsrvd uses) to enforce mandatory session recording.

The interesting bit is the freeze mechanism. Instead of just logging, we use
`cgroup.freeze=1` to freeze the child process if the log server stops
acknowledging chunks. We also call `unshare(CLONE_NEWCGROUP)` so the child
can't escape to a parent cgroup.

The agent also loads eBPF tracepoints (sys_enter_write, sys_enter_execve,
sched_process_exit) to:
- Capture I/O from TTY login sessions (SSH, screen, tmux) without requiring
  the user to run sudo — the recording starts at login
- Detect divergence: if sudo runs but the plugin doesn't fire, an alert fires
- Optional eBPF LSM sandbox: deny-list of files/processes the sudo session
  can't touch, even as root (18 hooks)

The eBPF parts require Linux 5.8+ with BTF. The plugin and basic recording
work on older kernels.

Repo: https://github.com/alun-hub/sudo-logger
Demo: https://sudo-logger.unixkonsult.se

---

## r/devops

**Title:** Open source sudo session recording with Kubernetes support: S3 + PostgreSQL backend, SIEM forwarding, web replay UI

**Body:**

We've open sourced sudo-logger — mandatory sudo session recording with a web
replay interface.

**The Kubernetes story:**

The log server supports a distributed storage backend: cast files go to S3
(or MinIO / NetApp StorageGRID), metadata goes to PostgreSQL. Both the log
server and replay server can run as stateless replicas with no shared volume
requirement (no ReadWriteMany PVC needed). Kustomize manifests are in `k8s/`.

**The monitoring story:**

Prometheus metrics on the log server (session counts, incomplete sessions,
risk score histograms). SIEM forwarding on session close: CEF, OCSF v1.3.0,
syslog, or HTTPS JSON. A sample Elasticsearch index template + Kibana dashboard
is in `contrib/elastic/`.

**The compliance story:**

Sessions are frozen (not just warned) if the log server is unreachable. This
satisfies the "mandatory" requirement in PCI-DSS 10.2 and similar frameworks
without relying on best-effort behavior.

Repo: https://github.com/alun-hub/sudo-logger
Demo: https://sudo-logger.unixkonsult.se
