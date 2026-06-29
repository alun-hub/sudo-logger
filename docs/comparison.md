# sudo-logger vs alternatives

This page compares sudo-logger to the tools people typically evaluate for mandatory
sudo session auditing: `sudo_logsrvd` (built into sudo), `auditd` (Linux kernel audit
subsystem), and enterprise PAM solutions such as BeyondTrust and CyberArk.

The central question is not "can this tool record what happened?" — all of them can.
The question is: **can an attacker proceed with unlogged sudo activity?**

---

## Quick comparison

| | sudo_logsrvd | auditd | BeyondTrust / CyberArk | **sudo-logger** |
|---|:---:|:---:|:---:|:---:|
| Freeze terminal if server unreachable | ✗ | ✗ | varies | ✅ ≤800 ms |
| Block sudo if logging unavailable at start | ⚠️ config flag | ✗ | ✅ | ✅ always |
| Cryptographic per-chunk ACKs | ✗ | ✗ | ✗ | ✅ ed25519 |
| eBPF plugin-bypass detection | ✗ | partial | ✗ | ✅ |
| Web replay UI | ✗ | ✗ | ✅ | ✅ |
| Risk scoring | ✗ | ✗ | ✅ | ✅ |
| SIEM forwarding | ✗ | via auditd | ✅ | ✅ CEF / OCSF |
| Secret redaction before transit | ✗ | ✗ | varies | ✅ |
| Ships with the OS / no extra install | ✅ | ✅ | ✗ | ✗ |
| Relay / hierarchical logging | ✅ | ✗ | ✅ | ✗ |
| Kubernetes / horizontal scaling | ✗ | ✗ | ✅ | ✅ S3 + PG |
| Open source | ✅ | ✅ | ✗ | ✅ |
| Approximate cost | free | free | $$$$ | free |

---

## sudo_logsrvd

`sudo_logsrvd` is the official remote logging server that ships with sudo 1.9+.
It uses the same plugin API as sudo-logger and is the most natural comparison.

**Where they are the same:**
- Both capture stdin/stdout/tty I/O over TLS
- Both require sudo 1.9+
- Both store sessions in a format compatible with `sudoreplay(8)` (though sudo-logger
  also writes asciinema v2)
- Both can reject sessions if the server is unreachable at start time (sudo-logger
  always does; sudo_logsrvd requires `ignore_log_errors=false`)

**Where sudo-logger goes further:**

1. **Freeze on mid-session loss.** `sudo_logsrvd` has no mechanism to freeze an
   active session if the connection drops after it starts. The session proceeds and
   I/O is lost. sudo-logger freezes the child process via `cgroup.freeze=1` within
   ~800 ms — the user cannot type, paste, or run subcommands until ACKs resume.

2. **Cryptographic ACKs.** sudo-logger uses ed25519-signed per-chunk ACKs that bind
   the session ID, sequence number, and timestamp. A captured ACK from one session
   cannot be replayed to unfreeze another. sudo_logsrvd has no ACK mechanism.

3. **cgroup namespace isolation.** sudo-logger calls `unshare(CLONE_NEWCGROUP)` so
   child processes see the session cgroup as their filesystem root for
   `/sys/fs/cgroup`. Even with `CAP_SYS_ADMIN`, a process cannot migrate to a parent
   cgroup to escape the freeze. sudo_logsrvd does no process isolation.

4. **eBPF divergence detection.** sudo-logger correlates kernel-level sudo execve
   events with plugin activity. If sudo runs without the plugin (e.g., `sudo.conf`
   was tampered with), the agent alerts centrally. sudo_logsrvd relies entirely on
   the plugin being loaded.

5. **Web replay UI, risk scoring, SIEM, secret redaction.** sudo_logsrvd provides
   only the `sudoreplay(8)` CLI.

**Where sudo_logsrvd is better:**

- Ships with sudo — zero additional packages or services to install
- Supports relay chains (client → relay → server) for air-gapped or high-latency segments
- sudoreplay format is widely understood and tooled

**When to choose sudo_logsrvd:** best-effort logging where network reliability is
high and local buffering at a relay is acceptable.

**When to choose sudo-logger:** mandatory enforcement — unacknowledged I/O must
never proceed.

For a more detailed feature-by-feature breakdown see
[comparison-sudo-logsrvd.md](comparison-sudo-logsrvd.md).

---

## auditd

`auditd` is the Linux kernel's audit subsystem. It records syscalls (execve, open,
connect, etc.) via a kernel ring buffer. Every major distribution ships it by default.

**What auditd does well:**
- Immutable kernel-level trail — a userspace process cannot suppress its own audit
  records without `CAP_AUDIT_CONTROL`
- Captures *all* privileged processes, not just sudo
- Extremely low overhead for simple rules
- Records failed attempts (a `sudo` invocation that was denied still appears)
- Integrates with the full Linux security ecosystem (SELinux, AIDE, Wazuh, etc.)

**Where auditd falls short for mandatory session recording:**

1. **No I/O capture.** `auditd` records that `sudo cat /etc/shadow` was executed.
   It does not record what `cat` printed. For SOC analysts who need to know *what
   data was accessed*, this is a critical gap.

2. **No enforcement.** auditd cannot block, freeze, or slow down a process. If the
   audit daemon is stopped, kernel records are dropped (unless configured with
   `--backlog-wait-time` at the cost of system-wide slowdown). It cannot enforce
   that every byte of I/O reaches a remote server.

3. **No session replay.** There is no concept of a "session" with start, I/O stream,
   and end timestamp. Correlating an audit trail for a complex interactive session
   requires custom tooling.

4. **No secret redaction.** Passwords typed during an interactive session appear in
   plaintext in the I/O stream — auditd cannot intercept tty I/O at all.

**sudo-logger and auditd are complementary, not competing.** sudo-logger captures
the I/O stream with enforcement guarantees; auditd captures the syscall trail. The
two are commonly deployed together. sudo-logger's SELinux policy is designed for
this coexistence.

---

## BeyondTrust Password Safe / Privilege Management

BeyondTrust is an enterprise Privileged Access Management (PAM) platform. It provides
session recording, just-in-time access, password vaulting, and policy enforcement for
heterogeneous environments (Linux, Windows, network devices, cloud consoles).

**What BeyondTrust does well:**
- Unified PAM across OS types — single console for Linux, Windows, and cloud
- Workflow-driven access requests with approval chains and ticketing integration
- Password vaulting and session brokering (agent can inject credentials without
  revealing them to the user)
- Long-term compliance reporting and audit export

**Where it differs from sudo-logger:**

1. **Architecture.** BeyondTrust typically intercepts sessions at a PAM module or
   SSH proxy layer, not at the sudo I/O plugin level. This means it can record
   sessions but may not enforce the same freeze-on-loss guarantee at the cgroup level.

2. **Cost.** Enterprise PAM pricing starts in the tens of thousands of dollars per
   year. sudo-logger is open source under AGPL-3.0.

3. **Complexity.** A BeyondTrust deployment requires a central appliance, database,
   and change management process. sudo-logger installs two packages and runs two Go
   daemons.

4. **Transparency.** As a closed-source appliance, BeyondTrust's enforcement logic
   cannot be audited or customised. sudo-logger's freeze and ACK logic is publicly
   reviewable.

**When to choose BeyondTrust (or CyberArk):** enterprises with existing PAM
investments, Windows environments, or requirements for password vaulting and session
brokering that go beyond Linux sudo.

**When to choose sudo-logger:** Linux-native mandatory recording with a transparent,
auditable enforcement mechanism and no per-seat licensing.

---

## CyberArk Privileged Access Security

CyberArk occupies the same market segment as BeyondTrust. The comparison is similar:
comprehensive enterprise PAM with unified policy, password vaulting, and SIEM
integration at enterprise price points.

CyberArk's PSM (Privileged Session Manager) records sessions from a proxy jump host,
which means it captures network-level sessions but not necessarily local sudo
commands on a host that has direct network access. sudo-logger captures at the kernel
level regardless of network topology.

---

## Summary: which to choose

| Scenario | Recommended tool |
|---|---|
| No extra install, best-effort logging | `sudo_logsrvd` |
| Syscall-level trail, failed attempt detection | `auditd` (alongside sudo-logger) |
| Linux-native mandatory I/O logging, open source | **sudo-logger** |
| Multi-OS enterprise PAM, password vaulting, existing investment | BeyondTrust / CyberArk |
| All of the above | sudo-logger + auditd + enterprise PAM (layered) |

Most security-mature Linux environments run `auditd` for syscall auditing and
sudo-logger for mandatory I/O capture. The two tools record different things and
the combination is stronger than either alone.
