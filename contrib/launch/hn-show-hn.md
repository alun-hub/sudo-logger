# Hacker News — Show HN draft

**Submit at:** https://news.ycombinator.com/submit
**Best time:** Tuesday or Wednesday, 9–11 AM US Eastern (15:00–17:00 CET)

---

## Title options (pick one, test with friends first)

1. `Show HN: sudo-logger – freeze the terminal if audit logs can't be delivered`
2. `Show HN: Mandatory sudo session recording – terminal freezes if logs aren't ACKed`
3. `Show HN: sudo-logger – cgroup.freeze enforces mandatory Linux session auditing`

**Recommended:** option 1. "freeze the terminal" is the hook; it's concrete and unusual.

**URL:** https://github.com/alun-hub/sudo-logger

---

## First comment (post immediately after submitting — this gets shown first)

Post this yourself as the first reply to get ahead of the discussion:

---

I built this because I kept seeing compliance audits that said "sudo sessions
are logged" — but the logging was optional. A brief network outage, a stopped
log daemon, or a tampered sudo.conf and the audit trail has a gap. The
frameworks (PCI-DSS 10.2, ISO 27001 A.9.4.2) say logs must be collected; they
don't say what happens if logging fails. sudo-logger's answer: the session
freezes.

**How the freeze works:**

Every sudo session streams I/O to a central log server over mutual TLS. The
server sends an ed25519-signed acknowledgement per chunk. The local agent sends
a heartbeat every 400 ms. If two consecutive heartbeats go unacknowledged (~800
ms), the agent calls `cgroup.freeze=1` on the session's cgroup. The process is
frozen at the kernel scheduler level — not paused with SIGSTOP (which the
process can counter), but actually not scheduled. The user sees a banner and can
exit with Ctrl+C. They cannot continue working.

We also call `unshare(CLONE_NEWCGROUP)` at session start so child processes
cannot migrate to a parent cgroup to escape the freeze, even with CAP_SYS_ADMIN.

**Live demo:** https://sudo-logger.unixkonsult.se — real sessions from a
monitored host, searchable and replayable in the browser.

**Honest limitations:**

- Linux/Fedora/RHEL-focused. The RPM packages have SELinux policy; Debian/Ubuntu
  support exists but is less polished.
- No relay mode. If the network is reliably down for > 3 minutes, the session is
  terminated. For break-glass situations you need a documented out-of-band
  procedure (physical console, etc.).
- The eBPF sandbox and divergence detection require Linux 5.8+ with BTF
  (`/sys/kernel/btf/vmlinux`). The plugin and agent work on older kernels.
- This is an enforcement tool, not an IDS. It guarantees that I/O is recorded;
  it does not analyze it in real time (though the SIEM integration lets your
  SIEM do that).

Happy to answer questions about the design trade-offs.

---

## Likely questions to prepare for

**Q: How is this different from sudo_logsrvd?**
A: sudo_logsrvd logs but doesn't enforce. `ignore_log_errors` defaults to true;
mid-session network loss is silently tolerated. See docs/comparison.md in the
repo for a full breakdown.

**Q: What about auditd?**
A: auditd records syscalls, not I/O content. It can't tell you what `sudo vim
/etc/passwd` *changed*. The two are complementary — many deployments run both.

**Q: Isn't freezing too disruptive? What if the network blips?**
A: There's a 3-minute timeout before the session is terminated (configurable).
A brief blip of a few seconds freezes and then automatically resumes. The freeze
is only permanent if the connection doesn't recover.

**Q: What about Kubernetes/cloud?**
A: Distributed storage mode (S3 + PostgreSQL) lets the log server run as
stateless replicas. The k8s/ directory has Kustomize manifests.
