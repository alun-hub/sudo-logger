# Why sudo logging is broken by default

*And how mandatory acknowledgement closes the gap.*

---

## What sudo logs by default

When a Linux administrator runs `sudo cat /etc/shadow`, three things happen:
syslog gets an entry, the command runs, and the output goes to the terminal.
That syslog entry is the extent of the default audit trail on most systems.

It records *who* ran *what* — but not *what they saw*. There is no record of
the output. If the admin ran `sudo vim /etc/passwd` and edited an entry, the
syslog says "vim was run", not what changed. If they ran an interactive `sudo
bash` session for 45 minutes, the log shows one line.

This is enough for basic accountability in low-risk environments. It is not
enough for compliance frameworks that require a complete, tamper-evident record
of privileged activity — PCI-DSS requirement 10.2, ISO 27001 Annex A.9.4.2,
HIPAA audit controls, or CIS Level 2 benchmarks.

## sudo_logsrvd: better, but still optional

sudo 1.9 introduced `sudo_logsrvd`, a remote log server that captures complete
I/O sessions via sudo's built-in plugin API. Sessions are stored as asciinema
or timing files on a central server. The `sudoreplay(8)` command can play them
back.

This is a significant improvement. But there is a fundamental problem: logging
is opt-in.

The option `ignore_log_errors` defaults to `true`. This means that if the log
server is unreachable — network outage, server crash, misconfiguration — sudo
proceeds anyway and the session is not recorded. The rationale is
availability: operators do not want a brief network blip to lock out their
admins. This is a reasonable default for a development environment. It is
disqualifying for any environment where the audit trail must be complete.

The second problem is what happens mid-session. Even if you set
`ignore_log_errors=false`, this only blocks sessions that cannot connect at
*start time*. Once a session is established, if the network drops, there is no
mechanism to freeze the running process. The user continues working; chunks
that cannot be delivered are either lost or buffered locally, but there is no
enforcement that they will ever reach the central server.

## How an attacker bypasses optional logging

Consider an insider threat or a compromised account with sudo rights. The
attacker knows that logs go to a central server. They have three easy options:

**Option 1: kill the log server.** If they have access to the server, they
stop `sudo-logserver`. From that point, new sudo sessions on every host proceed
unlogged (with default settings). They have a clean window.

**Option 2: disrupt the network path.** A firewall rule change, a routing
table modification, or a targeted DoS against the log server's IP. Same
result: logging stops, sessions proceed.

**Option 3: tamper with sudo.conf.** The sudo configuration file
`/etc/sudo.conf` controls which plugins are loaded. If an attacker can write
to it (which requires root, but they already have root via sudo), they can
remove the `Plugin` line and restart sudo. Subsequent sessions run without any
plugin at all.

None of these options require sophisticated tooling. They require only the
access that the attacker is presumably trying to cover up.

## The mandatory ACK + freeze approach

sudo-logger treats logging as a hard prerequisite, not a best-effort service.
The mechanism works as follows:

**At session start:** the C plugin connects to the local agent daemon, which
opens a TLS connection to the central log server. If the server is unreachable,
sudo is blocked — the command never runs. This closes the "can't connect at
start" window.

**During a session:** every chunk of I/O is streamed to the server. The server
returns an ed25519-signed acknowledgement for each chunk, binding the session
ID and sequence number. The agent tracks the most recent acknowledged sequence.
Every 400 ms, the agent sends a heartbeat to the server; the server replies
immediately.

**On network loss:** if two consecutive heartbeats (800 ms) go unacknowledged,
the agent freezes the child process via `cgroup.freeze=1`. The user's terminal
stops accepting input — not a soft "the process seems stuck" but a hard
kernel-enforced pause. A banner is written to the terminal explaining the
freeze. The user can exit with Ctrl+C, which terminates the session. They
cannot continue working.

**Why cgroups, not signals?** Job-control signals (`SIGSTOP`/`SIGCONT`) can be
sent by the process itself, or countered with signal handlers. `cgroup.freeze`
operates at the kernel scheduler level. A process in a frozen cgroup cannot be
scheduled — it does not run, period. Additionally, sudo-logger calls
`unshare(CLONE_NEWCGROUP)` at session start, so the child process cannot
migrate itself to a parent cgroup to escape the freeze, even with
`CAP_SYS_ADMIN`.

**On recovery:** when ACKs resume, the cgroup is unfrozen automatically. The
session continues from the point of the last ACK. No data is lost.

## What mandatory ACK prevents

Going back to the three attack options:

**Option 1 (kill the log server):** when the server goes down, active sessions
are frozen within 800 ms. New sessions cannot start. The attacker has closed
the audit window but locked themselves out of sudo as well.

**Option 2 (disrupt the network):** same result. The freeze kicks in during
the network outage. Sessions cannot proceed unlogged.

**Option 3 (tamper with sudo.conf):** sudo-logger's eBPF subsystem runs kernel
tracepoints that monitor all `sudo` and `pkexec` execve events. It correlates
these with plugin activity. If sudo executes but no `SESSION_START` message
arrives within 30 seconds, the agent sends a `DIVERGENCE_ALERT` to the server,
which creates a visible "⚠ no plugin" entry in the replay UI. The bypass is
detected and flagged, even if the attacker successfully removed the plugin.

## Limitations to be honest about

Mandatory logging introduces availability risk. If the log server is down for
an extended period, administrators cannot use sudo at all (beyond the freeze
timeout, currently 3 minutes). This is a deliberate trade-off: completeness
over availability. For break-glass access during a logging outage, operators
should have a documented procedure (e.g., a physical console login that
bypasses sudo entirely).

sudo-logger is Linux-only and works best on Fedora/RHEL systems (SELinux
policy ships in the package). The eBPF sandbox and divergence detection require
a kernel with BTF support (Linux 5.8+, standard on Fedora 32+ and RHEL 9+).

The freeze is not instantaneous. There is a ~800 ms detection window during
which the child process continues to run. In practice this is negligible for
interactive sessions; it would only matter if the attacker had a prepared
script designed to complete a destructive action in under a second after
disrupting the network.

## Summary

Optional logging is not logging. A compliance framework that says "logs must be
collected" but allows the logging service to be disrupted without consequence
provides the appearance of control without the substance.

Mandatory acknowledgement — where the process physically cannot proceed until
the log server confirms receipt — closes the gap. sudo-logger implements this
guarantee at the Linux kernel level using cgroup freezing and ed25519-signed
per-chunk ACKs.

The freeze mechanism is what makes sudo-logger unusual. It is also what makes
it genuinely useful for environments where the audit trail is not negotiable.

---

*See also:*
- [comparison.md](comparison.md) — sudo-logger vs sudo_logsrvd, auditd, and enterprise PAM
- [ARCHITECTURE.md](../ARCHITECTURE.md) — wire protocol, freeze mechanism, and cgroup isolation details
