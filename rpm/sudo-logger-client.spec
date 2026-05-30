Name:           sudo-logger-client
Version:        1.20.93
Release:        1%{?dist}
Summary:        Sudo I/O plugin and agent for remote session logging

License:        MIT
Source0:        sudo-logger-%{version}.tar.gz

BuildRequires:  gcc
BuildRequires:  sudo-devel
BuildRequires:  golang
BuildRequires:  selinux-policy-devel

# Go binaries via gccgo have non-standard debug info
%global debug_package %{nil}

Requires:       sudo >= 1.9
Requires:       systemd
Requires:       selinux-policy

%description
Sudo I/O plugin (sudo_logger_plugin.so) and local agent daemon
(sudo-logger-agent) that together record all sudo sessions and ship
them in real-time to a remote sudo-logger-server instance over
mutual TLS.  The agent also uses eBPF tracepoints (when available)
to capture su, screen, tmux, and pkexec privilege escalations
and to detect attempts to bypass the plugin.

Input is frozen if the log server stops acknowledging, preventing
users from running sudo commands without a verified log trail.

%prep
%setup -q -n sudo-logger-%{version}

%build
# Build the sudo I/O plugin
cd plugin
gcc -Wall -Wextra -O2 -fPIC -shared \
    -I/usr/include/sudo \
    -D_GNU_SOURCE \
    -o sudo_logger_plugin.so \
    plugin.c -lpthread

# Build the agent daemon.
# The eBPF Go bindings (recorder_bpf*.go / *.o) are pre-generated and
# included in the source tarball, so clang/bpf2go are not needed here.
cd ../go
/usr/lib/golang/bin/go build -mod=vendor -o sudo-logger-agent ./cmd/agent

# Build the SELinux policy module
cd ../selinux
make -f /usr/share/selinux/devel/Makefile sudo_logger.pp

%install
# Plugin
install -D -m 0755 plugin/sudo_logger_plugin.so \
    %{buildroot}%{_libexecdir}/sudo/sudo_logger_plugin.so

# Agent binary
install -D -m 0755 go/sudo-logger-agent \
    %{buildroot}%{_bindir}/sudo-logger-agent

# Systemd service
install -D -m 0644 sudo-logger-agent.service \
    %{buildroot}%{_unitdir}/sudo-logger-agent.service

# Systemd preset (enable service on install)
install -D -m 0644 sudo-logger-agent.preset \
    %{buildroot}%{_presetdir}/50-sudo-logger-agent.preset

# Config directory (certs placed here by admin)
install -d -m 0750 %{buildroot}%{_sysconfdir}/sudo-logger

# Default client config (LOGSERVER address)
install -D -m 0640 agent.conf \
    %{buildroot}%{_sysconfdir}/sudo-logger/agent.conf

# Example sandbox deny-list (not enabled by default)
install -D -m 0640 sandbox.yaml \
    %{buildroot}%{_sysconfdir}/sudo-logger/sandbox.yaml

# SELinux policy module
install -D -m 0644 selinux/sudo_logger.pp \
    %{buildroot}%{_datadir}/selinux/packages/sudo_logger.pp

# Audit immutable rules — lock audit config against runtime changes
install -D -m 0640 audit/99-immutable.rules \
    %{buildroot}%{_sysconfdir}/audit/rules.d/99-immutable.rules

# systemd drop-ins — RefuseManualStop=yes for security-critical daemons
for svc in sshd sssd rsyslog polkit chronyd NetworkManager firewalld crond gssproxy; do
    install -D -m 0644 systemd-drop-ins/refuse-stop.conf \
        %{buildroot}/etc/systemd/system/${svc}.service.d/refuse-stop.conf
done

# Man pages
install -D -m 0644 man/sudo-logger-agent.8 \
    %{buildroot}%{_mandir}/man8/sudo-logger-agent.8
install -D -m 0644 man/sudo_logger_plugin.8 \
    %{buildroot}%{_mandir}/man8/sudo_logger_plugin.8
install -D -m 0644 man/sandbox.yaml.5 \
    %{buildroot}%{_mandir}/man5/sandbox.yaml.5

%pre
# Migrate legacy shipper.conf → agent.conf BEFORE RPM installs new files.
# Must run in %pre so the file exists when RPM processes %config(noreplace),
# causing RPM to keep the user's migrated config instead of overwriting it.
if [ ! -f %{_sysconfdir}/sudo-logger/agent.conf ] && \
   [ -f %{_sysconfdir}/sudo-logger/shipper.conf ]; then
    cp -p %{_sysconfdir}/sudo-logger/shipper.conf \
          %{_sysconfdir}/sudo-logger/agent.conf
fi
# Clear any stale BPF hooks/maps before the new agent starts.
rm -rf /sys/fs/bpf/sudo-logger 2>/dev/null || true
# Remove immutable flag from our binaries before RPM writes new files.
# This is needed for upgrades — on first install the files don't exist yet
# so the commands silently fail (|| true).
chattr -i %{_libexecdir}/sudo/sudo_logger_plugin.so       2>/dev/null || true
chattr -i %{_bindir}/sudo-logger-agent                    2>/dev/null || true
chattr -i %{_bindir}/sudo-shipper                         2>/dev/null || true

%post
# Add plugin line to sudo.conf if not already present
if ! grep -q 'Plugin sudo_logger_plugin sudo_logger_plugin.so' /etc/sudo.conf 2>/dev/null; then
    echo 'Plugin sudo_logger_plugin sudo_logger_plugin.so' >> /etc/sudo.conf
fi
# Load SELinux policy module
semodule -i %{_datadir}/selinux/packages/sudo_logger.pp 2>/dev/null || true
%systemd_post sudo-logger-agent.service
# On upgrade the preset only runs for fresh installs, so explicitly enable
# and start the service here. On upgrade %postun of the old package sends
# SIGTERM via systemctl kill; Restart=always then picks up the new binary.
systemctl enable --now sudo-logger-agent.service >/dev/null 2>&1 || true

%posttrans
# Make plugin binary and agent immutable so they cannot be silently replaced
# or removed without first running chattr -i (which requires root intent).
chattr +i %{_libexecdir}/sudo/sudo_logger_plugin.so       2>/dev/null || true
chattr +i %{_bindir}/sudo-logger-agent                    2>/dev/null || true
# Relabel installed files with correct SELinux contexts
restorecon -R %{_bindir}/sudo-logger-agent \
              %{_libexecdir}/sudo/sudo_logger_plugin.so \
              %{_sysconfdir}/sudo-logger 2>/dev/null || true

%preun
# Remove immutable flag so RPM can delete the files on uninstall.
chattr -i %{_libexecdir}/sudo/sudo_logger_plugin.so       2>/dev/null || true
chattr -i %{_bindir}/sudo-logger-agent                    2>/dev/null || true
# Cannot use %%systemd_preun because it calls systemctl stop, which is blocked
# by RefuseManualStop=yes.  On uninstall: disable the unit (removes symlinks)
# then kill the running process via systemctl kill (not blocked).
if [ $1 -eq 0 ]; then
    systemctl disable sudo-logger-agent.service >/dev/null 2>&1 || true
    systemctl kill sudo-logger-agent.service    >/dev/null 2>&1 || true
fi
# Remove SELinux policy module on full uninstall (not on upgrade)
if [ $1 -eq 0 ]; then
    semodule -r sudo_logger 2>/dev/null || true
fi
# Remove plugin line from sudo.conf on uninstall
if [ $1 -eq 0 ]; then
    sed -i '/Plugin sudo_logger_plugin sudo_logger_plugin\.so/d' /etc/sudo.conf \
        2>/dev/null || true
fi

%postun
# On upgrade: reload unit and signal the running agent to restart.
# We cannot use %%systemd_postun_with_restart / systemctl try-restart because
# RefuseManualStop=yes blocks those operations.  Instead, send SIGTERM via
# systemctl kill (not blocked by RefuseManualStop) and let Restart=always
# pick up the new binary after daemon-reload.
if [ $1 -ge 1 ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl kill sudo-logger-agent.service >/dev/null 2>&1 || true
else
    systemctl daemon-reload >/dev/null 2>&1 || true
fi

%files
%{_libexecdir}/sudo/sudo_logger_plugin.so
%{_bindir}/sudo-logger-agent
%{_unitdir}/sudo-logger-agent.service
%{_presetdir}/50-sudo-logger-agent.preset
%dir %attr(0750, root, root) %{_sysconfdir}/sudo-logger
%config(noreplace) %attr(0640, root, root) %{_sysconfdir}/sudo-logger/agent.conf
%config(noreplace) %attr(0640, root, root) %{_sysconfdir}/sudo-logger/sandbox.yaml
%ghost %attr(0644, root, root) %{_sysconfdir}/sudo-logger/ack-verify.key
%{_datadir}/selinux/packages/sudo_logger.pp
%{_mandir}/man8/sudo-logger-agent.8*
%{_mandir}/man8/sudo_logger_plugin.8*
%{_mandir}/man5/sandbox.yaml.5*
%config(noreplace) %attr(0640, root, root) %{_sysconfdir}/audit/rules.d/99-immutable.rules
%dir /etc/systemd/system/sshd.service.d
/etc/systemd/system/sshd.service.d/refuse-stop.conf
%dir /etc/systemd/system/sssd.service.d
/etc/systemd/system/sssd.service.d/refuse-stop.conf
%dir /etc/systemd/system/rsyslog.service.d
/etc/systemd/system/rsyslog.service.d/refuse-stop.conf
%dir /etc/systemd/system/polkit.service.d
/etc/systemd/system/polkit.service.d/refuse-stop.conf
%dir /etc/systemd/system/chronyd.service.d
/etc/systemd/system/chronyd.service.d/refuse-stop.conf
%dir /etc/systemd/system/NetworkManager.service.d
/etc/systemd/system/NetworkManager.service.d/refuse-stop.conf
%dir /etc/systemd/system/firewalld.service.d
/etc/systemd/system/firewalld.service.d/refuse-stop.conf
%dir /etc/systemd/system/crond.service.d
/etc/systemd/system/crond.service.d/refuse-stop.conf
%dir /etc/systemd/system/gssproxy.service.d
/etc/systemd/system/gssproxy.service.d/refuse-stop.conf

%changelog
* Fri May 30 2026 sudo-logger 1.20.93-1
- feat(sandbox): block CAP_MAC_ADMIN (setenforce/semodule), CAP_SYS_RAWIO
  (ioperm/iopl, /dev/mem), and CAP_SYS_BOOT (kexec_load) in the eBPF LSM
  capable hook — all three on by default, each gated by its own feature flag
  in sandbox.yaml

* Sat May 30 2026 sudo-logger 1.20.86-1
- feat(sandbox): add deny_systemd_ipc to block connect() to systemd/D-Bus control
  sockets, closing the systemd-run / StartTransientUnit sandbox escape (off by default;
  also blocks systemctl/loginctl from within a session)
- feat(sandbox): block block/char device-node creation (mknod) inside the sandbox to
  stop raw-device writes that bypass inode-based /dev protection
- fix(sandbox): wire the deny_* feature flags to cfg_enabled() so sandbox.yaml toggles
  actually take effect (previously written to a map no BPF hook read)

* Fri May 29 2026 sudo-logger 1.20.85-1
- fix(bpf): add NETLINK_AUDIT to socket_create block list so auditctl -D is denied in sessions
- fix(bpf): sb_mount now only blocks mounts over protected inodes; legitimate mounts allowed

* Thu May 29 2026 sudo-logger 1.20.84-1
- hardening(sandbox): protect /etc/hosts, resolv.conf, ld.so.preload, /var/spool/at, nftables config
- hardening(audit): install /etc/audit/rules.d/99-immutable.rules (-e 2) to lock audit rules at runtime
- hardening(systemd): RefuseManualStop=yes drop-ins for sshd, sssd, rsyslog, polkit, chronyd, NetworkManager, firewalld, crond, gssproxy

* Wed May 28 2026 sudo-logger 1.20.83-1
- fix(spec): enable and start agent service on upgrade (not only fresh install)

* Wed May 28 2026 sudo-logger 1.20.82-1
- fix(spec): install systemd preset so service is auto-enabled on fresh install

* Wed May 27 2026 sudo-logger 1.20.81-1
- security: add lsm/bpf hook to block eBPF syscalls for sandboxed processes
  Prevents root users inside a sudo session from manipulating protected_inodes
  or protected_procs maps (e.g. via bpftool map delete).
- fix(sandbox): enforce periodic map refresh in agent poller (self-healing)
  Agent now rewrites BPF maps every 60s even if the server config hasn't
  changed, ensuring local tampering is automatically reverted.

* Wed May 27 2026 sudo-logger 1.20.80-1
- feat: central sandbox.yaml management via replay-server UI
  Protocol: MsgFetchConfig/MsgConfigData (0x12/0x13); log server serves
  sandbox.yaml from shared store; agent polls every 60s and reloads BPF
  maps live (no restart). Replay UI: Settings restructured into sub-tabs
  (Risk Rules / SIEM / Sandbox / Retention); new Sandbox editor tab.
  Help: new sections for Risk rules YAML format and Process Sandbox fields.

* Wed May 27 2026 sudo-logger 1.20.71-1
- fix(selinux): add file_type:file { getattr } and lnk_file { getattr read }
  for sandbox config loader stat() calls on .service files and symlinks
- fix(selinux): add debugfs_t and tracefs_t rules so cilium/ebpf can attach
  kprobes and tracepoints via /sys/kernel/tracing and /sys/kernel/debug/tracing

* Tue May 26 2026 sudo-logger 1.20.70-1
- fix(selinux): add sysctl_type:dir { watch } — sysctl_net_t and sysctl_kernel_t
  lack the file_type attribute so must be covered by sysctl_type attribute
- fix(sandbox): skip inotify watches on /proc/ and /sys/ paths — pseudo-fs
  entries are never atomically replaced so watches produce no useful events

* Tue May 26 2026 sudo-logger 1.20.69-1
- fix(selinux): add file_type:dir { open read getattr search watch } for
  sudo_agent_t — dir:watch (kernel 5.x+ inotify permission) and dir:read/open
  needed by sandbox config loader and inotify watcher across all directory types
  (etc_t, cert_t, pam_etc_t, bin_t, var_log_t, sysctl_t, system_conf_t, etc.)

* Tue May 26 2026 sudo-logger 1.20.68-1
- fix(service): remove all systemd hardening flags that cause inotify_add_watch
  EACCES — PrivateTmp/PrivateDevices create private mount namespace; Landlock
  (ProtectKernelTunables) and seccomp (ProtectKernelModules, LockPersonality,
  RestrictSUIDSGID) block watches on /etc and /proc/sys paths in kernel 6.x;
  kernel-level BPF LSM sandbox is the meaningful confinement boundary

* Tue May 26 2026 sudo-logger 1.20.67-1
- fix(service): remove ProtectSystem=strict — incompatible with sandbox inotify
  watcher; inotify_add_watch fails with EACCES on /etc and /usr inside strict's
  private mount namespace, causing sandbox to miss atomic file replacements
  (BPF LSM still enforces write-protection at kernel level for all paths)

* Tue May 26 2026 sudo-logger 1.20.66-1
- fix(selinux): restore confined domain for sudo_agent_t; replace unconfined_domain
  + permissive with targeted allow rules; add capability2 { bpf perfmon } and
  self:bpf { map_create map_read map_write prog_load prog_run } for eBPF agent
- fix(service): restore systemd hardening (ProtectSystem=strict, PrivateTmp,
  PrivateDevices, ProtectKernelTunables, ProtectKernelModules, LockPersonality,
  RestrictSUIDSGID) that was removed by incorrect SELinux troubleshooting
- feat(sandbox): auto-protect newly created files in watched directories via
  inotify + BPF inode map refresh (handles atomic rename by vi/cp/install)

* Tue May 27 2026 sudo-logger 1.20.62-1
- feat(spec): robust upgrade path for eBPF/Sandbox restoration
- feat(spec): clear stale BPF pins in %%pre to prevent agent start failures
- feat(spec): ensure chattr -i/+i and restorecon are applied to all binaries

* Tue May 26 2026 sudo-logger 1.20.52-1
- chore: rename shipper → agent throughout (g_agent_fd, connect_agent(),
  error messages); remove dead cmd/shipper package, sudo-shipper.service,
  shipper.conf, ebpf-recorder.service
- selinux: rename sudo_shipper_t → sudo_agent_t in policy module

* Sat May 23 2026 sudo-logger 1.20.51-1
- fix(wayland): restore screen recording for apps that fork immediately (gvim);
  added 2s grace period to agent linger-mode check to allow descendant detection
- fix(wayland): robust proxy socket permissions; use os.Chmod on path instead
  of fchmod on FD (more reliable kernel node update)
- fix(plugin): robust WAYLAND_DISPLAY injection; overwrite SUDO_COMMAND in
  user_env[] if WAYLAND_DISPLAY is missing to ensure it reaches child process
- feat(sudoers): include DISPLAY and XAUTHORITY in env_keep for XWayland support

* Sat May 23 2026 sudo-logger 1.20.50-1
- chore: demote noisy startup logs to debugLog (stat-skipping per missing
  path, inotify directory count, alert-listener-started)

* Sat May 23 2026 sudo-logger 1.20.49-1
- chore: demote verbose-but-normal log lines to debugLog (protecting inodes,
  aux cgroup registration, cgroupInodeOf diagnostics)

* Sat May 23 2026 sudo-logger 1.20.48-1
- debug: add explicit error logging to cgroupInodeOf to diagnose aux-cgroup
  registration failures in direct-sudo sandbox alert path

* Sat May 23 2026 sudo-logger 1.20.47-1
- fix(sandbox): forward alerts from processes that escaped their session cgroup
  (direct sudo commands: child escapes via PAM before exec, BPF blocks via
  sandboxed_pids — alert retry + aux-cgroup map now finds the session)

* Sat May 23 2026 sudo-logger 1.20.46-1
- debug: log when cgroup lookup misses in reportViolation (serverW nil)
- debug: log when sessionDirs lookup misses in RecordSandboxViolation

* Sat May 23 2026 sudo-logger 1.20.45-1
- fix(replay): sandbox violation check now runs before risk score cache;
  sessions scored before a violation arrived now show correctly in the UI

* Sat May 23 2026 sudo-logger 1.20.44-1
- fix(sandbox): server no longer closes session on MsgSandboxAlert; `return`
  replaced with `continue` so subsequent chunks and SESSION_END are preserved
- fix(sandbox): remove redundant Flush() after WriteMessage in reportViolation
- fix(sandbox): replace alert type magic numbers with named constants;
  use binary.NativeEndian instead of hardcoded LittleEndian
- fix(redactor): prevent echo-based recording bypass — prompt masking only
  activates when output chunk has no trailing newline (real prompts never do)
- docs: lsm=bpf not required on Fedora 38+; active by default in CONFIG_LSM

* Fri May 23 2026 sudo-logger 1.20.43-1
- fix(sandbox): add lsm/file_open and lsm/path_truncate hooks; blocks
  write-mode opens and truncate() syscalls on protected inodes
- fix(sandbox): add lsm/inode_setattr hook; prevents echo > /protected zeroing
  files via O_TRUNC before any write permission check fires
- fix(sandbox): use in_sandbox_pid() in all hooks including task_kill;
  ensures signals from short-lived sudo commands (sudo pkill) are blocked
- fix(sandbox): remove dead dev=0 wildcard inode entries; mountDev() already
  returns the correct s_dev for all filesystems including Btrfs
- fix(verify-sandbox.sh): use systemctl MainPID for reliable agent PID lookup

* Fri May 23 2026 sudo-logger 1.20.42-1
- fix(spec): replace %%systemd_preun with manual systemctl disable + kill;
  %%systemd_preun calls systemctl stop which is blocked by RefuseManualStop=yes

* Fri May 23 2026 sudo-logger 1.20.41-1
- fix(sandbox): raise MAX_PROTECTED_INODES from 1024 to 4096 — fixes E2BIG
  on agent start when sandbox.yaml resolves >1024 inodes via directory traversal
- fix(sandbox): add sandboxed_pids BPF map + sched_process_fork/exit hooks;
  PID tracking propagated atomically at fork time from sudo root to descendants;
  fixes task_kill not blocking signals from short-lived commands (sudo pkill)
  where pam_systemd migrates sudo to a new session scope cgroup before fork
- fix(sandbox): split in_sandbox into cgroup-only (file/inode hooks) and
  pid+cgroup (task_kill only) — prevents PID tracking from blocking sudo rpm
  upgrades by restricting the broader pid scope to kill operations only
- fix(sandbox): use link.AttachTracing instead of link.Tracepoint for tp_btf
  programs (BPF_PROG_TYPE_TRACING, not BPF_PROG_TYPE_TRACEPOINT)

* Thu May 22 2026 sudo-logger 1.20.40-1
- fix(sandbox): use bpf2go-generated SandboxInodeKey instead of hand-crafted
  inodeKey to eliminate possible E2BIG key-size mismatch in ProtectedInodes map
- diag(cgroup): log sudo's actual cgroup after move, children that trigger
  moveSudoOut, and escaped process cgroup paths for debugging kill-protection race

* Thu May 22 2026 sudo-logger 1.20.39-1
- fix(sandbox): remove BPF wildcard dev=0 fallback — caused devpts false
  positives (major=0 anonymous devices) that intermittently blocked terminal
  writes and hung sudo; replace with exact i_sb->s_dev match using mountDev()
  from /proc/self/mountinfo which returns the Btrfs superblock dev correctly
- fix(sandbox): refreshInode now uses mountDev() for exact dev on atomic replace

* Thu May 22 2026 sudo-logger 1.20.38-1
- fix(sandbox): refreshInode now syncs wildcard dev=0 entries on atomic replace
  (visudo etc.) — old wildcard removed, new wildcard added, matching
  loadSandboxConfig behaviour so inode_protected() keeps working after rename
- fix(sandbox): add readyToFork gate to prevent premature moveSudoOut race
- feat(sandbox): wildcard dev=0 fallback in BPF for anonymous-device filesystems
  (Btrfs) — stores both exact and wildcard entry in protected_inodes; BPF
  tries exact i_sb->s_dev first then dev=0 if major==0
- feat(sandbox): recursive directory traversal in loadSandboxConfig
- feat(sandbox): new LSM hooks inode_mkdir/create/mknod/symlink to block file
  creation inside protected directories
- chore(sandbox): fix indentation in sandbox.go, remove unused MAX_RESOLVED_DEVS

* Thu May 22 2026 sudo-logger 1.20.37-1
- fix(sandbox): use mountinfo MKDEV(major,minor) for protected inode dev field
  instead of stat().st_dev; on Btrfs stat returns the subvolume anon_dev while
  the BPF LSM hook reads i_sb->s_dev (superblock dev) — the mismatch caused
  inode_protected() to never match, letting sandboxed writes through
- fix(sandbox): remove debug bpf_printk from sandbox_file_permission

* Thu May 22 2026 sudo-logger 1.20.36-1
- debug(agent): log ino/dev for all sandboxed writes to diagnose why
  inode_protected() returns false despite the inode being in the map

* Thu May 22 2026 sudo-logger 1.20.35-1
- debug(agent): add targeted bpf_printk to sandbox_file_permission — logs
  comm, cgid and sandboxed status for bash/python3 writes to diagnose why
  in_sandbox() does not match the registered cgroup IDs

* Thu May 22 2026 sudo-logger 1.20.34-1
- fix(agent): keep protected_inodes BPF map fresh via inotify — watches
  parent directories of all protected paths; on IN_MOVED_TO (atomic rename
  by editors, cp, install) re-stats the path and swaps the old inode key
  for the new one so sandbox enforcement survives file replacement
- fix(agent): remove debug bpf_printk from sandbox LSM hooks

* Wed May 21 2026 sudo-logger 1.20.33-1
- debug(agent): narrow sandbox bpf_printk to sandboxed processes only —
  logs cgid/ino/dev/blocked once per write attempt inside a session cgroup

* Wed May 21 2026 sudo-logger 1.20.32-1
- debug(agent): add bpf_printk tracing to sandbox LSM hooks — logs cgid,
  inode and dev for every in_sandbox/inode_protected check; read via
  /sys/kernel/debug/tracing/trace_pipe

* Wed May 21 2026 sudo-logger 1.20.31-1
- feat(agent): add eBPF LSM process sandbox — deny-list for files, devices,
  sockets, /proc entries and process names; enforced at kernel level via
  lsm/file_permission, inode_unlink, inode_rename and task_kill hooks;
  scoped to session cgroup so only sudo processes are restricted
- feat(agent): install /etc/sudo-logger/sandbox.yaml example config
  covering Fedora security-critical paths; enable with sandbox_config
  in agent.conf

* Tue May 05 2026 sudo-logger 1.20.30-1
- fix(agent): wrap cgroup remove() in sync.Once — prevents double-remove
  when SIGTERM cleanupAllCgs() races with the linger goroutine defer
- fix(agent): log dropped chunk count in markAlive() when session closes
  mid-drain of the server-outage buffer
- fix(agent): propagate context to waitForPID so pkexec goroutines exit
  cleanly on agent shutdown instead of polling until process death
- fix(agent): prune stale pendingPkexec entries in resolvePkexecScope()
  to prevent unbounded slice growth over long uptimes
- fix(agent): guard inotify fd close with sync.Once preventing double-
  close race between defer and the ctx-cancel goroutine in watch()
- fix(agent): remove dead callerProcess field from ebpfSession

* Tue May 05 2026 sudo-logger 1.20.29-1
- fix(agent): buffer up to 500 session chunks while server unreachable;
  replayed when connection recovers — prevents data loss during brief
  outages where TLS connection remains intact but heartbeats time out
- fix(agent): silence accept-loop log spam on SIGTERM by checking
  context cancellation before logging the error

* Tue May 05 2026 sudo-logger 1.20.28-1
- fix(agent): exclude dbus-daemon from linger-mode exit detection; GUI
  apps (e.g. gvim) spawn a private dbus-daemon that kept sessions stuck
  in live state indefinitely after the main app exited

* Tue May 05 2026 sudo-logger 1.20.27-1
- remove(agent): drop D-Bus polkit monitoring subsystem; too noisy from
  system daemons (PowerDevil, logind, NetworkManager); pkexec sessions
  already captured via eBPF; removes godbus/dbus dependency

* Sat May 03 2026 sudo-logger 1.20.26-1
- fix(agent/ebpf): buffer failed hasIO=false pkexec sessions and retry
  every 30s (same mechanism as D-Bus polkit events); also preserve
  original event timestamp across retries for both eBPF and D-Bus paths

* Sat May 03 2026 sudo-logger 1.20.25-1
- feat(agent/dbus): buffer failed polkit events and retry every 30s;
  events are kept up to 10 minutes and then discarded if server remains
  unreachable; queue capped at 200 events

* Sat May 03 2026 sudo-logger 1.20.24-1
- fix(server): create session record for divergence alerts so they appear
  in the replay UI with red "⚠ no plugin" badge and a warning message
  in the output panel when the Plugin line is missing from sudo.conf

* Sat May 03 2026 sudo-logger 1.20.23-1
- fix(agent/ebpf): capture pkexec target command in BPF at tracepoint time
  instead of reading /proc/<pid>/cmdline from Go; the process can die
  before Go reads it (race condition), causing fallback to "pkexec"

* Sat May 03 2026 sudo-logger 1.20.22-1
- fix(spec): move shipper.conf → agent.conf migration from %%post to %%pre
  so it runs before RPM installs new files; %%config(noreplace) then
  preserves the migrated config instead of overwriting it with the example

* Sat May 03 2026 sudo-logger 1.20.21-1
- rename config file from shipper.conf to agent.conf; upgrade migrates
  existing shipper.conf automatically via %post cp; agent falls back to
  shipper.conf with a deprecation warning if agent.conf is missing
- document dbus option in agent.conf (disable polkit D-Bus logging with
  dbus = false)

* Sat May 03 2026 sudo-logger 1.20.20-1
- fix(agent/ebpf): timestamp pkexec sessions using Go reception time instead
  of BPF ktime conversion; bpf_ktime_get_ns() (CLOCK_MONOTONIC) and
  /proc/uptime (CLOCK_BOOTTIME) diverge after suspend/resume, causing all
  event timestamps to be before session startTime and clamped to 0,
  resulting in all output appearing at once in replay

* Sat May 02 2026 sudo-logger 1.20.19-1
- feat(agent/ebpf): read actual command from /proc/<pid>/cmdline for pkexec
  events instead of hardcoding "pkexec"
- feat(replay): group consecutive dbus-polkit events from the same caller
  within 3 seconds into a collapsible group header showing caller, count,
  and worst risk level

* Sat May 02 2026 sudo-logger 1.20.18-1
- feat(agent/dbus): capture calling process name from /proc/<pid>/comm for
  unix-process polkit subjects; infer service name (firewalld, NetworkManager,
  systemd, etc.) from action ID prefix for system-bus-name subjects
- feat(replay): output panel now shows action description, risk level (critical/
  high/medium/low), caller process/service, and user for polkit event sessions;
  adds JS-side lookup table covering ~35 common polkit action ID prefixes
- feat(store): add caller_process field to protocol, iolog, store (schema v6)

* Sat May 02 2026 sudo-logger 1.20.17-1
- feat(replay): show polkit action ID, result, and user in output panel for
  dbus-polkit and pkexec event-only sessions instead of generic placeholder text

* Sat May 02 2026 sudo-logger 1.20.16-1
- fix(agent/dbus): skip auto-authorized polkit events (exitCode=0);
  only record challenge (exitCode=2) and denied (exitCode=1) events

* Sat May 02 2026 sudo-logger 1.20.15-1
- fix(agent/dbus): resolve real username from /proc/<pid>/status for
  unix-process polkit subjects instead of using the raw D-Bus subject
  string (e.g. "bus::1.1474") — server's sanitizeName rejects colons,
  causing all dbus-polkit sessions to be silently dropped

* Sat May 02 2026 sudo-logger 1.20.14-1
- fix(agent/ebpf): route short-lived pkexec scopes to waiter; query
  loginctlSession before cgroupInode in sessionStarted so polkit PAM sessions
  with < 50ms scope lifetime still notify the pkexec waiter
- fix(agent/ebpf): stat scope before session connect; set hasIO=false when
  scope is gone to avoid sending hasIO=true sessions with no content

* Sat May 02 2026 sudo-logger 1.20.13-1
- feat(agent): add D-Bus polkit monitoring subsystem (dbus.go); agent now
  connects to the system bus as a BecomeMonitor and captures polkit
  CheckAuthorization calls, emitting dbus-polkit source events for each
  authorization request (authorized/denied/challenge) to the log server
- feat(selinux): allow sudo_shipper_t to connect to system_dbusd_t socket
  and send D-Bus messages for the polkit monitor
- feat(replay): add source/exit_code conditions to risk rules; D-Bus polkit
  rules added (dbus_polkit, dbus_polkit_high_value, dbus_polkit_denied)
- feat(replay/ui): teal card border and badge for dbus-polkit sessions;
  authorized/denied/challenge result shown in info bar

* Thu May 01 2026 sudo-logger 1.20.12-1
- fix(agent/ebpf): reduce inotify scope-detection delay from 200ms/100ms to
  50ms, narrowing the window where early PTY writes are missed before the
  cgroup is registered in the BPF tracked_cgroups map
- fix(agent/ebpf): log monoToWallNS boot time at startup for diagnostics

* Thu May 01 2026 sudo-logger 1.20.11-1
- debug: log monoToWallNS at startup and first IO event per pkexec session

* Thu May 01 2026 sudo-logger 1.20.10-1
- fix(agent/ebpf): convert BPF ktime (CLOCK_MONOTONIC) to wall-clock Unix ns
  using boot time from /proc/uptime; fixes all eBPF I/O events appearing at
  t=0 in replay instead of at their correct relative timestamps

* Thu May 01 2026 sudo-logger 1.20.9-1
- fix(agent/ebpf): add scopeToCgroup reverse map so sessionEnded() can close
  pkexec sessions even after the scope directory is already deleted by inotify

* Thu May 01 2026 sudo-logger 1.20.8-1
- fix(agent/ebpf): route empty-type session scopes (polkit PAM root sessions)
  to pkexec waiter instead of dropping them; fixes I/O capture for pkexec bash

* Thu May 01 2026 sudo-logger 1.20.7-1
- fix(agent/ebpf): fast-path pkexec cgroup registration — polkit moves pkexec
  into a new session scope almost immediately; read /proc/<pid>/cgroup at
  goroutine start and register it instantly rather than waiting 2 s

* Thu May 01 2026 sudo-logger 1.20.6-1
- fix(agent/ebpf): capture pkexec bash I/O via invoking cgroup when polkit
  creates no dedicated scope (common on Fedora); exit detected by polling
  pkexec PID via /proc

* Thu May 01 2026 sudo-logger 1.20.5-1
- feat(agent/ebpf): track pkexec invocations as ebpf-pkexec sessions in replay
- fix(agent/ebpf): stop false divergence alerts for pkexec (polkit, not sudo plugin)

* Thu May 01 2026 sudo-logger 1.20.4-1
- fix(agent/ebpf): replace cgroup-based execve filter with PID-parent check in BPF
- fix(agent/divergence): discard stale pending execve entries (>10s) before FIFO match

* Thu May 01 2026 sudo-logger 1.20.3-1
- debug(agent/ebpf): log inode when trackPluginCgroup adds/removes cgroup from BPF map

* Thu Apr 30 2026 sudo-logger 1.19.2-1
- fix(agent/divergence): suppress late-arriving duplicate execve via grace window (lastConfirmed)
- fix(agent): downgrade transient scope stat errors to debug (race between inotify and scope deletion)

* Thu Apr 30 2026 sudo-logger 1.19.1-1
- fix(agent): read parent process uid to identify invoking user (sudo setuid(0) before exec caused uid=0 mismatch)
- fix(agent): drain all execve events within 5s on plugin confirm (sudo fires 2 execve per invocation)
- fix(agent): tolerate loginctl returning partial data for system sessions
- fix(agent): remove ProtectHome to allow Wayland proxy socket in /run/user/<uid>

* Thu Apr 30 2026 sudo-logger 1.19.0-1
- feat: merge sudo-shipper and ebpf-recorder into sudo-logger-agent
- feat: eBPF tracepoints for PTY I/O, sudo/pkexec execve, and process exit
- feat: divergence detection — alerts when sudo runs without plugin logging
- feat: graceful degradation to plugin-only mode on kernels without BTF
- feat: BPF program pinning to /sys/fs/bpf/sudo-logger for crash resilience
- protocol: add source, parent_session_id, has_io fields to SESSION_START
- store: add source, divergence_status, matched_session_id to SessionRecord

* Sat Apr 25 2026 sudo-logger 1.17.36-1
- fix(shipper): restore heartbeat dead-declaration to 2 missed (800 ms); Gemini had raised it to 5 missed (2000 ms) as a workaround for false freezes now resolved by plugin mutex fix

* Sat Apr 25 2026 sudo-logger 1.17.35-1
- fix(plugin): add mutex to prevent race between ship_chunk and refresh_ack_cache causing stream corruption and session freeze under high I/O

* Wed Apr 22 2026 sudo-logger 1.17.31-1
- feat: support multiple sequential GUI applications in wayland-proxy
- feat: implement split-view and synchronized playback in replay UI
- feat: add pop-out window and animated loading screen for GUI sessions
- fix: ensure loading screen resets on session switch

* Wed Apr 22 2026 sudo-logger 1.17.30-1
- security: fix path traversal via unvalidated WAYLAND_DISPLAY in shipper (VULN-004)
- security: prevent resource exhaustion in wayland-proxy by limiting SHM pool size and image dimensions (VULN-005)

* Wed Apr 22 2026 sudo-logger 1.17.29-1
- docs: document GTK AT-SPI accessibility warnings and how to suppress them
- fix: remove invalid env_set from sudoers; use env_keep for NO_AT_SPI

* Wed Apr 22 2026 sudo-logger 1.17.28-1
- fix: set NO_AT_BRIDGE=1 and NO_AT_SPI=1 via sudoers env_set to suppress
  GTK accessibility warnings in GUI sessions

* Wed Apr 22 2026 sudo-logger 1.17.27-1
- security: fix critical path traversal in shipper via XDG_RUNTIME_DIR (VULN-001)
- security: fix Denial of Service in plugin via JSON truncation (VULN-002)
- security: fix path traversal in plugin cgroup management (VULN-003)

* Tue Apr 21 2026 sudo-logger 1.17.26-1
- fix(shipper): implement 10s stability period for recovery to prevent
  duplicate freeze banners during network flapping; frozenSince is only
  reset after 25 consecutive successful heartbeat windows
- fix(plugin): add 5s cooldown to terminal-reclaim (tcsetpgrp) to prevent
  frozen bash from being stopped (SIGTTOU) when user runs 'fg'

* Tue Apr 21 2026 sudo-logger 1.17.25-1
- fix(shipper): close done channel before serverConnAlive=false to prevent
  race where heartbeat goroutine calls markAlive() between the two writes,
  resetting serverConnAlive=true and triggering a spurious freeze banner
  after normal session exit (freeze → unfreeze → exit sequence)
- fix(shipper): add done-channel select to heartbeat goroutine so it exits
  cleanly when the session ends, consistent with other watchdog goroutines

* Tue Apr 21 2026 sudo-logger 1.17.24-1
- fix(plugin): remove FREEZE_MSG write from !fresh && !was_frozen path in
  monitor_thread_fn; shipper already writes the banner via writeTTYFreezeMsg
  at markDead() time — plugin write was redundant and caused a duplicate
  banner on the first fg after freeze; was_frozen tracking kept for UNFREEZE_MSG

* Tue Apr 21 2026 sudo-logger 1.17.23-1
- fix(plugin): remove redundant FREEZE_MSG write from terminal-reclaim code;
  the shipper already wrote the banner at markDead() time — terminal-reclaim
  only needs to call tcsetpgrp() to prevent the user being trapped

* Tue Apr 21 2026 sudo-logger 1.17.22-1
- fix: remove unfreeze logic from updateAck — delayed TCP ACKs (retransmits
  in-flight when the server went down) no longer reset serverConnAlive or
  frozenSince; only markAlive (2 consecutive heartbeat windows) can unfreeze;
  eliminates spurious second freeze banner and brief cgroup unfreeze

* Tue Apr 21 2026 sudo-logger 1.17.21-1
- fix: require 2 consecutive heartbeat windows before declaring server alive
  again; prevents a single delayed HeartbeatAck from triggering a spurious
  second freeze banner and brief cgroup unfreeze visible as an extra fg cycle

* Sat Apr 18 2026 alun <alun@alun.se> - 1.17.16-1
- Implement high-precision surgical secret masking for TTY and command metadata
- Optimize masking performance with fast-path trigger regex
- Fix Wayland proxy deadlock and implement final frame capture
- Add configurable proxy_period to shipper.conf
* Sat Apr 18 2026 sudo-logger 1.17.15-1
- feat(redaction): automatic secret masking in terminal streams and
  session metadata; built-in patterns for AWS/GCP/GitHub/JWT/Bearer;
  custom patterns via mask_pattern in shipper.conf
- docs: document secret redaction in README and slide deck (new slide)
- docs: document proxy_period config key

* Sat Apr 18 2026 sudo-logger 1.17.14-1
- fix(wayland-proxy): remove double lock in captureCommit (deadlock bug)

* Sat Apr 18 2026 sudo-logger 1.17.13-1
- feat(wayland-proxy): force capture on client disconnect to record last frame
- feat(wayland-proxy): lower default capture interval 500ms→300ms
- feat(shipper/config): add proxy_period key to shipper.conf; passed to
  wayland-proxy as --period flag

* Sat Apr 18 2026 sudo-logger 1.17.12-1
- fix(selinux): allow sudo_shipper_t to map/read/write user_tmp_t files
  (memfd SHM pools from gdk-wayland) and access dri_device_t for DMA-buf

* Sat Apr 18 2026 sudo-logger 1.17.11-1
- feat(selinux): include SELinux policy module in RPM; semodule -i runs
  in %%post, restorecon in %%posttrans, semodule -r on full uninstall
- fix(selinux): allow sudo_shipper_t sock_file setattr (needed for chmod
  of proxy socket after bind in /run/user/<uid>/)

* Fri Apr 17 2026 sudo-logger 1.17.10-1
- fix(selinux): grant sudo_shipper_t dac_override and dac_read_search
  capabilities so wayland-proxy can bind a socket in /run/user/<uid>/
  (mode 0700, owned by the logged-in user)

* Fri Apr 17 2026 sudo-logger 1.17.9-1
- fix(config): accept legacy LOGSERVER key as alias for server so
  existing shipper.conf files (%%config noreplace) keep working

* Fri Apr 17 2026 sudo-logger 1.17.8-1
- feat(shipper): replace CLI flags with key=value config file
  (shipper.conf); ExecStart is now just /usr/bin/sudo-shipper
- feat(shipper): add wayland = true/false config option to disable
  Wayland screen capture without rebuilding

* Fri Apr 17 2026 sudo-logger 1.17.7-1
- fix(service): remove ProtectHome — it makes /run/user inaccessible even with
  ReadWritePaths=/run/user, breaking the wayland-proxy compositor connection

* Fri Apr 17 2026 sudo-logger 1.17.6-1
- fix(spec): add wayland-proxy to chattr -i/%posttrans/+i/%preun scriptlets

* Fri Apr 17 2026 sudo-logger 1.17.5-1
- fix(wayland-proxy): readMsg now reads exact bytes into message buffer,
  fixing protocol desync that caused proxy to fall out of sync with compositor
- fix(wayland-proxy): add sync.Mutex to proxyState to prevent concurrent map
  writes between client and server forwarding goroutines
- fix(wayland-proxy): close local FD copies after parseClientMsg to prevent
  file descriptor leak
- fix(shipper): linger mode — keep server connection alive until all GUI
  processes in session cgroup exit after sudo itself has returned
- fix(plugin): correct inverted if-condition in WAYLAND_DISPLAY patch syslog

* Fri Apr 17 2026 sudo-logger 1.17.4-1
- fix(wayland): create proxy socket in /run/user/<uid>/ (user_tmp_t) instead of
  /run/sudo-logger/ (sudo_shipper_var_run_t); SELinux silently denies unconfined_t
  from connecting to sudo_shipper_var_run_t sockets, causing gvim to fall back to
  X11 and bypass the proxy entirely

* Fri Apr 17 2026 sudo-logger 1.17.3-1
- fix(service): ProtectHome=read-only + ReadWritePaths=/run/user so the
  wayland-proxy child can connect() to the compositor socket in /run/user/<uid>/
  (ProtectHome=yes made /run/user inaccessible in the service mount namespace,
  causing EACCES on connect() despite correct DAC ownership)

* Fri Apr 17 2026 sudo-logger 1.17.2-1
- fix(selinux): allow sudo_shipper_t to connectto unconfined_t unix sockets
  (compositor kwin/mutter runs as unconfined_t; denial was suppressed by dontaudit)
- fix(wayland): kill lingering wayland-proxy when session ends via deferred killProxy

* Fri Apr 17 2026 sudo-logger 1.17.1-1
- fix(wayland): SetUnlinkOnClose(false) before ln.Close() so the socket
  file stays on disk for gvim to connect; proxy goroutine removes it on exit

* Fri Apr 17 2026 sudo-logger 1.17.0-1
- fix(wayland): shipper creates proxy socket in /run/sudo-logger/ (always
  writable) and passes the fd to wayland-proxy via ExtraFiles; proxy no
  longer needs to bind in /run/user/<uid>/ which is read-only for child
  processes due to ProtectSystem=strict in the service unit

* Fri Apr 17 2026 sudo-logger 1.16.9-1
- fix(selinux): allow proxy to bind/unlink its socket in /run/user/<uid>/
  (user_tmp_t:dir write+add_name+remove_name, sock_file create+unlink)

* Fri Apr 17 2026 sudo-logger 1.16.8-1
- fix: pass user_uid/user_gid from plugin via SESSION_START; shipper uses
  them directly — no /etc/passwd read, works with SSSD/LDAP

* Fri Apr 17 2026 sudo-logger 1.16.6-1
- fix(selinux): add setuid/setgid capability and user_tmp_t getattr so
  shipper can drop privileges to the invoking user when spawning wayland-proxy

* Fri Apr 17 2026 sudo-logger 1.16.5-1
- fix: resolve UID/GID from XDG_RUNTIME_DIR path instead of os/user.Lookup
  (NSS not available in systemd service environment)

* Fri Apr 17 2026 sudo-logger 1.16.4-1
- fix: run wayland-proxy as invoking user (not root) so it can connect
  to the compositor socket in /run/user/<uid>/; proxy socket moved to
  /run/user/<uid>/sudo-wayland-<sessionid>.sock

* Fri Apr 17 2026 sudo-logger 1.16.3-1
- fix: install /etc/sudoers.d/sudo-logger-wayland with env_keep for
  WAYLAND_DISPLAY and XDG_RUNTIME_DIR; sudo env_reset stripped these
  variables so the wayland-proxy socket was never passed to GUI commands

* Fri Apr 17 2026 sudo-logger 1.16.2-1
- fix(plugin): read WAYLAND_DISPLAY and XDG_RUNTIME_DIR from
  /proc/self/environ instead of user_env[]; sudo env_reset strips
  WAYLAND_DISPLAY before the I/O plugin open() callback sees user_env[]

* Fri Apr 17 2026 sudo-logger 1.16.1-1
- fix: start wayland-proxy whenever WAYLAND_DISPLAY is set, not only when
  tty_path is empty; "sudo gvim" from a terminal was never captured because
  it has both a pty and WAYLAND_DISPLAY set

* Fri Apr 17 2026 sudo-logger 1.16.0-1
- feat: Wayland proxy screen capture for GUI sudo sessions (no pty)
  - new wayland-proxy binary intercepts wl_surface_commit, captures SHM
    pixel data, JPEG-encodes frames at up to 2 fps, streams to shipper
  - plugin sends WAYLAND_DISPLAY + XDG_RUNTIME_DIR in SESSION_START;
    patches user_env[] with proxy socket path from SESSION_READY body
  - shipper spawns wayland-proxy for GUI sessions and forwards frames
    as STREAM_SCREEN (0x05) chunks; zero extra client packages required

* Tue Apr 14 2026 sudo-logger 1.15.5-1
- security: raise SIEM client TLS minimum version from 1.2 to 1.3
- security: server rejects SESSION_START payloads exceeding 64 KB
  (MaxSessionStartPayload constant added to protocol package)
- fix: cgroup child-process tracker polls every 50 ms instead of 10 ms
- fix: lingerCgroup reachability check uses plain TCP dial, not full TLS
- fix: schema versioning in distributed store — DDL skipped on restart
  when version already matches (no client-side effect)
- refactor: deduplicated riskLevel, reportSessionMsg, WatchSessions goto

* Tue Apr 14 2026 sudo-logger 1.15.4-1
- fix: cgroup child-process tracker polls every 50 ms instead of 10 ms,
  reducing CPU overhead during frozen sessions
- fix: lingerCgroup reachability check is now a plain TCP dial instead of a
  full TLS handshake, preventing certificate-load errors during network outage
- refactor: extract shared reportSessionMsg helper; SESSION_FREEZING and
  SESSION_ABANDON are now one-liners (no logic change)

* Tue Apr 14 2026 sudo-logger 1.15.3-1
- fix: lower -freeze-timeout default from 5 min to 3 min; SESSION_FREEZING
  is sent at 800 ms so the replay network_outage distinction is unaffected,
  but users no longer wait up to 5 min for a frozen session to terminate

* Mon Apr 13 2026 sudo-logger 1.15.2-1
- fix: set serverConnAlive=false before closing server connection on
  SESSION_END so the heartbeat goroutine cannot fire markDead() after a
  clean session end and send a spurious SESSION_FREEZING — prevents all
  normal sessions being incorrectly marked as network_outage in replay UI

* Mon Apr 13 2026 sudo-logger 1.15.1-1
- fix: restore FREEZE_MSG write in plugin monitor_thread as fallback;
  shipper direct TTY write is primary (immediate), plugin write fires
  on fg resume as reminder

* Mon Apr 13 2026 sudo-logger 1.15.0-1
- fix: write FREEZE_MSG directly to TTY from shipper at markDead() time
  so the banner appears immediately even when sudo is auto-backgrounded
  by SIGSTOP job-control propagation; tty_path sent in SESSION_START

* Mon Apr 13 2026 sudo-logger 1.14.0-1
- feat: send SESSION_FREEZING (0x0f) on first network loss (~800 ms after
  markDead) so the server can mark the session as network-outage rather
  than shipper-killed; SESSION_ABANDON (0x0e) kept as fallback

* Sun Apr 12 2026 sudo-logger 1.13.0-1
- feat: freeze-timeout watchdog in shipper terminates frozen sessions after
  configurable duration of server unreachability (default 5 min, flag:
  -freeze-timeout); prevents permanent hangs when the TCP connection to the
  log server dies (OS retransmission timer expired)
- feat: new FREEZE_TIMEOUT protocol message (0x0d) sent from shipper to
  plugin before closing the connection; plugin distinguishes this from a
  plain shipper death and shows a distinct amber banner:
  "gave up waiting for log server — session terminated"
- feat: plugin calls unfreeze_session_cgroup() on receiving FREEZE_TIMEOUT
  (or any shipper death) to ensure the cgroup is thawed before sending
  SIGTERM — guarantees the signal reaches the frozen shell

* Tue Apr 07 2026 sudo-logger 1.12.2-1
- fix: suppress technical error detail in SESSION_ERROR banner — DNS errors
  and other infrastructure messages are drained but not shown on the terminal;
  only the "cannot reach log server" header is displayed

* Tue Apr 07 2026 sudo-logger 1.12.1-1
- fix: suppress "sudo: error initializing I/O plugin" on SESSION_DENIED and
  SESSION_ERROR — plugin calls _exit(1) after displaying the banner instead of
  returning -1, so sudo never reaches its own error-message code path

* Mon Apr 06 2026 sudo-logger 1.12.0-1
- feat: block users from sudo via central policy (SESSION_DENIED protocol msg)
  - plugin handles MSG_SESSION_DENIED (0x0c) with distinct red banner
  - shipper waits for server handshake (SERVER_READY/SESSION_DENIED) before
    sending SESSION_READY to plugin; reuses bufio.Reader to avoid byte loss
  - adds ARCHITECTURE.md

* Sat Apr 04 2026 sudo-logger 1.11.0-1
- feat: terminal dimensions (rows/cols) captured from command_info[] and sent
  in SESSION_START; stored in session.cast header for accurate replay

* Fri Apr 03 2026 sudo-logger 1.10.0-1
- security: cgroup namespace isolation via unshare(CLONE_NEWCGROUP) in plugin
  Child processes see the session cgroup as /sys/fs/cgroup root; cannot
  self-migrate to escape cgroup.freeze even with CAP_SYS_ADMIN

* Sat Mar 21 2026 sudo-logger 1.9.1-1
- fix: replace atoi with strtol for runas_uid/runas_gid in plugin (CWE-190)
- fix: propagate write errors in iolog log header (fmt.Fprintf, logF.Close)
- fix: log os.Remove error for stale shipper socket on startup
- fix: log json.Encode errors in replay-server HTTP handlers
- chore: add pre-commit hooks (golangci-lint, cppcheck, flawfinder, trivy, detect-secrets)

* Mon Mar 16 2026 sudo-logger 1.9.0-1
- security: plugin terminates active sudo session when shipper socket drops
  (EPIPE/ECONNRESET/EOF); monitor thread sends SIGTERM to sudo within 150 ms,
  I/O hooks return 0 immediately — closes the logging gap where an existing
  session continued unlogged after the shipper was killed

* Mon Mar 16 2026 sudo-logger 1.8.0-2
- fix: use systemctl kill in %%postun instead of %%systemd_postun_with_restart
  to bypass RefuseManualStop=yes during RPM upgrade

* Mon Mar 16 2026 sudo-logger 1.8.0-1
- hardening: complete SELinux policy for sudo_shipper_t (enforcing mode)
- hardening: fix RefuseManualStop=yes placement (must be in [Unit] section)
- hardening: remove ProtectControlGroups=yes (conflicts with Delegate=yes)
- hardening: raise SELinuxContext MCS range to s0-s0:c0.c1023

* Mon Mar 16 2026 sudo-logger 1.7.0-4
- hardening: %pre removes chattr +i before upgrade, %posttrans re-applies it
- hardening: %preun removes chattr +i before uninstall so RPM can delete files
- plugin binary and sudo-shipper are now immutable after install/upgrade

* Mon Mar 16 2026 sudo-logger 1.7.0-3
- hardening: add RefuseManualStop=yes to sudo-shipper.service
- hardening: add PrivateDevices, ProtectKernelTunables, ProtectKernelModules,
  ProtectControlGroups, LockPersonality, RestrictNamespaces, RestrictSUIDSGID

* Sun Mar 15 2026 sudo-logger 1.7.0-2
- security: add SOCK_CLOEXEC to shipper socket so child process cannot inherit it
- security: increase session ID buffer 128→320 bytes to prevent random suffix truncation
- fix: refresh_ack_cache drains extra socket bytes to prevent protocol desync
- cleanup: remove redundant serverBuf.Flush() after WriteMessage in shipper

* Sun Mar 15 2026 sudo-logger 1.7.0-1
- feat: SESSION_START now includes resolved_command (full binary path),
  runas_user, runas_uid, runas_gid, cwd, and sudo flags (login_shell,
  preserve_env, implied_shell) — enables accurate replay metadata

* Sun Mar 15 2026 sudo-logger 1.6.0-2
- add man pages: sudo-shipper(8), sudo_logger_plugin(8)

* Sat Mar 14 2026 sudo-logger 1.6.0-1
- security: ACK signature now binds to session ID (prevents cross-session replay)
- security: session ID uses nanoseconds + 4 random bytes (eliminates collision risk)
- security: plugin socket verifies peer UID==0 via SO_PEERCRED
- security: cgroup name validated before directory creation (path traversal)
- security: plugin socket read timeout (SO_RCVTIMEO 30s, prevents sudo hang)
- fix: ackDebtStartNs reset on HEARTBEAT_ACK (prevents false freeze banner)
- fix: replay server uses EvalSymlinks for path traversal defence
- security: session ID validated on server before creating iolog directory

* Sat Mar 14 2026 sudo-logger 1.5.0-1
- security: replace shared HMAC-SHA256 with ed25519 asymmetric ACK signing
- shipper uses public key only (ack-verify.key); private key stays on server
- ACK payload: 48 --> 80 bytes (64-byte ed25519 signature)
- --hmackey replaced by --verifykey (shipper) and --signkey (server)

* Sat Mar 14 2026 sudo-logger 1.4.1-1
- fix: handle snprintf negative return before uint32_t cast in plugin_open
- fix: g_monitor_stop changed from volatile int to _Atomic int for correct C11 memory ordering
* Thu Mar 12 2026 sudo-logger 1.4.0-1
- Version bump to stay in sync with replay (no client-side changes)

* Thu Mar 12 2026 sudo-logger 1.3.1-1
- plugin: fix terminal trap when user does "fg" into a cgroup-frozen bash
  session; monitor thread now reclaims terminal foreground (tcsetpgrp) every
  150 ms while frozen so Ctrl+C/Z remain functional

* Mon Mar 09 2026 sudo-logger 1.3.0-1
- New versioning: all packages now use MAJOR.MINOR.PATCH (semver) aligned
  with the GitHub release tag; RPM Release resets to 1 for each new Version
- plugin: capture full argv array in SESSION_START (all arguments, not just
  argv[0]); full command now visible in sudoreplay and web replay interface
- Codebase audit: remove dead code, fix nil-ptr dereference, add unit tests
- Translate config file comments to English; fix Makefile install path
- Web replay interface layout fix: terminal fills full available area

* Mon Mar 09 2026 sudo-logger 1.1-26
- plugin: capture full argv (all arguments) in SESSION_START, not just argv[0];
  command with options now visible in sudoreplay and the web replay interface

* Mon Mar 09 2026 sudo-logger 1.1-25
- Remove dead code: displaySocketInodes/isGUIApp were defined but never called
- Add unit tests for protocol and iolog packages
- Fix README: plugin-side freeze description was wrong (plugin only shows
  banners; cgroup.freeze in shipper does the actual freezing)
- Fix Makefile install path (/usr/lib/sudo → /usr/libexec/sudo)
- Translate shipper.conf comments to English
- Add function-level doc comments to plugin.c

* Sun Mar 08 2026 sudo-logger 1.1-24
- Security: fix nil-ptr dereference in server on malformed SESSION_END
- Security: reject duplicate session IDs in server (prevents file handle leak)
- Log integrity: strip newlines from command field in iolog log file
- iolog Close() now returns real file close errors
- Dead code: remove broken GUI socket detection (displaySocketInodes/isGUIApp)
- Dead code: remove unused g_conv from plugin
- Dead code: remove unused AckResponse struct from protocol

* Sun Mar 08 2026 sudo-logger 1.1-23
- Show styled ANSI banner on /dev/tty when log server is unreachable at
  startup (matches freeze banner style); fall back to plain g_printf for
  non-TTY invocations

* Sun Mar 08 2026 sudo-logger 1.1-22
- Fix bash being suspended during freeze: escaped processes that share bash's
  process group are dropped from tracking (no SIGSTOP); only processes with
  their own process group (pgid==pid, e.g. gvim after setsid) are SIGSTOP'd
  directly via syscall.Kill — never via signalGroup — so bash is never hit

* Sun Mar 08 2026 sudo-logger 1.1-21
- Show freeze banner immediately when session is suspended, not only on fg
- Add "Waiting for log server to come back" line to freeze message
- Repeat freeze banner every ~3 s so it stays visible after fg attempts

* Sun Mar 08 2026 sudo-logger 1.1-20
- Add -debug flag to sudo-shipper to suppress verbose cgroup operational logging

* Sat Mar 07 2026 sudo-logger 1.0-1
- Initial release
