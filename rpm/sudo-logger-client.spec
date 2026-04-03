Name:           sudo-logger-client
Version:        1.10.0
Release:        1%{?dist}
Summary:        Sudo I/O plugin and shipper for remote session logging

License:        MIT
Source0:        sudo-logger-%{version}.tar.gz

BuildRequires:  gcc
BuildRequires:  sudo-devel
BuildRequires:  golang

# Go binaries via gccgo have non-standard debug info
%global debug_package %{nil}

Requires:       sudo >= 1.9
Requires:       systemd

%description
Sudo I/O plugin (sudo_logger_plugin.so) and local shipper daemon
(sudo-shipper) that together record all sudo sessions and ship them
in real-time to a remote sudo-logger-server instance over mutual TLS.

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

# Build the shipper daemon
cd ../go
/usr/lib/golang/bin/go build -o sudo-shipper ./cmd/shipper

%install
# Plugin
install -D -m 0755 plugin/sudo_logger_plugin.so \
    %{buildroot}%{_libexecdir}/sudo/sudo_logger_plugin.so

# Shipper binary
install -D -m 0755 go/sudo-shipper \
    %{buildroot}%{_bindir}/sudo-shipper

# Systemd service
install -D -m 0644 sudo-shipper.service \
    %{buildroot}%{_unitdir}/sudo-shipper.service

# Config directory (certs placed here by admin)
install -d -m 0750 %{buildroot}%{_sysconfdir}/sudo-logger

# Default client config (LOGSERVER address)
install -D -m 0640 shipper.conf \
    %{buildroot}%{_sysconfdir}/sudo-logger/shipper.conf

# Man pages
install -D -m 0644 man/sudo-shipper.8 \
    %{buildroot}%{_mandir}/man8/sudo-shipper.8
install -D -m 0644 man/sudo_logger_plugin.8 \
    %{buildroot}%{_mandir}/man8/sudo_logger_plugin.8

%pre
# Remove immutable flag from our binaries before RPM writes new files.
# This is needed for upgrades — on first install the files don't exist yet
# so the commands silently fail (|| true).
chattr -i %{_libexecdir}/sudo/sudo_logger_plugin.so 2>/dev/null || true
chattr -i %{_bindir}/sudo-shipper                   2>/dev/null || true

%post
# Add plugin line to sudo.conf if not already present
if ! grep -q 'Plugin sudo_logger_plugin sudo_logger_plugin.so' /etc/sudo.conf 2>/dev/null; then
    echo 'Plugin sudo_logger_plugin sudo_logger_plugin.so' >> /etc/sudo.conf
fi
%systemd_post sudo-shipper.service

%posttrans
# Make plugin binary and shipper immutable so they cannot be silently replaced
# or removed without first running chattr -i (which requires root intent).
chattr +i %{_libexecdir}/sudo/sudo_logger_plugin.so 2>/dev/null || true
chattr +i %{_bindir}/sudo-shipper                   2>/dev/null || true

%preun
# Remove immutable flag so RPM can delete the files on uninstall.
chattr -i %{_libexecdir}/sudo/sudo_logger_plugin.so 2>/dev/null || true
chattr -i %{_bindir}/sudo-shipper                   2>/dev/null || true
%systemd_preun sudo-shipper.service
# Remove plugin line from sudo.conf on uninstall
if [ $1 -eq 0 ]; then
    sed -i '/Plugin sudo_logger_plugin sudo_logger_plugin\.so/d' /etc/sudo.conf
fi

%postun
# On upgrade: reload unit and signal the running shipper to restart.
# We cannot use %%systemd_postun_with_restart / systemctl try-restart because
# RefuseManualStop=yes blocks those operations.  Instead, send SIGTERM via
# systemctl kill (not blocked by RefuseManualStop) and let Restart=always
# pick up the new binary after daemon-reload.
if [ $1 -ge 1 ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl kill sudo-shipper.service >/dev/null 2>&1 || true
else
    systemctl daemon-reload >/dev/null 2>&1 || true
fi

%files
%{_libexecdir}/sudo/sudo_logger_plugin.so
%{_bindir}/sudo-shipper
%{_unitdir}/sudo-shipper.service
%dir %attr(0750, root, root) %{_sysconfdir}/sudo-logger
%config(noreplace) %attr(0640, root, root) %{_sysconfdir}/sudo-logger/shipper.conf
%ghost %attr(0644, root, root) %{_sysconfdir}/sudo-logger/ack-verify.key
%{_mandir}/man8/sudo-shipper.8*
%{_mandir}/man8/sudo_logger_plugin.8*

%changelog
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
