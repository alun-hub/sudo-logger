Name:           sudo-logger-client
Version:        1.17.4
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

# Build the shipper daemon and Wayland proxy
cd ../go
/usr/lib/golang/bin/go build -mod=vendor -o sudo-shipper ./cmd/shipper
/usr/lib/golang/bin/go build -mod=vendor -o wayland-proxy ./cmd/wayland-proxy

%install
# Plugin
install -D -m 0755 plugin/sudo_logger_plugin.so \
    %{buildroot}%{_libexecdir}/sudo/sudo_logger_plugin.so

# Shipper binary
install -D -m 0755 go/sudo-shipper \
    %{buildroot}%{_bindir}/sudo-shipper

# Wayland proxy binary (used by shipper for GUI screen capture)
install -d -m 0755 %{buildroot}%{_libexecdir}/sudo-logger
install -D -m 0755 go/wayland-proxy \
    %{buildroot}%{_libexecdir}/sudo-logger/wayland-proxy

# Systemd service
install -D -m 0644 sudo-shipper.service \
    %{buildroot}%{_unitdir}/sudo-shipper.service

# Config directory (certs placed here by admin)
install -d -m 0750 %{buildroot}%{_sysconfdir}/sudo-logger

# Default client config (LOGSERVER address)
install -D -m 0640 shipper.conf \
    %{buildroot}%{_sysconfdir}/sudo-logger/shipper.conf

# Sudoers drop-in: preserve WAYLAND_DISPLAY so the proxy reaches GUI commands
install -D -m 0440 sudo-logger-wayland.sudoers \
    %{buildroot}%{_sysconfdir}/sudoers.d/sudo-logger-wayland

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
%dir %{_libexecdir}/sudo-logger
%{_libexecdir}/sudo-logger/wayland-proxy
%{_unitdir}/sudo-shipper.service
%dir %attr(0750, root, root) %{_sysconfdir}/sudo-logger
%config(noreplace) %attr(0640, root, root) %{_sysconfdir}/sudo-logger/shipper.conf
%ghost %attr(0644, root, root) %{_sysconfdir}/sudo-logger/ack-verify.key
%config(noreplace) %attr(0440, root, root) %{_sysconfdir}/sudoers.d/sudo-logger-wayland
%{_mandir}/man8/sudo-shipper.8*
%{_mandir}/man8/sudo_logger_plugin.8*

%changelog
* Thu Apr 17 2026 sudo-logger 1.17.4-1
- fix(wayland): create proxy socket in /run/user/<uid>/ (user_tmp_t) instead of
  /run/sudo-logger/ (sudo_shipper_var_run_t); SELinux silently denies unconfined_t
  from connecting to sudo_shipper_var_run_t sockets, causing gvim to fall back to
  X11 and bypass the proxy entirely

* Thu Apr 17 2026 sudo-logger 1.17.3-1
- fix(service): ProtectHome=read-only + ReadWritePaths=/run/user so the
  wayland-proxy child can connect() to the compositor socket in /run/user/<uid>/
  (ProtectHome=yes made /run/user inaccessible in the service mount namespace,
  causing EACCES on connect() despite correct DAC ownership)

* Thu Apr 17 2026 sudo-logger 1.17.2-1
- fix(selinux): allow sudo_shipper_t to connectto unconfined_t unix sockets
  (compositor kwin/mutter runs as unconfined_t; denial was suppressed by dontaudit)
- fix(wayland): kill lingering wayland-proxy when session ends via deferred killProxy

* Thu Apr 17 2026 sudo-logger 1.17.1-1
- fix(wayland): SetUnlinkOnClose(false) before ln.Close() so the socket
  file stays on disk for gvim to connect; proxy goroutine removes it on exit

* Thu Apr 17 2026 sudo-logger 1.17.0-1
- fix(wayland): shipper creates proxy socket in /run/sudo-logger/ (always
  writable) and passes the fd to wayland-proxy via ExtraFiles; proxy no
  longer needs to bind in /run/user/<uid>/ which is read-only for child
  processes due to ProtectSystem=strict in the service unit

* Thu Apr 17 2026 sudo-logger 1.16.9-1
- fix(selinux): allow proxy to bind/unlink its socket in /run/user/<uid>/
  (user_tmp_t:dir write+add_name+remove_name, sock_file create+unlink)

* Thu Apr 17 2026 sudo-logger 1.16.8-1
- fix: pass user_uid/user_gid from plugin via SESSION_START; shipper uses
  them directly — no /etc/passwd read, works with SSSD/LDAP

* Thu Apr 17 2026 sudo-logger 1.16.6-1
- fix(selinux): add setuid/setgid capability and user_tmp_t getattr so
  shipper can drop privileges to the invoking user when spawning wayland-proxy

* Thu Apr 17 2026 sudo-logger 1.16.5-1
- fix: resolve UID/GID from XDG_RUNTIME_DIR path instead of os/user.Lookup
  (NSS not available in systemd service environment)

* Thu Apr 17 2026 sudo-logger 1.16.4-1
- fix: run wayland-proxy as invoking user (not root) so it can connect
  to the compositor socket in /run/user/<uid>/; proxy socket moved to
  /run/user/<uid>/sudo-wayland-<sessionid>.sock

* Thu Apr 17 2026 sudo-logger 1.16.3-1
- fix: install /etc/sudoers.d/sudo-logger-wayland with env_keep for
  WAYLAND_DISPLAY and XDG_RUNTIME_DIR; sudo env_reset stripped these
  variables so the wayland-proxy socket was never passed to GUI commands

* Thu Apr 17 2026 sudo-logger 1.16.2-1
- fix(plugin): read WAYLAND_DISPLAY and XDG_RUNTIME_DIR from
  /proc/self/environ instead of user_env[]; sudo env_reset strips
  WAYLAND_DISPLAY before the I/O plugin open() callback sees user_env[]

* Thu Apr 17 2026 sudo-logger 1.16.1-1
- fix: start wayland-proxy whenever WAYLAND_DISPLAY is set, not only when
  tty_path is empty; "sudo gvim" from a terminal was never captured because
  it has both a pty and WAYLAND_DISPLAY set

* Thu Apr 17 2026 sudo-logger 1.16.0-1
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

* Mon Apr 14 2026 sudo-logger 1.15.4-1
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
