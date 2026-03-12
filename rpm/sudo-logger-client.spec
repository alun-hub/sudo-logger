Name:           sudo-logger-client
Version:        1.3.1
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
go build -o sudo-shipper ./cmd/shipper

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

%pre
# Nothing needed on client

%post
# Add plugin line to sudo.conf if not already present
if ! grep -q 'Plugin sudo_logger_plugin sudo_logger_plugin.so' /etc/sudo.conf 2>/dev/null; then
    echo 'Plugin sudo_logger_plugin sudo_logger_plugin.so' >> /etc/sudo.conf
fi
%systemd_post sudo-shipper.service

%preun
%systemd_preun sudo-shipper.service
# Remove plugin line from sudo.conf on uninstall
if [ $1 -eq 0 ]; then
    sed -i '/Plugin sudo_logger_plugin sudo_logger_plugin\.so/d' /etc/sudo.conf
fi

%postun
%systemd_postun_with_restart sudo-shipper.service

%files
%{_libexecdir}/sudo/sudo_logger_plugin.so
%{_bindir}/sudo-shipper
%{_unitdir}/sudo-shipper.service
%dir %attr(0750, root, root) %{_sysconfdir}/sudo-logger
%config(noreplace) %attr(0640, root, root) %{_sysconfdir}/sudo-logger/shipper.conf

%changelog
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
