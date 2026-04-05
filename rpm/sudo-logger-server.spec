Name:           sudo-logger-server
Version:        1.11.1
Release:        1%{?dist}
Summary:        Remote log server for sudo session recordings

License:        MIT
Source0:        sudo-logger-%{version}.tar.gz

BuildRequires:  golang

# Go binaries via gccgo have non-standard debug info
%global debug_package %{nil}

Requires:       systemd
Requires(pre):  shadow-utils
Provides:       user(sudologger)
Provides:       group(sudologger)

%description
Remote TLS log server that receives sudo session recordings from
sudo-logger-client instances and stores them for later replay.

%prep
%setup -q -n sudo-logger-%{version}

%build
cd go
/usr/lib/golang/bin/go build -o sudo-logserver ./cmd/server

%install
# Server binary
install -D -m 0755 go/sudo-logserver \
    %{buildroot}%{_bindir}/sudo-logserver

# Systemd service and daily restart timer
install -D -m 0644 sudo-logserver.service \
    %{buildroot}%{_unitdir}/sudo-logserver.service
install -D -m 0644 sudo-logserver-restart.timer \
    %{buildroot}%{_unitdir}/sudo-logserver-restart.timer
install -D -m 0644 sudo-logserver-restart.service \
    %{buildroot}%{_unitdir}/sudo-logserver-restart.service

# Config directory
install -d -m 0750 %{buildroot}%{_sysconfdir}/sudo-logger

# Config file
install -D -m 0640 server.conf \
    %{buildroot}%{_sysconfdir}/sudo-logger/server.conf

# Log directory
install -d -m 0750 %{buildroot}%{_localstatedir}/log/sudoreplay

# Logrotate configuration
install -D -m 0644 sudo-logserver.logrotate \
    %{buildroot}%{_sysconfdir}/logrotate.d/sudo-logserver

# Man page
install -D -m 0644 man/sudo-logserver.8 \
    %{buildroot}%{_mandir}/man8/sudo-logserver.8

%pre
getent group sudologger >/dev/null || groupadd -r sudologger
getent passwd sudologger >/dev/null || \
    useradd -r -g sudologger -s /sbin/nologin \
            -d /var/log/sudoreplay sudologger

%post
%systemd_post sudo-logserver.service sudo-logserver-restart.timer
# Generate ed25519 signing key on first install
if [ ! -f %{_sysconfdir}/sudo-logger/ack-sign.key ]; then
    openssl genpkey -algorithm ed25519 \
        -out %{_sysconfdir}/sudo-logger/ack-sign.key 2>/dev/null
    chown root:sudologger %{_sysconfdir}/sudo-logger/ack-sign.key
    chmod 0640 %{_sysconfdir}/sudo-logger/ack-sign.key
    openssl pkey -in %{_sysconfdir}/sudo-logger/ack-sign.key \
        -pubout -out %{_sysconfdir}/sudo-logger/ack-verify.key 2>/dev/null
    chmod 0644 %{_sysconfdir}/sudo-logger/ack-verify.key
    echo "sudo-logserver: ACK signing key generated."
    echo "  Copy %{_sysconfdir}/sudo-logger/ack-verify.key to all clients."
fi

%preun
%systemd_preun sudo-logserver.service sudo-logserver-restart.timer

%postun
%systemd_postun_with_restart sudo-logserver.service sudo-logserver-restart.timer

%files
%{_bindir}/sudo-logserver
%{_unitdir}/sudo-logserver.service
%{_unitdir}/sudo-logserver-restart.timer
%{_unitdir}/sudo-logserver-restart.service
%dir %attr(0770, root, sudologger) %{_sysconfdir}/sudo-logger
%config(noreplace) %attr(0640, root, sudologger) %{_sysconfdir}/sudo-logger/server.conf
%ghost %attr(0640, root, sudologger) %{_sysconfdir}/sudo-logger/ack-sign.key
%ghost %attr(0644, root, root)       %{_sysconfdir}/sudo-logger/ack-verify.key

%dir %attr(0750, sudologger, sudologger) %{_localstatedir}/log/sudoreplay
%config(noreplace) %{_sysconfdir}/logrotate.d/sudo-logserver
%{_mandir}/man8/sudo-logserver.8*

%changelog
* Sun Apr 05 2026 sudo-logger 1.11.1-1
- fix: /etc/sudo-logger/ mode 0750 → 0770 so sudologger service can create
  new files (siem.yaml, uploaded certs) without requiring root intervention

* Sun Apr 05 2026 sudo-logger 1.11.0-1
- feat: SIEM forwarding — sends session events to external SIEM on session close
- Supports HTTPS (mTLS) and syslog (UDP/TCP/TCP-TLS) transports
- Supports JSON, CEF, and OCSF v1.3.0 (Class 3003) formats
- Config loaded from /etc/sudo-logger/siem.yaml; reloaded automatically every 30s
- New flag: -siem-config (default /etc/sudo-logger/siem.yaml)
- siem.yaml managed via sudo-replay GUI Settings tab

* Sat Apr 04 2026 sudo-logger 1.10.0-1
- feat: sessions stored as asciinema v2 (session.cast) instead of sudoreplay
  multi-file format; all metadata embedded in cast header, no separate meta.json

* Sun Mar 29 2026 sudo-logger 1.9.2-1
- feat: add daily 03:00 restart timer (sudo-logserver-restart.timer) to
  reclaim leaked goroutines and file descriptors from sessions where the
  shipper died without a clean TCP teardown

* Sat Mar 21 2026 sudo-logger 1.9.1-1
- fix: propagate write errors in iolog log header (fmt.Fprintf, logF.Close)

* Mon Mar 16 2026 sudo-logger 1.8.0-1
- security: log SECURITY warning and write INCOMPLETE marker when shipper
  drops connection without session_end (shipper killed mid-session)

* Sun Mar 15 2026 sudo-logger 1.7.0-1
- feat: iolog log file now records actual runas_user and cwd from client
  (previously hardcoded to "root" and "/")
- feat: server log line includes resolved_command, runas uid, and cwd

* Sun Mar 15 2026 sudo-logger 1.6.0-3
- add man page: sudo-logserver(8)

* Sun Mar 15 2026 sudo-logger 1.6.0-2
- fix: cert-vs-host check warns by default, hard-rejects only with -strict-cert-host
  (shared client certificate setups, e.g. CN="sudo-client", were incorrectly rejected)

* Sat Mar 14 2026 sudo-logger 1.6.0-1
- security: ACK signature now binds to session ID (prevents cross-session replay)
- security: host field in SESSION_START verified against TLS client certificate CN/SAN
  (a compromised shipper on host A cannot forge log entries for host B)
- security: session ID validated on server before creating iolog directory
- fix: ackDebtStartNs reset on HEARTBEAT_ACK (prevents false freeze banner)
- fix: replay server uses EvalSymlinks for path traversal defence

* Sat Mar 14 2026 sudo-logger 1.5.0-1
- security: replace shared HMAC-SHA256 with ed25519 asymmetric ACK signing
- shipper uses public key only (ack-verify.key); private key stays on server
- ACK payload: 48 --> 80 bytes (64-byte ed25519 signature)
- --hmackey replaced by --verifykey (shipper) and --signkey (server)

* Sat Mar 14 2026 sudo-logger 1.4.1-1
- Version bump to align with client 1.4.1 (no server changes)
* Thu Mar 12 2026 sudo-logger 1.4.0-1
- Version bump to stay in sync with replay (no server-side changes)

* Thu Mar 12 2026 sudo-logger 1.3.1-1
- Version bump to stay in sync with client (no server-side changes)

* Mon Mar 09 2026 sudo-logger 1.3.0-1
- New versioning: all packages now use MAJOR.MINOR.PATCH (semver) aligned
  with the GitHub release tag; RPM Release resets to 1 for each new Version
- Add logrotate configuration for /var/log/sudoreplay (from 1.1-7)

* Mon Mar 09 2026 sudo-logger 1.1-7
- Add logrotate configuration for /var/log/sudoreplay

* Sat Mar 07 2026 sudo-logger 1.1-1
- Initial release
