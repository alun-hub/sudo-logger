Name:           sudo-logger-replay
Version:        1.10.2
Release:        1%{?dist}
Summary:        Web interface for replaying sudo session logs

License:        MIT
Source0:        sudo-logger-%{version}.tar.gz

BuildRequires:  golang

%global debug_package %{nil}

Requires:       systemd
Requires:       sudo-logger-server

%description
Browser-based session replay interface for sudo-logserver.
Reads iolog directories in /var/log/sudoreplay and serves a terminal
player with play/pause, scrubbing, and speed control.

Access on http://localhost:8080 — restrict to management network.

%prep
%setup -q -n sudo-logger-%{version}

%build
cd go
go build -o sudo-replay-server ./cmd/replay-server

%install
install -D -m 0755 go/sudo-replay-server \
    %{buildroot}%{_bindir}/sudo-replay-server

install -D -m 0644 sudo-replay.service \
    %{buildroot}%{_unitdir}/sudo-replay.service

install -D -m 0664 go/cmd/replay-server/risk-rules.yaml \
    %{buildroot}%{_sysconfdir}/sudo-logger/risk-rules.yaml

# Man page
install -D -m 0644 man/sudo-replay-server.8 \
    %{buildroot}%{_mandir}/man8/sudo-replay-server.8

%post
%systemd_post sudo-replay.service
# Ensure the replay service can write the rules file (fix pre-1.10.0 installs)
chown root:sudologger %{_sysconfdir}/sudo-logger/risk-rules.yaml 2>/dev/null || :
chmod 0664            %{_sysconfdir}/sudo-logger/risk-rules.yaml 2>/dev/null || :

%preun
%systemd_preun sudo-replay.service

%postun
%systemd_postun_with_restart sudo-replay.service

%files
%{_bindir}/sudo-replay-server
%{_unitdir}/sudo-replay.service
%config(noreplace) %attr(0664, root, sudologger) %{_sysconfdir}/sudo-logger/risk-rules.yaml
%{_mandir}/man8/sudo-replay-server.8*

%changelog
* Thu Apr 03 2026 sudo-logger 1.10.2-1
- feat: HTTP Basic Auth (-auth user:bcrypt-hash) with bcrypt password hashing
- feat: TLS support (-tls-cert/-tls-key, TLS 1.2+)
- feat: trusted user header (-trusted-user-header) for proxy-authenticated deployments
- feat: access logging with authenticated username on every request

* Thu Apr 03 2026 sudo-logger 1.10.1-1
- fix: risk-rules.yaml owned root:sudologger 0664 so the replay service
  can write it via the Settings UI (was root:root 0644 — permission denied)
- fix: keyboard shortcuts no longer intercept input in modal fields
  (Swedish keyboard: physical minus key has e.code Slash, was caught by
  the / shortcut handler with preventDefault)
- feat: Help tab explaining risk rule fields, AND/OR logic and examples
- docs: RULE FILE section added to sudo-replay-server(8) man page

* Thu Apr 02 2026 sudo-logger 1.10.0-1
- feat: risk scoring for sessions (0-100) based on configurable YAML rules
- Rules match against sudo command line and ttyout content for shell sessions
- Covers audit/logging tampering, auth manipulation, firewall, persistence
- Scores cached in risk.json per session; auto-invalidated on rule changes
- UI: risk badges on session cards, Risk sort, info-bar risk row,
  High Risk/Critical summary cards, risk column in anomalies table,
  new high_risk anomaly kind
- New config file: /etc/sudo-logger/risk-rules.yaml

* Sun Mar 29 2026 sudo-logger 1.9.2-1
- feat: add Summary and Anomalies tabs with /api/report endpoint
  (per-user stats, incomplete/after-hours/long-session/root-shell detection)

* Sat Mar 21 2026 sudo-logger 1.9.1-1
- fix: log json.Encode errors in HTTP handlers

* Mon Mar 16 2026 sudo-logger 1.8.0-1
- feat: show INCOMPLETE badge and warning bar for sessions where shipper
  was killed mid-session (connection dropped without session_end)

* Sun Mar 15 2026 sudo-logger 1.7.0-8
- feat: light mode uses One Light colour scheme (UI + terminal)

* Sun Mar 15 2026 sudo-logger 1.7.0-7
- feat: terminal also switches theme (light/dark) when toggling mode

* Sun Mar 15 2026 sudo-logger 1.7.0-6
- feat: light/dark mode toggle in topbar; preference saved in localStorage

* Sun Mar 15 2026 sudo-logger 1.7.0-5
- perf: in-memory session index with 30s TTL eliminates per-request directory scan
- perf: ttyout/ttyin read as streaming chunks (io.ReadFull) instead of full os.ReadFile

* Sun Mar 15 2026 sudo-logger 1.7.0-4
- fix: call fitAddon.fit() after term.reset() so terminal renders on first card select

* Sun Mar 15 2026 sudo-logger 1.7.0-3
- fix: race condition — stale fetch response no longer overwrites active session

* Sun Mar 15 2026 sudo-logger 1.7.0-2
- fix: revert date range inputs to type=date (native calendar picker)

* Sun Mar 15 2026 sudo-logger 1.7.0-1
- feat: /api/sessions now returns cwd field per session

* Sun Mar 15 2026 sudo-logger 1.6.0-2
- add man page: sudo-replay-server(8)

* Sat Mar 14 2026 sudo-logger 1.6.0-1
- fix: replay server uses EvalSymlinks for path traversal defence via symlinks
- Version bump to stay in sync with client and server

* Sat Mar 14 2026 sudo-logger 1.5.0-1
- security: replace shared HMAC-SHA256 with ed25519 asymmetric ACK signing
- shipper uses public key only (ack-verify.key); private key stays on server
- ACK payload: 48 --> 80 bytes (64-byte ed25519 signature)
- --hmackey replaced by --verifykey (shipper) and --signkey (server)

* Sat Mar 14 2026 sudo-logger 1.4.1-1
- Version bump to align with client 1.4.1 (no replay-server changes)
* Thu Mar 12 2026 sudo-logger 1.4.0-1
- Web UI: sort sessions by date/user/host/duration with direction toggle
- Web UI: date range filter (from/to) in sidebar
- Web UI: deep link — URL tracks selected session and playback position (?tsid=&t=)
- Web UI: search highlighting marks matched terms in user/host/command
- Web UI: AND search — space-separated terms all must match (e.g. "alun dnf")
- Web UI: load more pagination (200 sessions per page, server-side)
- Web UI: playback speed persisted in localStorage
- Web UI: / key focuses search; date/duration colors improved
- Backend: server-side filtering, sorting and pagination for /api/sessions

* Thu Mar 12 2026 sudo-logger 1.3.1-1
- Version bump to stay in sync with client (no replay-side changes)

* Mon Mar 09 2026 sudo-logger 1.3.0-1
- New versioning: all packages now use MAJOR.MINOR.PATCH (semver) aligned
  with the GitHub release tag; RPM Release resets to 1 for each new Version
- Terminal player fills full available area (min-height:0, min-width:0)
- Scrubber/progress bar extends to full window width
- SVG mockup of web UI added to README and presentation slide
- Presentation gains Web Replay Interface slide (7 slides total)

* Mon Mar 09 2026 sudo-logger 1.1-2
- Fix JSON null serialization: initialize slices with make() so empty session/event
  lists serialize as [] instead of null, preventing JS crash on first load

* Mon Mar 09 2026 sudo-logger 1.1-1
- Initial release
