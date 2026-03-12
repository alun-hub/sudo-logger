Name:           sudo-logger-replay
Version:        1.3.1
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

%post
%systemd_post sudo-replay.service

%preun
%systemd_preun sudo-replay.service

%postun
%systemd_postun_with_restart sudo-replay.service

%files
%{_bindir}/sudo-replay-server
%{_unitdir}/sudo-replay.service

%changelog
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
