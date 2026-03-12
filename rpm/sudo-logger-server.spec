Name:           sudo-logger-server
Version:        1.3.1
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
go build -o sudo-logserver ./cmd/server

%install
# Server binary
install -D -m 0755 go/sudo-logserver \
    %{buildroot}%{_bindir}/sudo-logserver

# Systemd service
install -D -m 0644 sudo-logserver.service \
    %{buildroot}%{_unitdir}/sudo-logserver.service

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

%pre
getent group sudologger >/dev/null || groupadd -r sudologger
getent passwd sudologger >/dev/null || \
    useradd -r -g sudologger -s /sbin/nologin \
            -d /var/log/sudoreplay sudologger

%post
%systemd_post sudo-logserver.service

%preun
%systemd_preun sudo-logserver.service

%postun
%systemd_postun_with_restart sudo-logserver.service

%files
%{_bindir}/sudo-logserver
%{_unitdir}/sudo-logserver.service
%dir %attr(0750, root, sudologger) %{_sysconfdir}/sudo-logger
%config(noreplace) %attr(0640, root, sudologger) %{_sysconfdir}/sudo-logger/server.conf
%dir %attr(0750, sudologger, sudologger) %{_localstatedir}/log/sudoreplay
%config(noreplace) %{_sysconfdir}/logrotate.d/sudo-logserver

%changelog
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
