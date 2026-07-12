# Network, Security & Firewall

## Network topology

```
  ┌──────────────────────────────────────────────────────────────┐
  │ Monitored host                                               │
  │                                                              │
  │  sudo process                                                │
  │      │ fork + exec                                           │
  │      ▼                                                       │
  │  sudo_logger_plugin.so                                       │
  │      │ Unix socket IPC                                       │
  │      ▼                                                       │
  │  sudo-logger-agent ────────── mTLS TCP :9876 ──────────────►│
  │                                                              │
  └──────────────────────────────────────────────────────────────┘
                                                                  │
                                        ┌─────────────────────────┘
                                        ▼
                              ┌─────────────────────┐
                              │  sudo-logserver      │
                              │  :9876 (mTLS)        │
                              │  :9877 (plain HTTP)  │◄──────────┐
                              │                      │            │
                              │  /var/log/sudoreplay │            │
                              └──────────────────────┘            │
                                                                   │
                              ┌───────────────────────┐            │
                              │  sudo-replay-server    │───────────┘
                              │  :8080 (HTTP or HTTPS) │
                              └───────────────────────┘
                                         ▲
                                    browsers
```

---

## Complete port reference

| Port | Protocol | From | To | Purpose | Required |
|---|---|---|---|---|---|
| 9876 | TCP (mTLS) | `sudo-logger-agent` | `sudo-logserver` | Session data streaming + ACK responses | Yes |
| 9877 | TCP (plain HTTP) | `sudo-replay-server`, monitoring tools | `sudo-logserver` | `/healthz`, `/metrics`, JIT approval API (`/api/approvals`) | No — required only for JIT approvals and metrics |
| 8080 | TCP (HTTP or HTTPS) | Browsers, Ingress | `sudo-replay-server` | Web UI, REST API | Yes |
| `/run/sudo-logger/plugin.sock` | Unix stream socket | `sudo_logger_plugin.so` | `sudo-logger-agent` | Local plugin↔agent IPC (same host) | Yes |

> **Note:** Port 9877 is enabled only when `--health-listen` is passed to `sudo-logserver`. When empty (the default), the health/metrics/approval endpoint is disabled entirely.

---

## Mutual TLS (mTLS)

### How mTLS works in sudo-logger

Every connection from an agent to the log server uses mutual TLS (TLS 1.3 minimum):

1. **Agent** opens a TCP connection to `logserver:9876`.
2. **TLS handshake**: the log server presents `server.crt`. The agent verifies it against `ca.crt`.
3. **Client authentication**: the agent presents `client.crt`. The log server verifies it against `ca.crt` using `tls.RequireAndVerifyClientCert`.
4. After the handshake, all session data and ACK messages travel inside the encrypted tunnel.

From `go/cmd/server/main.go`:

```go
return &tls.Config{
    Certificates: []tls.Certificate{cert},
    ClientCAs:    pool,
    ClientAuth:   tls.RequireAndVerifyClientCert,
    MinVersion:   tls.VersionTLS13,
}, nil
```

The log server rejects any connection that does not present a client certificate signed by the configured CA. There is no fallback to unauthenticated access.

Default certificate paths:

| Flag | Default path | Purpose |
|---|---|---|
| `-cert` | `/etc/sudo-logger/server.crt` | Server TLS certificate (presented to agents) |
| `-key` | `/etc/sudo-logger/server.key` | Server TLS private key |
| `-ca` | `/etc/sudo-logger/ca.crt` | CA certificate (used to verify client certs) |

Agent certificate paths (in `/etc/sudo-logger/agent.conf`):

| Config key | Default path | Purpose |
|---|---|---|
| `Cert` | `/etc/sudo-logger/client.crt` | Client certificate (presented to server) |
| `Key` | `/etc/sudo-logger/client.key` | Client private key |
| `CA` | `/etc/sudo-logger/ca.crt` | CA certificate (used to verify server cert) |

### --strict-cert-host

When the log server is started with `--strict-cert-host`, it extracts the CN and DNS SANs from the client's TLS certificate and compares them against the `host` field in the `SESSION_START` message that the agent sends when a sudo session begins.

If the certificate identity does not match the claimed hostname, the session is rejected.

```
-strict-cert-host  (default: false)
```

From the source:

> "Reject sessions where the claimed host does not match the client certificate CN/SAN. Requires per-machine client certificates. Off by default to support shared-cert setups."

| Mode | Cert type | Impersonation prevention | Management |
|---|---|---|---|
| Default (off) | One shared cert for all agents | None | Simple |
| `--strict-cert-host` | One cert per machine (CN = hostname) | Yes — server validates cert identity | Requires per-host PKI |

Use `--strict-cert-host` in high-assurance environments where agents should not be able to log sessions under another host's identity.

**Recommendation:** the default is off deliberately — flipping it would break any deployment already using a single shared client certificate across hosts (this is a supported, documented configuration, not an oversight). For a new deployment, or one where per-host identity actually matters (multi-tenant hosts, compliance requirements, or any environment where one compromised host impersonating another is a real concern), mint one client certificate per host and enable `--strict-cert-host` from the start — retrofitting per-host certs onto an existing shared-cert fleet later is more work than starting that way.

### Replay server HTTPS

The replay server supports HTTPS via `--tls-cert` and `--tls-key`:

```bash
sudo-replay-server \
    -listen    :8080 \
    -tls-cert  /etc/sudo-logger/replay.crt \
    -tls-key   /etc/sudo-logger/replay.key \
    -logdir    /var/log/sudoreplay
```

When both flags are set, the server uses standard TLS (server-only certificate). The replay server does **not** do mTLS with browsers — client authentication is handled at the application level via HTTP Basic Auth (`--htpasswd`), OIDC (`--oidc-issuer`), or a trusted proxy header (`--trusted-user-header`).

In Kubernetes, HTTPS is typically handled by an Ingress controller or the `oauth2-proxy` sidecar rather than by the replay server binary directly.

### ACK signing

The log server signs every ACK message with an ed25519 private key. Agents verify ACKs before releasing a frozen session. This prevents an attacker from injecting fake ACK messages to unfreeze a session that is waiting for JIT approval.

| Component | Key | Flag |
|---|---|---|
| Log server | Private key (ed25519, PKCS8 PEM) | `-signkey` (default: `/etc/sudo-logger/ack-sign.key`) |
| Agent | Public key (PEM) | `VerifyKey` in `agent.conf` (default: `/etc/sudo-logger/ack-verify.key`) |

Generate the key pair:

```bash
openssl genpkey -algorithm ed25519 -out /etc/sudo-logger/ack-sign.key
openssl pkey -in /etc/sudo-logger/ack-sign.key -pubout \
    -out /etc/sudo-logger/ack-verify.key
chmod 600 /etc/sudo-logger/ack-sign.key
```

Distribute `ack-verify.key` to every agent host.

---

## SELinux

### The sudo-logger SELinux policy module

sudo-logger ships a type enforcement (TE) policy module that grants the agent the permissions it requires while keeping it confined. The policy is compiled into `sudo_logger.pp` and installed automatically by the `sudo-logger-client` RPM `%post` scriptlet.

Source: `selinux/sudo_logger.te` in the repository.

Check that the module is loaded:

```bash
semodule -l | grep sudo
# sudo_logger    1.1.20
```

### Policy module overview

The module defines four types:

| Type | Purpose |
|---|---|
| `sudo_agent_t` | Domain for the `sudo-logger-agent` process |
| `sudo_agent_exec_t` | The agent binary (`/usr/bin/sudo-logger-agent`) |
| `sudo_agent_var_run_t` | Files under `/run/sudo-logger/` (PID file, Unix socket) |
| `sudo_agent_etc_t` | Files under `/etc/sudo-logger/` (certs, keys, config) |
| `sudo_logger_plugin_t` | The plugin `.so` file loaded by sudo |

### Key permissions granted

**eBPF operations** (required for session recording and the BPF LSM sandbox):

```
allow sudo_agent_t self:bpf { map_create map_read map_write prog_load prog_run };
allow sudo_agent_t self:perf_event { open read write tracepoint cpu kernel };
allow sudo_agent_t self:capability2 { bpf perfmon };
```

**Capabilities** (required for cgroup management, process tracing, file access):

```
allow sudo_agent_t self:capability {
    kill net_bind_service sys_admin sys_ptrace
    setuid setgid dac_override dac_read_search chown fowner
};
```

**Cgroup management** (used to freeze sessions awaiting JIT approval):

```
fs_manage_cgroup_dirs(sudo_agent_t)
fs_rw_cgroup_files(sudo_agent_t)
allow sudo_agent_t cgroup_t:dir { write add_name remove_name create rmdir };
allow sudo_agent_t cgroup_t:file { create };
```

**Unix socket** between plugin and agent (in `/run/sudo-logger/`):

```
manage_sock_files_pattern(sudo_agent_t, sudo_agent_var_run_t, sudo_agent_var_run_t)
files_pid_filetrans(sudo_agent_t, sudo_agent_var_run_t, { dir file sock_file })

# sudo process connects to the agent socket
allow sudo_t sudo_agent_var_run_t:sock_file write;
allow sudo_t sudo_agent_t:unix_stream_socket connectto;
```

**debugfs / tracefs** (required for eBPF tracepoint attachment):

```
allow sudo_agent_t tracefs_t:file { read open getattr write create unlink };
allow sudo_agent_t debugfs_t:file { read open getattr };
```

**BTF support** (required to load eBPF programs on modern kernels):

```
allow sudo_agent_t sysfs_t:file { read open getattr map };
```

**TLS outbound connection** to the log server:

```
corenet_tcp_connect_generic_port(sudo_agent_t)
```

### Reinstalling the policy module

```bash
semodule -i /usr/share/selinux/packages/sudo_logger.pp
```

### Troubleshooting SELinux denials

```bash
# Show recent AVC denials related to sudo-logger
ausearch -m avc -ts recent | grep sudo

# Generate a human-readable report with suggested fixes
sealert -a /var/log/audit/audit.log

# Preview what new rules would be needed (do not apply automatically)
audit2allow -a
```

Common causes of SELinux denials:

| Symptom | Likely cause |
|---|---|
| Agent fails to start | Policy module not loaded — run `semodule -i sudo_logger.pp` |
| eBPF fails to load with SELinux enforcing | Missing `bpf` / `perf_event` permissions — check policy version |
| Socket permission denied | `sudo_t` not allowed to connect to `sudo_agent_var_run_t:sock_file` |
| cgroup freeze fails | `cgroup_t` write permissions missing |

---

## Systemd security hardening

The `sudo-logger-agent` systemd unit runs as `root` because eBPF tracing (`CAP_BPF`, `CAP_SYS_PTRACE`, `CAP_SYS_ADMIN`) requires elevated privileges. Conventional systemd sandboxing directives that create private mount namespaces (e.g., `PrivateTmp`, `PrivateDevices`, `ProtectKernelTunables`) conflict with `inotify_add_watch` on `/etc` and `/proc/sys` paths inside the service's namespace. The BPF LSM sandbox (kernel-level enforcement) is the meaningful confinement boundary.

From `sudo-logger-agent.service`:

```ini
[Unit]
Description=sudo-logger audit agent (plugin handler + eBPF recorder)
After=systemd-logind.service network-online.target
Wants=network-online.target
RefuseManualStop=yes

[Service]
ExecStart=/usr/bin/sudo-logger-agent -config /etc/sudo-logger/agent.conf
KillMode=process
Restart=always
RestartSec=2
User=root
ReadWritePaths=/sys/fs/bpf
```

The `ReadWritePaths=/sys/fs/bpf` directive grants the agent write access to the BPF filesystem (required for pinning BPF programs and maps), while the implicit `ReadOnlyPaths=/` default restricts all other paths to read-only within any systemd sandboxing that applies.

`RefuseManualStop=yes` blocks `systemctl stop sudo-logger-agent`. This closes the attack vector where a user with sudo access stops the agent to avoid having their session recorded. Any attempt to kill the agent from within a sudo session is captured as TTY I/O before the agent dies, making the tampering self-documenting.

The log server and replay server run as the `sudologger` user with tighter sandboxing:

```ini
User=sudologger
Group=sudologger
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/log/sudoreplay
```

---

## File permissions

The following paths must have the correct ownership and mode for sudo-logger to function correctly.

| Path | Owner | Mode | Purpose |
|---|---|---|---|
| `/usr/libexec/sudo/sudo_logger_plugin.so` | root | 0755 | sudo I/O plugin loaded by `sudo` |
| `/usr/bin/sudo-logger-agent` | root | 0755 | Agent binary |
| `/etc/sudo-logger/` | root | 0750 | Configuration directory |
| `/etc/sudo-logger/agent.conf` | root | 0640 | Agent configuration |
| `/etc/sudo-logger/client.crt` | root | 0644 | Agent TLS certificate (public) |
| `/etc/sudo-logger/client.key` | root | 0600 | Agent TLS private key |
| `/etc/sudo-logger/ca.crt` | root | 0644 | CA certificate |
| `/etc/sudo-logger/ack-verify.key` | root | 0644 | ACK public key (agent) |
| `/etc/sudo-logger/server.crt` | root | 0644 | Server TLS certificate (public) |
| `/etc/sudo-logger/server.key` | root | 0600 | Server TLS private key |
| `/etc/sudo-logger/ack-sign.key` | root:sudologger | 0640 | ACK signing private key (server) |
| `/run/sudo-logger/` | root | 0755 | Runtime directory |
| `/run/sudo-logger/plugin.sock` | root | 0660 | Unix socket: plugin ↔ agent |
| `/var/log/sudoreplay/` | sudologger | 0750 | Session file storage |
| `/sys/fs/bpf` | root | 0700 | BPF program/map pinning (agent) |

> **Warning:** Private key files `client.key` and `server.key` must be mode 0600 and owned by root. `ack-sign.key` is the exception — mode 0640, owned `root:sudologger`, since the log server runs as the `sudologger` user and needs group-read access to sign ACKs. Any more permissive mode than documented here allows other processes to read the private key, compromising the mTLS trust chain and ACK signing integrity.
