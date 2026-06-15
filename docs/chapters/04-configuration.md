# Configuration Reference

This chapter documents every configuration option for the three sudo-logger
server-side components: the agent, the log server, and the replay server.
It also covers the sudo plugin configuration in `/etc/sudo.conf`.

---

## Agent configuration

The agent (`sudo-logger-agent`) runs on every monitored host. It receives
session data from the plugin via a Unix socket and forwards it to the log
server over mutual-TLS.

### CLI flag

The agent accepts exactly one command-line flag:

| Flag | Default | Description |
|------|---------|-------------|
| `--config <path>` | `/etc/sudo-logger/agent.conf` | Path to the agent configuration file |

All other settings are read from the configuration file.

### agent.conf format

`agent.conf` uses a simple `Key = Value` format, one setting per line.
Key names are case-insensitive. Lines beginning with `#` are comments.
Unknown keys are silently ignored for backward compatibility.

```
# Example: /etc/sudo-logger/agent.conf
Server         = logserver.example.com:9876
Cert           = /etc/sudo-logger/client.crt
Key            = /etc/sudo-logger/client.key
CA             = /etc/sudo-logger/ca.crt
```

### Complete agent.conf reference

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `Server` | string | `logserver:9876` | Address of the log server in `host:port` form |
| `Socket` | string | `/run/sudo-logger/plugin.sock` | Unix socket path for communication with the sudo plugin |
| `Cert` | string | `/etc/sudo-logger/client.crt` | Client TLS certificate presented to the log server |
| `Key` | string | `/etc/sudo-logger/client.key` | Private key for the client TLS certificate |
| `CA` | string | `/etc/sudo-logger/ca.crt` | CA certificate used to verify the log server's certificate |
| `VerifyKey` | string | `/etc/sudo-logger/ack-verify.key` | Path to the ed25519 public key used to verify ACK signatures from the log server |
| `MaskPatterns` | []string | _(empty)_ | Newline- or comma-separated list of regular expressions; matching content in session output is redacted before forwarding |
| `FreezeTimeout` | duration | `3m` | Duration after which a session with no network progress is terminated (prevents resource leaks from hung connections) |
| `IdleTimeout` | duration | _(none)_ | Duration after which a session with no terminal activity is terminated; zero means no idle timeout |
| `Disclaimer` | string | _(empty)_ | Message displayed to the user at the start of every sudo session |
| `DisclaimerColor` | string | _(empty)_ | ANSI color name or code applied to the disclaimer text (e.g. `yellow`, `red`) |
| `Debug` | bool | `false` | Enable verbose debug logging to stderr |
| `Ebpf` | bool | `true` | Enable eBPF-based session sandbox. Auto-disabled when the kernel lacks BTF support. Set to `false` to disable explicitly |
| `SandboxConfig` | string | _(empty)_ | Path to `sandbox.yaml`; sandbox is disabled when this key is absent or empty |
| `Hostname` | string | _(empty)_ | Override the auto-detected fully-qualified hostname. When empty, the agent resolves the FQDN via `os.Hostname` + reverse DNS lookup |

> **Note:** `MaskPatterns` entries are Go regular expressions. Each pattern is
> matched against the raw byte stream of terminal output. Matched regions are
> replaced with `[REDACTED]` before the data reaches the log server.

> **Note:** Duration values use Go duration syntax: `30s`, `5m`, `1h30m`.

### Example agent.conf

```
# /etc/sudo-logger/agent.conf

# Log server address
Server          = logserver.corp.example.com:9876

# Mutual TLS certificates
Cert            = /etc/sudo-logger/client.crt
Key             = /etc/sudo-logger/client.key
CA              = /etc/sudo-logger/ca.crt

# ACK signature verification
VerifyKey       = /etc/sudo-logger/ack-verify.key

# Redact passwords from output streams
MaskPatterns    = [Pp]assword\s*[:=]\s*\S+

# Kill frozen sessions after 5 minutes
FreezeTimeout   = 5m

# Terminate idle sessions after 30 minutes
IdleTimeout     = 30m

# Show a warning banner at session start
Disclaimer      = WARNING: This session is recorded and audited.
DisclaimerColor = yellow

# eBPF sandbox
Ebpf            = true
SandboxConfig   = /etc/sudo-logger/sandbox.yaml

# Override hostname detection (uncomment if FQDN resolution is unreliable)
# Hostname = myhost.example.com
```

### Configuration priority

Settings are applied in this order (later entries override earlier ones):

1. Built-in defaults (from `defaultConfig()`)
2. Values read from the file specified by `--config`

There are no environment variable overrides for agent configuration. The
`--config` flag itself is typically set in the systemd unit `ExecStart` line
when using a non-default path.

---

## Log server configuration

The log server (`sudo-logger-server`) receives session recordings from agents
and stores them on disk (local mode) or in PostgreSQL + S3 (distributed mode).

### Starting the log server

```bash
sudo-logger-server \
  --listen :9876 \
  --logdir /var/log/sudoreplay \
  --cert /etc/sudo-logger/server.crt \
  --key /etc/sudo-logger/server.key \
  --ca /etc/sudo-logger/ca.crt \
  --signkey /etc/sudo-logger/ack-sign.key \
  --health-listen :9877
```

In production, the server is managed by systemd. See the RPM-installed unit
file for the full invocation.

### Complete flag reference

| Flag | Default | Description |
|------|---------|-------------|
| `--listen` | `:9876` | TLS listen address for agent connections |
| `--logdir` | `/var/log/sudoreplay` | Base directory for session log storage (local mode) |
| `--cert` | `/etc/sudo-logger/server.crt` | Server TLS certificate |
| `--key` | `/etc/sudo-logger/server.key` | Server TLS private key |
| `--ca` | `/etc/sudo-logger/ca.crt` | CA certificate used to verify client (agent) certificates |
| `--signkey` | `/etc/sudo-logger/ack-sign.key` | ed25519 private key (PEM) for signing ACKs sent to agents |
| `--strict-cert-host` | `false` | When true, reject sessions where the agent's TLS certificate CN/SAN does not match the hostname the agent claims |
| `--blocked-users` | `/etc/sudo-logger/blocked-users.yaml` | Path to the blocked users list; sessions from listed users are denied |
| `--whitelisted-users` | `/etc/sudo-logger/whitelisted-users.yaml` | Path to the whitelisted users list; listed users bypass JIT approval |
| `--approval-policy` | `/etc/sudo-logger/approval-policy.yaml` | Path to the JIT approval policy; JIT feature is disabled when this file is absent |
| `--approval-token` | _(empty)_ | Shared secret (Bearer token) for the approval REST API |
| `--approval-token-file` | _(empty)_ | File containing the approval Bearer token (alternative to `--approval-token`) |
| `--sandbox` | `/etc/sudo-logger/sandbox.yaml` | Path to the sandbox policy YAML file; served to agents at startup |
| `--sandbox-templates` | `/etc/sudo-logger/sandbox-templates.json` | Path to custom sandbox templates |
| `--storage` | `local` | Storage backend: `local` or `distributed` |
| `--s3-bucket` | _(empty)_ | S3 bucket name (distributed storage only) |
| `--s3-region` | `us-east-1` | AWS region for S3 (distributed storage) |
| `--s3-prefix` | `sessions/` | S3 key prefix for session objects (distributed storage) |
| `--s3-endpoint` | _(empty)_ | S3-compatible endpoint URL, e.g. `https://minio.internal:9000` |
| `--s3-path-style` | `false` | Use path-style S3 URLs; required for MinIO and StorageGRID |
| `--s3-access-key` | _(empty)_ | Static S3 access key; leave empty to use IAM role or environment credentials |
| `--s3-secret-key` | _(empty)_ | Static S3 secret key; leave empty to use IAM role or environment credentials |
| `--db-url` | _(empty)_ | PostgreSQL DSN for distributed storage (e.g. `postgres://user:$PG_PASS@host/dbname`) |
| `--buffer-dir` | `/var/lib/sudo-logger/buffer` | Local write-buffer directory for S3 uploads (distributed mode) |
| `--health-listen` | _(empty)_ | Plain HTTP address for `/healthz`, `/metrics`, and the approval REST API (e.g. `:9877`); disabled when empty |

### Storage flags: local vs distributed

**Local mode** (default) — session files are written to `--logdir` on the log
server's local filesystem. No additional infrastructure is required. Suitable
for single-server deployments.

```bash
sudo-logger-server \
  --storage local \
  --logdir /var/log/sudoreplay \
  --cert /etc/sudo-logger/server.crt \
  --key /etc/sudo-logger/server.key \
  --ca /etc/sudo-logger/ca.crt \
  --signkey /etc/sudo-logger/ack-sign.key
```

**Distributed mode** — session metadata is stored in PostgreSQL and session
files are stored in S3-compatible object storage. Use this when you need
multiple replay server instances, horizontal scaling, or separation of storage
from the log server process.

```bash
sudo-logger-server \
  --storage distributed \
  --db-url "postgres://sudologger:$DB_PASS@pg.internal:5432/sudologger" \
  --s3-bucket sudo-sessions \
  --s3-region eu-west-1 \
  --s3-endpoint https://minio.internal:9000 \
  --s3-path-style \
  --s3-access-key ACCESS_KEY \
  --s3-secret-key SECRET_KEY \
  --buffer-dir /var/lib/sudo-logger/buffer \
  --cert /etc/sudo-logger/server.crt \
  --key /etc/sudo-logger/server.key \
  --ca /etc/sudo-logger/ca.crt \
  --signkey /etc/sudo-logger/ack-sign.key
```

> **Note:** The `--buffer-dir` directory is a temporary write buffer for S3
> uploads. Sessions are written here first, then uploaded asynchronously.
> Ensure the directory has sufficient space for the expected peak session volume.

### Approval API flags

The JIT approval REST API is mounted on the `--health-listen` HTTP server.
The Approvals tab in the replay UI will not function unless `--health-listen`
is set.

Token resolution order (first match wins):
1. `--approval-token-file` — content of the named file
2. `--approval-token` — value of the flag directly

Set the same token value on the replay server via `--logserver-admin-token`
or `--logserver-admin-token-file`. The environment variable
`SUDO_LOGGER_ADMIN_TOKEN` is also accepted on the replay server side.

```bash
# Log server
sudo-logger-server \
  --health-listen :9877 \
  --approval-policy /etc/sudo-logger/approval-policy.yaml \
  --approval-token-file /etc/sudo-logger/approval-token \
  # ...

# Replay server (token must match)
sudo-replay-server \
  --logserver-admin http://localhost:9877 \
  --logserver-admin-token-file /etc/sudo-logger/approval-token \
  # ...
```

---

## Replay server configuration

The replay server (`sudo-replay-server`) provides the browser-based UI for
searching, viewing, and replaying recorded sessions. It also hosts the
Settings, Approvals, and SIEM configuration interfaces.

### Starting the replay server

```bash
sudo-replay-server \
  --listen :8080 \
  --logdir /var/log/sudoreplay \
  --tls-cert /etc/sudo-logger/replay.crt \
  --tls-key /etc/sudo-logger/replay.key \
  --htpasswd /etc/sudo-logger/htpasswd \
  --admin-users alice,bob \
  --rules /etc/sudo-logger/risk-rules.yaml \
  --logserver-admin http://localhost:9877 \
  --logserver-admin-token-file /etc/sudo-logger/approval-token
```

### Complete flag reference

| Flag | Default | Description |
|------|---------|-------------|
| `--listen` | `:8080` | HTTP/HTTPS listen address |
| `--logdir` | `/var/log/sudoreplay` | Base directory for session logs (must match log server `--logdir` in local mode) |
| `--rules` | `/etc/sudo-logger/risk-rules.yaml` | Risk scoring rules file |
| `--sandbox` | `/etc/sudo-logger/sandbox.yaml` | Sandbox policy file (shared with log server) |
| `--sandbox-templates` | `/etc/sudo-logger/sandbox-templates.json` | Custom sandbox templates (local store only) |
| `--siem-config` | `/etc/sudo-logger/siem.yaml` | SIEM forwarding configuration file (shared with log server) |
| `--blocked-users` | `/etc/sudo-logger/blocked-users.yaml` | Blocked users list (shared with log server) |
| `--whitelisted-users` | `/etc/sudo-logger/whitelisted-users.yaml` | Whitelisted users list (shared with log server) |
| `--logserver-admin` | _(empty)_ | Log server admin address for the approval API (e.g. `http://localhost:9877`); empty disables the Approvals tab |
| `--logserver-admin-token` | _(empty)_ | Bearer token for the log server approval API (must match `--approval-token` on the log server) |
| `--logserver-admin-token-file` | _(empty)_ | File containing the Bearer token; env `SUDO_LOGGER_ADMIN_TOKEN` is also accepted |
| `--tls-cert` | _(empty)_ | TLS certificate file; HTTPS is enabled when this flag is set |
| `--tls-key` | _(empty)_ | TLS private key file |
| `--htpasswd` | _(empty)_ | Path to bcrypt htpasswd file for HTTP Basic Auth; reload without restart with `SIGHUP` |
| `--trusted-user-header` | _(empty)_ | HTTP request header containing a pre-authenticated username from an upstream proxy (e.g. `X-Forwarded-User`) |
| `--admin-users` | _(empty)_ | Comma-separated list of usernames granted the admin role (can view all sessions, approve requests, delete sessions) |
| `--oidc-issuer` | _(empty)_ | OIDC provider issuer URL (e.g. `https://accounts.google.com`) |
| `--oidc-client-id` | _(empty)_ | OIDC client ID |
| `--oidc-client-secret` | _(empty)_ | OIDC client secret |
| `--oidc-redirect-url` | _(empty)_ | OIDC redirect URL (e.g. `https://replay.example.com/api/oidc/callback`) |
| `--storage` | `local` | Storage backend: `local` or `distributed` (must match log server) |
| `--s3-bucket` | _(empty)_ | S3 bucket name (distributed storage) |
| `--s3-region` | `us-east-1` | S3 region (distributed storage) |
| `--s3-prefix` | `sessions/` | S3 key prefix (distributed storage) |
| `--s3-endpoint` | _(empty)_ | S3-compatible endpoint URL (distributed storage) |
| `--s3-path-style` | `false` | Use path-style S3 URLs (required for MinIO/StorageGRID) |
| `--s3-access-key` | _(empty)_ | Static S3 access key (distributed storage) |
| `--s3-secret-key` | _(empty)_ | Static S3 secret key (distributed storage) |
| `--db-url` | _(empty)_ | PostgreSQL DSN (distributed storage) |
| `--buffer-dir` | `/var/lib/sudo-logger/buffer` | Local write-buffer directory for S3 uploads |

### Authentication configuration

The replay server supports four authentication modes. Modes can be combined
(for example: HTTPS + htpasswd, or trusted-header + admin-users).

#### 1. HTTP Basic Auth (htpasswd)

Set `--htpasswd` to a bcrypt htpasswd file. Only bcrypt hashes are supported;
MD5 and SHA1 hashes are rejected.

```bash
# Create a new htpasswd file with the first user
htpasswd -B -c /etc/sudo-logger/htpasswd alice

# Add another user to an existing file
htpasswd -B /etc/sudo-logger/htpasswd bob
```

The replay server reloads the htpasswd file without restart when it receives
`SIGHUP`:

```bash
kill -HUP $(systemctl show -p MainPID --value sudo-logger-replay)
```

#### 2. Trusted-header proxy authentication

Set `--trusted-user-header` to the HTTP header name that your upstream proxy
sets after authenticating the user. The replay server trusts this header
without further verification; the service must not be directly reachable by
clients, only through the authenticating proxy.

```bash
sudo-replay-server \
  --trusted-user-header X-Forwarded-User \
  # ...
```

A typical deployment uses nginx or oauth2-proxy in front of the replay server.
The proxy authenticates the user (e.g. via SSO) and sets the configured header.
The replay server reads the username from that header and creates a session.

For group-based role mapping in proxy auth mode, configure `AuthConfig.Source`
and supply a groups header via `PUT /api/auth-config`.

#### 3. OIDC (OpenID Connect)

Set the four OIDC flags to enable the Authorization Code Flow:

```bash
sudo-replay-server \
  --oidc-issuer https://accounts.google.com \
  --oidc-client-id 1234567890-abc.apps.googleusercontent.com \
  --oidc-client-secret GOCSPX-... \
  --oidc-redirect-url https://replay.example.com/api/oidc/callback \
  # ...
```

OIDC can also be configured at runtime via `PUT /api/auth-config` with
`AuthConfig.Source = "oidc"`. CLI flags take precedence over the API
configuration when both are set.

After a successful login, the server sets a session cookie and redirects the
user to the main UI. Tokens are verified via OIDC discovery document and JWKS;
raw JWT validation is not performed.

#### 4. Bearer token (approval API only)

Bearer token authentication is not used for browser sessions. It is used
exclusively by the replay server when calling the log server's approval REST
API. Set matching tokens on both sides:

```bash
# Log server
--approval-token mysharedsecret

# Replay server
--logserver-admin-token mysharedsecret
```

The replay server accepts the token from three sources, in priority order:
1. `--logserver-admin-token-file` (file contents)
2. `--logserver-admin-token` (flag value)
3. Environment variable `SUDO_LOGGER_ADMIN_TOKEN`

---

## /etc/sudo.conf

The sudo configuration file tells sudo which plugins to load. The
`sudo_logger.so` plugin must be declared after the policy plugin.

```
# /etc/sudo.conf

Plugin sudoers_policy  sudoers.so
Plugin sudo_io_logger  /usr/libexec/sudo/sudo_logger.so
```

> **Note:** Plugin line order matters. `sudoers_policy` must appear before
> `sudo_io_logger`. Reversing the order causes sudo to fail at startup.

The `sudo_logger.so` plugin is installed to `/usr/libexec/sudo/` by the
`sudo-logger-client` RPM package. After editing `/etc/sudo.conf`, no service
restart is required — sudo reads the file on every invocation.
