# Troubleshooting

## Diagnostic overview

Before diving into specific symptoms, collect these data points:

```bash
# Agent status and recent log lines
systemctl status sudo-logger-agent
journalctl -u sudo-logger-agent -n 100 --no-pager

# Log server status
systemctl status sudo-logserver
journalctl -u sudo-logserver -n 100 --no-pager

# Replay server status (systemd unit is "sudo-replay"; the binary itself is
# named sudo-replay-server — see below)
systemctl status sudo-replay
journalctl -u sudo-replay -n 100 --no-pager

# Session files on disk
ls -lh /var/log/sudoreplay/

# Health endpoints (if --health-listen is configured)
curl -s http://logserver:9877/healthz
curl -s http://replay-server:8080/healthz
```

Enable debug logging in the agent for verbose output (see [Getting debug output](#getting-debug-output) below).

---

## sudo hangs or blocks at startup

**Symptoms:** `sudo` command hangs indefinitely after the password prompt or before it. Nothing appears in session logs.

**Cause:** The plugin (`sudo_logger_plugin.so`) connects to the agent via the Unix socket `/run/sudo-logger/plugin.sock` during `sudo` startup. If the agent is not running or the socket does not exist, sudo blocks.

**Diagnosis:**

1. Check whether the agent is running:

   ```bash
   systemctl status sudo-logger-agent
   ```

2. Check whether the socket exists:

   ```bash
   ls -la /run/sudo-logger/plugin.sock
   ```

3. Check recent agent logs:

   ```bash
   journalctl -u sudo-logger-agent -n 50
   ```

4. Verify network connectivity to the log server:

   ```bash
   openssl s_client \
       -connect logserver:9876 \
       -cert    /etc/sudo-logger/client.crt \
       -key     /etc/sudo-logger/client.key \
       -CAfile  /etc/sudo-logger/ca.crt
   ```

   A successful mTLS handshake prints the server certificate and `Verify return code: 0 (ok)`. Any TLS error (wrong CA, expired cert, hostname mismatch) appears here.

5. If the socket is missing and the agent will not start, check for SELinux denials:

   ```bash
   ausearch -m avc -ts recent | grep sudo
   ```

**Fix:** Start the agent (`systemctl start sudo-logger-agent`) or resolve the underlying cause from the logs. If SELinux is blocking, reinstall the policy module (`semodule -i /usr/share/selinux/packages/sudo_logger.pp`).

---

## Session appears in agent log but not in replay UI

**Symptoms:** Agent logs show the session was forwarded to the server. The session does not appear in the replay web UI.

**Diagnosis:**

1. Verify the log server is running and accepting connections:

   ```bash
   systemctl status sudo-logserver
   journalctl -u sudo-logserver -n 50
   ```

2. Look for TLS errors in the agent log:

   ```bash
   journalctl -u sudo-logger-agent -n 100 | grep -i 'tls\|cert\|x509\|handshake'
   ```

   Common TLS error messages:
   - `certificate signed by unknown authority` — `ca.crt` does not match the server cert
   - `certificate has expired` — renew the server or client certificate
   - `remote error: tls: bad certificate` — client cert not accepted by server CA

3. Check that session files are being written to disk on the server:

   ```bash
   ls -lht /var/log/sudoreplay/ | head -20
   ```

4. Check whether the replay server is pointing at the correct `--logdir`:

   ```bash
   # Check the replay server command line
   systemctl cat sudo-replay | grep logdir
   ```

   The replay server's `--logdir` must match the log server's `--logdir` (default: `/var/log/sudoreplay`).

5. Check replay server logs for indexing or read errors:

   ```bash
   journalctl -u sudo-replay -n 100
   ```

---

## "chunk data truncated" or session freezes mid-way

**Symptoms:** A session appears in the replay UI but playback is cut short, or a running session freezes. Agent or server logs contain "chunk data truncated".

**Cause:** This was a race condition between `ship_chunk` and `refresh_ack_cache` — both wrote to the plugin socket descriptor (`g_shipper_fd`) concurrently without a mutex, causing partial writes. The fix (a `g_send_mu` mutex) was applied in commit `cba194f`.

**Check:** Ensure the installed plugin and agent versions both postdate commit `cba194f`. If you built from source, verify with:

```bash
sudo-logger-agent -version 2>/dev/null || \
    strings /usr/bin/sudo-logger-agent | grep -i version
```

Also verify that the plugin `.so` and the agent binary were compiled from the same source tree. Mismatched plugin/agent versions can cause protocol errors.

---

## "strict-cert-host" rejections

**Symptoms:** Sessions are rejected by the log server with a message such as "host mismatch" or "cert CN does not match". The agent logs show the session was sent but the server rejected it.

**Cause:** The log server was started with `--strict-cert-host`. The server reads the CN (and DNS SANs) from the agent's client TLS certificate and verifies it matches the `host` field in the `SESSION_START` message. If the certificate has a generic CN (e.g., `CN=agent`) but the agent reports a specific hostname (e.g., `host42.example.com`), the check fails.

**Fix options:**

1. Issue per-machine certificates where `CN` matches the agent's FQDN:

   ```bash
   openssl req -new -key host42.key -out host42.csr \
       -subj "/CN=host42.example.com"
   ```

   Deploy the resulting cert+key pair to that specific host.

2. If per-machine certs are not yet in place, remove `--strict-cert-host` from the log server's flags and restart.

3. To debug the hostname the agent is reporting, check agent logs for `SESSION_START` messages. The reported hostname can be overridden in `agent.conf`:

   ```ini
   Hostname = host42.example.com
   ```

---

## eBPF fails to load

**Symptoms:** Agent starts but logs contain "eBPF disabled", "BTF not found", or "failed to load BPF program". Session recording still works (fallback to plugin-only mode), but eBPF-based features (BPF LSM sandbox, pkexec tracking) are unavailable.

**Causes and checks:**

| Cause | Check | Fix |
|---|---|---|
| Kernel < 5.7 | `uname -r` | Upgrade kernel; 5.7+ required for BPF LSM (`CONFIG_BPF_LSM=y`, `lsm=bpf` boot parameter) |
| No BTF support | `ls /sys/kernel/btf/vmlinux` | Install a kernel built with `CONFIG_DEBUG_INFO_BTF=y` |
| Missing capabilities | `systemctl cat sudo-logger-agent` | Agent must run as root with `CAP_BPF`, `CAP_SYS_ADMIN` |
| SELinux blocking BPF | `ausearch -m avc -ts recent` | Reinstall SELinux policy module |

**Fallback behaviour:** If eBPF fails to load, the agent continues operating. Plugin-only recording (via `plugin.sock`) still captures terminal I/O. The BPF LSM sandbox and eBPF-level recording are disabled for that boot. The agent logs the reason at startup.

To permanently disable eBPF on a host that does not support it:

```ini
# /etc/sudo-logger/agent.conf
Ebpf = false
```

---

## SELinux denials

**Symptoms:** Agent fails to start, socket is not created, or eBPF fails to load, with SELinux in enforcing mode. `systemctl status sudo-logger-agent` shows the process exited immediately.

**Diagnosis:**

```bash
# Check for recent AVC denials
ausearch -m avc -ts recent | grep sudo

# Generate a summary with suggested allow rules
audit2allow -a

# Full audit log analysis
sealert -a /var/log/audit/audit.log
```

**Fix:**

```bash
# Reinstall the policy module
semodule -i /usr/share/selinux/packages/sudo_logger.pp

# Verify it is loaded
semodule -l | grep sudo_logger
```

If the RPM is not installed, locate the compiled policy module:

```bash
find /usr/share/selinux -name 'sudo_logger.pp'
```

If denials persist after reinstalling the module, the policy version may not match the running kernel's SELinux policy. In that case, temporarily set SELinux to permissive for the `sudo_agent_t` domain while investigating:

```bash
semanage permissive -a sudo_agent_t
```

> **Warning:** Setting a domain permissive disables enforcement for that domain only. Remove with `semanage permissive -d sudo_agent_t` once the issue is resolved.

---

## Session visible in file system but risk score not showing

**Symptoms:** Sessions appear in the replay UI but the risk score column is blank or shows zero for all sessions.

**Cause:** The risk scoring engine evaluates sessions against rules in `/etc/sudo-logger/risk-rules.yaml` (default path, configurable with `--rules`). The score may not appear if:

- The rules file is missing or unparseable.
- The `risk.json` cache file for the session is stale or missing.

**Fix:**

1. Verify the rules file exists and is valid YAML:

   ```bash
   cat /etc/sudo-logger/risk-rules.yaml
   ```

2. Check replay server logs for rule parsing errors:

   ```bash
   journalctl -u sudo-replay | grep -i 'risk\|rules\|yaml'
   ```

3. Rules take effect immediately when saved through the Settings tab (or `PUT /api/rules`) — there is no signal-based reload; the replay server only handles `SIGTERM`/`SIGINT` for shutdown. Editing the on-disk YAML file directly does not get picked up without going through the API/UI.

---

## SIEM forwarding not working

**Symptoms:** Sessions are recorded correctly in the replay UI but do not appear in the SIEM (Splunk, Elastic, etc.).

**Checklist:**

1. Is SIEM forwarding enabled in `/etc/sudo-logger/siem.yaml`?

   ```yaml
   enabled: true
   url: https://siem.example.com:8088/services/collector
   ```

2. Is the URL reachable from the replay server host?

   ```bash
   curl -v https://siem.example.com:8088/services/collector
   ```

3. If the SIEM endpoint uses a private CA, ensure the CA cert is trusted by the system or configured in `siem.yaml`.

4. Check replay server logs for SIEM-related errors:

   ```bash
   journalctl -u sudo-replay | grep -i 'siem\|forward\|hec\|http'
   ```

5. The `siem.yaml` file is polled for changes every 30 seconds — after editing it directly, wait for the next poll (there is no signal-based reload; the replay server only handles `SIGTERM`/`SIGINT`). Changes saved through the Settings tab take effect immediately.

---

## JIT approval: session stuck waiting forever

**Symptoms:** A session triggered the JIT approval policy and is frozen, but no approval request appears in the replay UI, or the approval is never delivered to the agent.

**Causes and checks:**

1. **Webhook not configured:** If `notifications.webhook_url` is empty in the approval policy, operators do not receive a notification about the pending session. Check `/etc/sudo-logger/approval-policy.yaml`.

2. **`pending_ttl` expired:** If no approval or denial is received within `pending_ttl`, the session is automatically denied. Check the `pending_ttl` value in `approval-policy.yaml` and the timestamp on the pending session.

3. **Replay server cannot reach the approval API:** The replay server contacts the log server's admin port to list and approve sessions. Check that `--logserver-admin` is set on the replay server and points to the correct URL:

   ```bash
   curl http://logserver:9877/api/approvals
   ```

   If this URL is unreachable, `--health-listen` may not be configured on the log server. Add `-health-listen :9877` to the log server's flags.

4. **Token mismatch:** The bearer token passed as `--logserver-admin-token` on the replay server must match the `-approval-token` (or `SUDO_LOGGER_APPROVAL_TOKEN` env var, or `-approval-token-file` file) on the log server.

5. **Check pending approvals directly:**

   ```bash
   curl -H "Authorization: Bearer <token>" http://logserver:9877/api/approvals
   ```

---

## RBAC: 403 on API endpoints

**Symptoms:** A user receives an HTTP 403 response when accessing the replay UI or API endpoints that require a permission their role does not hold (e.g. `sessions:list_all`, `approvals:decide`, `config:write`).

**Diagnosis:**

1. Check what roles and permissions the current user has:

   ```bash
   curl -s http://replay-server:8080/api/me \
       -H "Authorization: Bearer <token>"
   ```

   The response includes the user's roles and effective permissions.

2. Verify the user is listed in `--admin-users` (for the admin role):

   ```bash
   systemctl cat sudo-replay | grep admin-users
   ```

   `--admin-users` accepts a comma-separated list of usernames. Users not listed here do not receive the admin role.

3. If OIDC is in use, verify the group-to-role mapping in the RBAC configuration. Check replay server logs for role assignment messages.

4. The `--trusted-user-header` flag (e.g., `X-Forwarded-User`) must be set when running behind a reverse proxy that injects the authenticated username. Without it, the replay server cannot identify the user.

---

## Verifying session file integrity

The `scripts/verify-integrity.sh` script performs a syntax check on source files. It is intended for validating Go and C files during development:

```bash
./scripts/verify-integrity.sh <file>
```

- For `.go` files: runs `go fmt` then `go vet`.
- For `.c` files: runs `gcc -fsyntax-only`.
- For other types: reports "unknown file type, skipping".

> **Note:** This script validates source file syntax, not session recording integrity. It is a development tool, not a runtime integrity check for session log files.

To verify session log files on disk, check that the files are present and non-zero. Sessions are stored as asciinema v2 `session.cast` files (see Chapter 7), not sudo's native `.iolog` format, so check for empty `session.cast` files:

```bash
ls -lh /var/log/sudoreplay/
find /var/log/sudoreplay/ -name 'session.cast' -empty
```

---

## Getting debug output

### Agent

Enable debug logging in `/etc/sudo-logger/agent.conf`:

```ini
Debug = true
```

Restart the agent:

```bash
systemctl restart sudo-logger-agent
```

With `Debug = true`, the agent logs each message exchange with the plugin, connection events to the log server, ACK processing, and eBPF events to the journal.

```bash
journalctl -u sudo-logger-agent -f
```

### Log server

The log server does not currently support a `--debug` flag. Verbose output is available via the standard journal. Check for connection events, TLS handshake errors, and session write errors:

```bash
journalctl -u sudo-logserver -f
```

For TLS debugging, use `openssl s_client` directly (see [sudo hangs or blocks at startup](#sudo-hangs-or-blocks-at-startup) above).

### Replay server

The replay server does not currently support a `--debug` flag. Run it in the foreground to see all log output:

```bash
sudo-replay-server \
    -logdir      /var/log/sudoreplay \
    -listen      :8080 \
    -admin-users yourusername
```

All HTTP requests, rule reload events, SIEM errors, and approval API calls are logged to stderr.

### Checking component connectivity end-to-end

```bash
# 1. Plugin → agent (Unix socket)
ls -la /run/sudo-logger/plugin.sock
sudo -l   # triggers plugin connect, check agent log

# 2. Agent → log server (mTLS)
openssl s_client \
    -connect logserver:9876 \
    -cert    /etc/sudo-logger/client.crt \
    -key     /etc/sudo-logger/client.key \
    -CAfile  /etc/sudo-logger/ca.crt \
    -brief

# 3. Replay server → log server admin port
curl -s http://logserver:9877/healthz

# 4. Browser → replay server
curl -s http://replay-server:8080/healthz
```

Each step should succeed independently before testing the full chain.
