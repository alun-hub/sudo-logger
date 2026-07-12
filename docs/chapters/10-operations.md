# Operations & Maintenance

## Log rotation and retention

### Default storage path

Session files are written to the directory specified by `--logdir` on both the log server and the replay server. The default is `/var/log/sudoreplay`.

### Directory structure on disk

Each session is stored in a per-user, per-session subdirectory:

```
/var/log/sudoreplay/
└── <user>/
    └── <host>_<timestamp>/
        ├── session.cast    # asciinema v2 recording (header + event lines)
        ├── session.json    # header-only metadata copy (no I/O data; used for fast listing)
        ├── ACTIVE          # marker present while the session is being recorded; removed on close
        ├── INCOMPLETE      # marker written if the connection drops without a SESSION_END message
        └── risk.json       # optional risk score cache written by the replay server
```

The `<timestamp>` component in the directory name is the session start time in the format used internally by the log server (a Unix timestamp in nanoseconds, rendered as a decimal integer — the `tsid` field). The `session.json` file contains the asciinema v2 header only (no event data), allowing the replay server to enumerate sessions without reading full cast files.

### Retention via the web UI

The replay server exposes a retention policy API. In the web UI, navigate to **Settings → Data Retention** to configure automatic cleanup:

- **Auto-cleanup** — enable or disable the scheduled cleanup process.
- **Retention period** — number of days to keep sessions; sessions older than this are permanently deleted from both storage (local disk or S3) and the database (distributed mode).
- The cleanup process runs once every 24 hours when enabled.

> **Warning:** Deletion is permanent and irreversible. Verify your retention period against any regulatory or audit requirements before enabling auto-cleanup. For audit-grade deployments, consider keeping all sessions and archiving them to cold storage instead.

### Manual cleanup (local disk)

To remove sessions older than 90 days without enabling the UI-based retention:

```bash
find /var/log/sudoreplay -mindepth 2 -maxdepth 2 -type d \
    -mtime +90 -exec rm -rf {} +
```

Run this as a cron job or a systemd timer. Always test with `--dry-run` (`find ... -print`) before deleting.

### Retention in distributed mode

In distributed mode, sessions in S3/MinIO can be aged out using the object store's built-in lifecycle policies. Set an expiry rule on the bucket prefix (default: `sessions/`) to match your retention period. Rows in PostgreSQL are cleaned up by the replay server's internal retention process when auto-cleanup is enabled. Both actions must be configured: deleting from S3 without cleaning the database leaves orphaned metadata rows, and vice versa.

---

## Backup

### What to back up

| What | Default path | Why |
|---|---|---|
| Session files (local mode) | `/var/log/sudoreplay/` | Primary audit record — the cast files and metadata JSON |
| TLS certificates and keys | `/etc/sudo-logger/` | Required to restore a working mTLS chain (`ca.crt`, `server.crt`, `server.key`, `client.crt`, `client.key`, `ack-sign.key`, `ack-verify.key`) |
| Agent configuration | `/etc/sudo-logger/agent.conf` | Agent connection parameters, mask patterns, freeze timeout |
| Risk rules | `/etc/sudo-logger/risk-rules.yaml` | Custom risk scoring rules |
| SIEM configuration | `/etc/sudo-logger/siem.yaml` | SIEM forwarding endpoint, credentials, format |
| Blocked/whitelisted users | `/etc/sudo-logger/blocked-users.yaml`, `/etc/sudo-logger/whitelisted-users.yaml` | Access control lists managed by the GUI |
| Approval policy | `/etc/sudo-logger/approval-policy.yaml` | JIT approval rules |
| Sandbox rules | `/etc/sudo-logger/sandbox.yaml` | eBPF LSM process sandbox deny-lists |
| PostgreSQL database (distributed mode) | configured via `--db-url` | Session metadata (users, hosts, commands, timestamps, risk scores) |

### Backup procedure

For local storage:

```bash
# Back up session files (incremental rsync)
rsync -av --delete /var/log/sudoreplay/ backup-host:/backups/sudoreplay/

# Back up configuration and certificates
tar -czf /backups/sudo-logger-config-$(date +%F).tar.gz /etc/sudo-logger/
```

For distributed mode, back up the PostgreSQL database in addition:

```bash
pg_dump --no-password "$PGDSN" | gzip > /backups/sudo-logger-db-$(date +%F).sql.gz
```

S3/MinIO session files are replicated using the object store's own replication mechanism; point-in-time recovery depends on the bucket's versioning and replication configuration.

### Restore procedure

1. **Restore TLS certificates first.** Without valid certificates, the agent cannot establish mTLS connections to the log server and all sudo sessions will be blocked.

   ```bash
   tar -xzf /backups/sudo-logger-config-<date>.tar.gz -C /
   chmod 600 /etc/sudo-logger/server.key /etc/sudo-logger/client.key
   chown root:sudologger /etc/sudo-logger/ack-sign.key
   chmod 640 /etc/sudo-logger/ack-sign.key
   chmod 644 /etc/sudo-logger/ca.crt /etc/sudo-logger/server.crt /etc/sudo-logger/client.crt /etc/sudo-logger/ack-verify.key
   ```

2. **Restore session data.**

   ```bash
   rsync -av backup-host:/backups/sudoreplay/ /var/log/sudoreplay/
   chown -R sudologger:sudologger /var/log/sudoreplay/
   ```

   In distributed mode, restore the PostgreSQL dump first, then allow S3 to serve the session files from the replicated bucket.

3. **Start services** in dependency order: log server first, then replay server, then agents.

   ```bash
   systemctl start sudo-logserver
   systemctl start sudo-replay
   # On each monitored host:
   systemctl start sudo-logger-agent
   ```

4. **Verify** by loading the replay UI and confirming that sessions appear and play back correctly.

---

## Certificate rotation

TLS certificates used by sudo-logger must be rotated before expiry. The PKI consists of:

- `ca.crt` — CA certificate (shared by all components)
- `server.crt` / `server.key` — log server TLS certificate
- `client.crt` / `client.key` — agent client certificate (may be shared across hosts or per-host)
- `ack-sign.key` / `ack-verify.key` — ed25519 key pair for ACK signing

> **Warning:** Rotating the CA requires updating certificates on all monitored hosts and the log server simultaneously. Plan a maintenance window. If the CA changes before the agent's `ca.crt` is updated, the agent will reject the server's new certificate and all sudo sessions on that host will be blocked.

### Rotating server and client certificates (same CA)

1. Generate new certificates signed by the existing CA:

   ```bash
   # On the CA host (or wherever the CA key is stored):
   openssl genrsa -out /tmp/server-new.key 4096
   openssl req -new -key /tmp/server-new.key -out /tmp/server-new.csr \
       -subj "/CN=logserver.example.internal"
   openssl x509 -req -in /tmp/server-new.csr -CA /etc/sudo-logger/ca.crt \
       -CAkey /etc/sudo-logger/ca.key -CAcreateserial \
       -out /tmp/server-new.crt -days 365
   ```

2. Copy the new certificate and key to the log server:

   ```bash
   install -m 644 /tmp/server-new.crt /etc/sudo-logger/server.crt
   install -m 600 /tmp/server-new.key /etc/sudo-logger/server.key
   ```

3. Restart the log server to load the new certificate:

   ```bash
   systemctl restart sudo-logserver
   ```

4. Repeat for client certificates on each monitored host, then restart the agent:

   ```bash
   systemctl restart sudo-logger-agent
   ```

### Rotating the CA

Rotating the CA is more involved because both the server and all agents must trust the new CA:

1. Generate the new CA.
2. Issue new server and client certificates from the new CA.
3. Deploy the new `ca.crt`, `server.crt`, `server.key` to the log server and restart `sudo-logserver`.
4. Deploy the new `ca.crt`, `client.crt`, `client.key` to every monitored host and restart `sudo-logger-agent` on each.

Perform steps 3 and 4 as close together as possible. During the window between step 3 and step 4 completion, agents with the old `ca.crt` will reject the server's new certificate and their sudo sessions will be blocked.

### Certificate rotation in Kubernetes

Update the Kubernetes `Secret` that holds the certificate material. Pods will pick up the new certificates on next restart (or when the mounted secret volume is refreshed, depending on the cluster's volume projection interval). To force an immediate update, perform a rolling restart:

```bash
kubectl rollout restart deployment/sudo-logserver
kubectl rollout restart deployment/sudo-replay-server
# DaemonSet agents on each node:
kubectl rollout restart daemonset/sudo-logger-agent
```

---

## Upgrading

### RPM upgrade (standard path)

On the log server, upgrade the server and replay packages together:

```bash
sudo dnf upgrade sudo-logger-server sudo-logger-replay
sudo systemctl restart sudo-logserver sudo-replay
```

On each monitored host, upgrade the client package:

```bash
sudo dnf upgrade sudo-logger-client
sudo systemctl restart sudo-logger-agent
```

> **Note:** The three RPM packages (`sudo-logger-client`, `sudo-logger-server`, `sudo-logger-replay`) are versioned independently. Only upgrade the package corresponding to the components that changed. See the `rpm/*.spec` files for the current version of each package.

### Checking the current version

```bash
rpm -q sudo-logger-client sudo-logger-server sudo-logger-replay
```

### Database migrations (distributed mode)

The log server applies PostgreSQL schema changes automatically at startup. No manual migration step is required for schema upgrades when using `--storage=distributed`.

### Migrating from local to distributed storage

The `migrate-sessions` tool (`go/cmd/migrate-sessions/`) imports existing local-disk session recordings into the distributed backend (S3 + PostgreSQL). Run it once before switching the log server and replay server to `--storage=distributed`.

**What it does:**

- Walks the `--logdir` directory tree and reads every `session.json` metadata file.
- Uploads the corresponding `session.cast` file to S3 under the configured prefix (`--s3-prefix`, default `sessions/`).
- Inserts a metadata row into PostgreSQL. The insert uses `ON CONFLICT DO NOTHING`, so the tool is idempotent — re-running it after a partial failure is safe.

**Usage:**

```bash
migrate-sessions \
  --logdir /var/log/sudoreplay \
  --db-url "postgres://sudo-logger:$DB_PASS@db.internal/sudologger" \
  --s3-bucket my-sessions-bucket \
  --s3-endpoint https://minio.internal:9000 \
  --s3-path-style \
  --s3-access-key ACCESS_KEY \
  --s3-secret-key SECRET_KEY
```

| Flag | Default | Description |
|---|---|---|
| `--logdir` | `/var/log/sudoreplay` | Source directory containing local session files |
| `--db-url` | (required) | PostgreSQL DSN |
| `--s3-bucket` | (required) | Destination S3 bucket |
| `--s3-region` | `us-east-1` | S3 region |
| `--s3-prefix` | `sessions/` | S3 key prefix for uploaded session files |
| `--s3-endpoint` | — | S3-compatible endpoint URL (required for MinIO/StorageGRID) |
| `--s3-path-style` | false | Use path-style S3 URLs (required for MinIO) |
| `--s3-access-key` | — | Static access key (omit to use IAM role or environment) |
| `--s3-secret-key` | — | Static secret key (omit to use IAM role or environment) |
| `--dry-run` | false | Print what would be migrated without writing anything |
| `--workers` | 4 | Number of concurrent upload workers |

After migration completes successfully, update the log server and replay server startup flags to include `--storage=distributed` along with the `--db-url` and `--s3-*` flags, then restart both services.

---

## Reloading configuration without restart

Each component handles configuration changes differently. The table below summarises which files can be updated without restarting the process.

| Component | File | Reload mechanism | Interval / trigger |
|---|---|---|---|
| **Agent** (`sudo-logger-agent`) | `agent.conf` | Requires process restart | No live reload |
| **Log server** (`sudo-logserver`) | `blocked-users.yaml` | Automatic background poll | Every 30 s |
| **Log server** (`sudo-logserver`) | `whitelisted-users.yaml` | Automatic background poll | Every 30 s |
| **Log server** (`sudo-logserver`) | `approval-policy.yaml` | Automatic background poll | Every 30 s |
| **Log server** (`sudo-logserver`) | `sandbox.yaml` | Served to agents on request | No explicit reload interval; agents fetch on connect |
| **Log server** (`sudo-logserver`) | `siem.yaml` | Automatic background poll | Every 30 s |
| **Replay server** (`sudo-replay`) | `risk-rules.yaml` | Automatic background poll | Every 30 s |
| **Replay server** (`sudo-replay`) | `siem.yaml` | Automatic background poll | Every 30 s |

> **Note:** The `-htpasswd` flag's help text says "reload with SIGHUP", but this is not currently wired up: `go/cmd/replay-server/main.go` only registers signal handling for `SIGTERM`/`SIGINT`, and the shipped `sudo-replay.service` unit has no `ExecReload=` directive. Sending `kill -HUP <pid>` or running `systemctl reload sudo-replay` will not reload anything — with no `ExecReload=` configured, systemd will report the reload as unsupported for this unit, and a raw `SIGHUP` to the process falls back to the OS default action (process termination), not a graceful reload. Local user accounts (used for Basic Auth login) are managed through the `/api/users` API and the local store, not by re-reading a htpasswd-format file at runtime. If you change local user passwords, do so via `/api/users`; there is no supported live-reload path for this flag today.

Changes to `agent.conf` require a full agent restart. Active sudo sessions survive a brief agent restart because the log server connection is re-established per session and the plugin holds the Unix socket open; however, sessions in flight at the exact moment of restart may be marked `INCOMPLETE`.

---

## Health checks

Both the log server and the replay server expose a `GET /healthz` endpoint that returns `200 OK` with body `ok` when the process is running and its main subsystems are initialised.

| Component | Endpoint | Port | Authentication |
|---|---|---|---|
| Replay server | `GET /healthz` | 8080 (or `--listen`) | Same as rest of UI |
| Log server | `GET /healthz` | configured via `--health-listen` | None (plain HTTP) |

> **Note:** The log server `/healthz` endpoint is only available when `--health-listen` is set. Without it there is no HTTP health endpoint on the log server.

### Manual check

```bash
# Replay server (no auth):
curl -sf http://localhost:8080/healthz && echo ok

# Replay server (with Basic Auth):
curl -sf -u prometheus-scraper:$SCRAPER_PASS http://localhost:8080/healthz && echo ok

# Log server health port:
curl -sf http://localhost:9877/healthz && echo ok
```

### Kubernetes liveness and readiness probes

```yaml
livenessProbe:
  httpGet:
    path: /healthz
    port: 9877    # --health-listen port
  initialDelaySeconds: 5
  periodSeconds: 10

readinessProbe:
  httpGet:
    path: /healthz
    port: 9877
  initialDelaySeconds: 2
  periodSeconds: 5
```

---

## Systemd service management

The following systemd unit names are installed by the RPM packages:

| Unit | Package | Description |
|---|---|---|
| `sudo-logger-agent` | `sudo-logger-client` | Agent daemon on monitored hosts |
| `sudo-logserver` | `sudo-logger-server` | Central log server |
| `sudo-logserver-restart.timer` | `sudo-logger-server` | Daily 03:00 restart timer (memory leak mitigation) |
| `sudo-replay` | `sudo-logger-replay` | Web replay UI |

### Common operations

```bash
# Status
systemctl status sudo-logger-agent
systemctl status sudo-logserver
systemctl status sudo-replay

# Restart
systemctl restart sudo-logger-agent
systemctl restart sudo-logserver
systemctl restart sudo-replay

# Enable at boot
systemctl enable sudo-logger-agent
systemctl enable sudo-logserver
systemctl enable sudo-replay

# View logs
journalctl -u sudo-logger-agent -f
journalctl -u sudo-logserver -f
journalctl -u sudo-replay -f

# View logs since last boot
journalctl -u sudo-logserver -b
```

### Log server daily restart timer

The `sudo-logserver-restart.timer` unit triggers a restart of the log server daily at 03:00. This is a precautionary measure to reclaim any memory that accumulates from long-lived TLS connections over time. The timer invokes `sudo-logserver-restart.service`, a oneshot unit that restarts `sudo-logserver`. Active sessions at the time of restart will be marked `INCOMPLETE` by the agent; the agent reconnects and new sessions resume normally within seconds of the server coming back up.

To inspect the timer:

```bash
systemctl status sudo-logserver-restart.timer
systemctl list-timers sudo-logserver-restart.timer
```

To disable the daily restart (not recommended for long-running deployments):

```bash
systemctl disable --now sudo-logserver-restart.timer
```
