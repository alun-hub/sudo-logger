# API Reference

## Overview

sudo-logger exposes two HTTP API surfaces:

| Server | Base URL | Transport | Auth |
|--------|----------|-----------|------|
| Replay server | `http(s)://replay-server:8080` | HTTP or HTTPS | Basic Auth / OIDC / trusted header |
| Log server (admin) | `http://logserver:9877` | Plain HTTP | Bearer token |

All JSON endpoints use `Content-Type: application/json`. Errors return:

```json
{ "error": "human-readable message" }
```

Common HTTP status codes: `400` bad request · `401` not authenticated · `403` missing permission · `404` not found · `500` internal error.

**Date formats:** Query parameters accept Unix epoch seconds (integer) or RFC 3339 strings. Response timestamps are RFC 3339 UTC strings, except where noted.

### Authentication summary

| Mechanism | Configured via | Applies to |
|-----------|---------------|-----------|
| HTTP Basic Auth | `--htpasswd` (bcrypt htpasswd file) | Replay server |
| Trusted-header proxy | `--trusted-user-header` | Replay server |
| OIDC | `--oidc-issuer` / `PUT /api/auth-config` | Replay server |
| Bearer token | `--approval-token` / `--approval-token-file` | Log server admin API |
| No auth | — | `/healthz`, `/metrics` |

### Permission model

Every API call checks the caller's permissions. The 12 defined permissions are:

| Permission | String value | What it allows |
|------------|-------------|---------------|
| `PermSessionsListOwn` | `sessions:list_own` | List and search own sessions |
| `PermSessionsListAll` | `sessions:list_all` | List and search all users' sessions |
| `PermSessionsReplayOwn` | `sessions:replay_own` | Replay own sessions |
| `PermSessionsReplayAll` | `sessions:replay_all` | Replay any session |
| `PermSessionsDelete` | `sessions:delete` | Delete sessions (GDPR) |
| `PermUsersRead` | `users:read` | List users and roles |
| `PermUsersWrite` | `users:write` | Create, modify, delete users and roles |
| `PermAuditLogRead` | `audit_log:read` | Read the access/audit log |
| `PermApprovalsRead` | `approvals:read` | View pending JIT approvals |
| `PermApprovalsDecide` | `approvals:decide` | Approve or deny JIT requests |
| `PermConfigRead` | `config:read` | Read configuration (rules, SIEM, sandbox) |
| `PermConfigWrite` | `config:write` | Write configuration |

Built-in roles: **admin** (all permissions) and **viewer** (`sessions:list_own` + `sessions:replay_own`). Custom roles can hold any subset.

---

## Replay Server API

### Sessions

#### `GET /api/sessions`

List and search sessions. Results are paginated via cursor.

**Required permission:** `sessions:list_own` (own sessions) or `sessions:list_all` (all users)

**Query parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `q` | string | Full-text search across user, host, command |
| `from` | int (epoch seconds) | Start of time range |
| `to` | int (epoch seconds) | End of time range |
| `cursor` | string | Pagination cursor from previous response |
| `limit` | int | Results per page (default: 50) |
| `sort` | string | Sort field (e.g. `start_time`, `-start_time`) |

**Response:**

```json
{
  "sessions": [
    {
      "tsid": "alice/web01_20260615-143022",
      "user": "alice",
      "host": "web01.example.com",
      "command": "vim /etc/nginx/nginx.conf",
      "runas": "root",
      "start_time": "2026-06-15T14:30:22Z",
      "end_time": "2026-06-15T14:35:11Z",
      "duration": 289,
      "exit_code": 0,
      "source": "plugin",
      "risk_score": 20,
      "risk_level": "low",
      "in_progress": false,
      "incomplete": false,
      "network_outage": false,
      "divergence_status": "ok",
      "has_io": true
    }
  ],
  "next_cursor": "abc123",
  "total": 1482
}
```

`source` values: `"plugin"`, `"ebpf-tty"`, `"ebpf-pkexec"`, `"dbus-polkit"`.

---

#### `GET /api/session/events`

Fetch the event stream for one session as newline-delimited JSON.

**Required permission:** `sessions:replay_own` or `sessions:replay_all`

**Query parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `tsid` | string | Session identifier (required) |

**Response:** `Content-Type: application/x-ndjson`

Each line is a JSON object representing one session event. The exact shape depends on event type (session metadata, I/O chunk, risk scoring result, etc.).

---

#### `GET /api/session/cast`

Serve the raw asciicast v2 file for playback.

**Required permission:** `sessions:replay_own` or `sessions:replay_all`

**Query parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `tsid` | string | Session identifier (required) |

**Response:** `Content-Type: text/plain`

The response body is an asciicast v2 file consumed directly by `asciinema-player`. Line 1 is a JSON header; subsequent lines are `[seconds, "o"|"i", "data"]` tuples.

---

#### `DELETE /api/sessions/{tsid}`

Permanently delete a session and all associated data (GDPR erasure).

**Required permission:** `sessions:delete`

> **Note:** This endpoint is only registered when the approval feature is enabled (log server `--approval-token` configured and `--logserver-admin` set on replay server).

**Response:** `204 No Content`

The delete is also recorded in the audit log.

---

### Reports

#### `GET /api/report`

Aggregate statistics for a date range.

**Required permission:** `sessions:list_all`

**Query parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `from` | int (epoch seconds) | Start of range |
| `to` | int (epoch seconds) | End of range |

**Response:**

```json
{
  "summary": {
    "total_sessions": 1482,
    "unique_users": 14,
    "unique_hosts": 8,
    "incomplete_sessions": 3,
    "long_sessions": 7,
    "high_risk_sessions": 12,
    "critical_sessions": 2,
    "period_from": 1749916800,
    "period_to": 1750003200
  },
  "per_user": [
    {
      "user": "alice",
      "sessions": 42,
      "hosts": 3,
      "host_counts": [{"host": "web01", "count": 30}, {"host": "db01", "count": 12}],
      "avg_duration": 145.2,
      "top_commands": ["vim", "systemctl", "tail"],
      "incomplete": 0,
      "long_sessions": 1,
      "high_risk": 2,
      "critical": 0
    }
  ],
  "anomalies": [
    {
      "kind": "incomplete",
      "tsid": "bob/db01_20260615-020011",
      "user": "bob",
      "host": "db01",
      "command": "pg_dump -U postgres mydb",
      "start_time": 1749952811,
      "duration": 0,
      "detail": "Session ended without SESSION_END",
      "risk_score": 15
    }
  ]
}
```

`anomaly.kind` values: `"incomplete"`, `"high_risk"`, `"root_shell"`, `"after_hours"`, `"long_session"`.

---

#### `GET /api/access-log`

Audit log of who viewed which session.

**Required permission:** `audit_log:read`

**Response:**

```json
[
  {
    "time": 1750001234,
    "viewer": "carol",
    "tsid": "alice/web01_20260615-143022",
    "replay_url": "https://replay.example.com/?tsid=alice%2Fweb01_20260615-143022"
  }
]
```

---

### Configuration

All configuration endpoints require `config:read` (GET) or `config:write` (PUT).

#### `GET / PUT /api/rules`

Read or replace the risk-rules configuration.

**GET response / PUT request body:**

```json
{
  "rules": [
    {
      "id": "root_shell",
      "score": 10,
      "reason": "Interactive root shell started",
      "command_base_any": ["bash", "sh", "zsh"],
      "runas": "root"
    }
  ]
}
```

PUT replaces the entire rules file atomically. Changes take effect immediately; existing session risk caches are invalidated on next access.

---

#### `GET / PUT /api/siem-config`

Read or update the SIEM forwarding configuration.

**GET response / PUT request body:**

```json
{
  "config": {
    "enabled": true,
    "transport": "https",
    "format": "json",
    "replay_url_base": "https://replay.example.com",
    "https": {
      "url": "https://splunk.corp:8088/services/collector",
      "token": "Splunk abc123",
      "tls": { "ca": "", "cert": "", "key": "" }
    },
    "syslog": {
      "addr": "",
      "protocol": "udp",
      "tls": { "ca": "", "cert": "", "key": "" }
    }
  }
}
```

---

#### `POST /api/siem-cert`

Upload a PEM certificate for use by the SIEM TLS connection.

**Request:** `multipart/form-data`, field name `file`, max 64 KB, must contain a valid PEM block.

**Response:**

```json
{ "path": "/etc/sudo-logger/siem-ca.crt" }
```

---

#### `GET / PUT /api/retention`

Read or update session retention settings.

**GET response / PUT request body:** retention configuration object (structure depends on storage backend — local: max age in days / distributed: S3 lifecycle policy reference).

---

#### `GET / PUT /api/sandbox`

Read or replace the sandbox policy YAML.

**GET response:**

```json
{ "content": "features:\n  deny_netlink: true\n  deny_mount: true\n..." }
```

**PUT request body:** same shape — `content` is the raw YAML string.

**PUT** requires a recent **step-up re-authentication**, same as
`PUT /api/sudoers/config` above — see
[Step-up re-authentication](04-configuration.md#step-up-re-authentication-for-sudoerssandbox-pushes)
in Chapter 4. A push also writes an audit-log line and forwards a
`sandbox_config_push` SIEM event. If the new policy removes protection the
previous one had (a feature disabled, or a previously-protected
path/process/socket/binary no longer covered), the agent logs a distinct
`SECURITY WARNING: protection reduced` line when it reloads — this is
detection only, the reload still applies.

---

#### `GET /api/sandbox/templates`

List predefined sandbox policy templates.

**Response:**

```json
{
  "strict": "features:\n  deny_netlink: true\n  deny_mount: true\n...",
  "permissive": "features:\n  deny_netlink: false\n..."
}
```

Keys are template names; values are raw YAML strings.

---

#### `GET / PUT /api/redaction-config`

Read or update output-redaction rules.

**GET response / PUT request body:**

```json
{
  "patterns": [
    "[Pp]assword\\s*[:=]\\s*\\S+",
    "AWS_SECRET_ACCESS_KEY=[A-Za-z0-9+/]+"
  ]
}
```

Patterns are Go regular expressions applied to the terminal output stream.

---

#### `GET / PUT /api/auth-config`

Read or replace the authentication configuration.

**GET response / PUT request body:**

```json
{
  "config": {
    "source": "oidc",
    "oidc": {
      "issuer": "https://accounts.google.com",
      "client_id": "123456.apps.googleusercontent.com",
      "client_secret": "***"
    },
    "proxy": {
      "user_header": "X-Forwarded-User",
      "groups_header": "X-Forwarded-Groups"
    },
    "admin_groups": ["ops-admins"],
    "group_mappings": [
      { "group": "ops-team", "role": "admin" },
      { "group": "dev-team", "role": "viewer" }
    ],
    "step_up_ttl_minutes": 10
  }
}
```

`source` values: `"local"` (htpasswd), `"oidc"`, `"proxy"`.

`step_up_ttl_minutes` — how long a step-up re-authentication for a sudoers/
sandbox push stays valid (see [Step-up re-authentication](04-configuration.md#step-up-re-authentication-for-sudoerssandbox-pushes)
in Chapter 4). Omitted or `0` means the server default (10 minutes). Has no
effect in `"proxy"` mode.

> **Note:** `client_secret` is masked (`"***"`) in GET responses.

> **Note:** CLI flags (`--oidc-issuer`, etc.) take precedence over the database-stored config when both are set.

---

#### `GET / PUT /api/auth-mapping`

Shorthand for reading/updating just the `group_mappings` array. Equivalent to reading/writing the `config.group_mappings` field in `/api/auth-config`.

**GET response / PUT request body:**

```json
[
  { "group": "ops-team", "role": "admin" },
  { "group": "dev-team", "role": "viewer" }
]
```

First matching group wins when a user belongs to multiple groups.

---

#### `GET / PUT /api/blocked-users`

Read or replace the list of users whose sudo sessions are blocked at the log server.

**GET response / PUT request body:**

```json
{ "users": ["badactor", "compromised-account"] }
```

Changes take effect within 30 seconds (the log server polls this file).

---

#### `GET / PUT /api/whitelisted-users`

Read or replace the list of users who bypass JIT approval.

**GET response / PUT request body:**

```json
{ "users": ["ops-bot", "deploy-svc"] }
```

Whitelisted users are still recorded normally — only the JIT approval requirement is skipped.

---

### RBAC

#### `GET /api/me`

Return the authenticated user's identity and permissions.

**No special permission required** (any authenticated user).

**Response:**

```json
{
  "user": "alice",
  "logoutUrl": "/api/oidc/logout",
  "role": "admin",
  "permissions": [
    "sessions:list_own",
    "sessions:list_all",
    "sessions:replay_own",
    "sessions:replay_all",
    "sessions:delete",
    "users:read",
    "users:write",
    "audit_log:read",
    "approvals:read",
    "approvals:decide",
    "config:read",
    "config:write"
  ]
}
```

`logoutUrl` is `""` for local (htpasswd) auth, `/api/oidc/logout` when
`AuthConfig.Source == "oidc"`, or `/oauth2/sign_out` when a trusted-header
proxy is configured. There is no `is_admin` field; check `role` or the
`permissions` array instead.

---

#### `GET /api/users`

List all user accounts.

**Required permission:** `users:read`

**Response:** Array of user objects:

```json
[
  {
    "username": "alice",
    "role": "admin",
    "source": "local",
    "full_name": "",
    "email": "",
    "created_at": "2026-01-10T09:00:00Z",
    "last_login": "2026-06-15T14:30:00Z"
  }
]
```

`source` is one of `"local"`, `"oidc"`, `"proxy"`. `last_login` is omitted
when the user has never logged in. The password hash is never included.

---

#### `PUT /api/users`

Create or update a user account.

**Required permission:** `users:write`

**Request body:**

```json
{
  "username": "bob",
  "role": "viewer"
}
```

For local (htpasswd) auth, include a `"password_hash"` field containing the
new **plaintext** password — despite the field name, this is not a
pre-computed hash; the server bcrypt-hashes it before storing.

---

#### `DELETE /api/users/{username}`

Delete a user account.

**Required permission:** `users:write`

**Response:** `204 No Content`

---

#### `GET /api/roles`

List all role definitions (built-in and custom).

**Required permission:** `users:read`

**Response:**

```json
[
  {
    "name": "admin",
    "permissions": ["sessions:list_own", "sessions:list_all", "..."],
    "built_in": true
  },
  {
    "name": "on-call",
    "permissions": ["sessions:list_all", "sessions:replay_all", "approvals:read", "approvals:decide"],
    "built_in": false
  }
]
```

An optional `"description"` string field may also be present on any role.

---

#### `POST /api/roles`

Create a custom role.

**Required permission:** `users:write`

**Request body:**

```json
{
  "name": "on-call",
  "permissions": ["sessions:list_all", "sessions:replay_all", "approvals:read", "approvals:decide"]
}
```

> **Note:** You cannot assign permissions you do not hold yourself (prevents privilege escalation).

---

#### `PUT /api/roles/{name}`

Replace a custom role's permissions.

**Required permission:** `users:write`

Same body as `POST /api/roles`.

---

#### `DELETE /api/roles/{name}`

Delete a custom role. Built-in roles (`admin`, `viewer`) cannot be deleted.

**Required permission:** `users:write`

**Response:** `204 No Content`

---

#### `GET /api/hosts`

List all hostnames that have at least one recorded session.

**Required permission:** `sessions:list_own` or `sessions:list_all`

**Response:**

```json
{ "hosts": ["web01.example.com", "db01.example.com", "bastion.example.com"] }
```

---

### JIT Approvals

These endpoints are only registered when `--logserver-admin` is configured on the replay server.

#### `GET /api/approvals`

List pending JIT approval requests.

**Required permission:** `approvals:read`

**Response:**

```json
[
  {
    "id": "req_abc123",
    "tsid": "charlie/db01_20260615-160022",
    "user": "charlie",
    "host": "db01.example.com",
    "command": "psql -U postgres production",
    "runas": "root",
    "requested_at": "2026-06-15T16:00:22Z",
    "expires_at": "2026-06-16T16:00:22Z",
    "status": "pending"
  }
]
```

---

#### `POST /api/approvals/{id}/approve`

Approve a pending JIT request. The session is allowed to proceed for `default_window` duration.

**Required permission:** `approvals:decide`

**Request body:** empty (`{}`)

**Response:** `200 OK`

---

#### `POST /api/approvals/{id}/deny`

Deny a pending JIT request. The user's sudo session is terminated with an error message.

**Required permission:** `approvals:decide`

**Request body:**

```json
{ "reason": "Not authorized for production database access outside change window" }
```

`reason` is optional but is displayed to the requesting user and logged.

**Response:** `200 OK`

---

#### `GET / PUT /api/approval-config`

Read or replace the JIT approval policy.

**GET response / PUT request body:**

```json
{
  "config": {
    "enabled": true,
    "default_window": "30m",
    "pending_ttl": "24h",
    "max_session_duration": "2h",
    "exempt": [
      { "user": "ops-bot", "hosts": [] }
    ],
    "notifications": {
      "webhook_url": "https://mattermost.example.com/hooks/xxx",
      "webhook_secret": "***",
      "mention_user": true,
      "request_channel": "sudo-approvals",
      "replay_web_app_url": "https://replay.example.com"
    }
  }
}
```

`webhook_secret` is masked in GET responses.

---

#### `GET / PUT /api/jit-policy`

Read or replace the OPA Rego policy used for JIT decisions.

**Content-Type:** `text/plain` (both GET and PUT)

**GET response / PUT request body:** Raw Rego policy text.

---

### Sudoers

Two distinct things live under `/api/sudoers/*`: **snapshots** (a read-only,
historical record of what `/etc/sudoers` actually contained on each host,
uploaded periodically by the agent) and **config** (the admin-authored
*desired* sudoers policy, staged centrally and pushed out to agents — see
[Sudoers policy management](07-features.md#sudoers-policy-management) in
Chapter 7 for the full push/confirm/step-up workflow).

#### `GET /api/sudoers/hosts`

List every host with a sudoers snapshot, a session, or a staged override —
enriched with staging/sync status so the UI can show it without a second
round trip.

**Required permission:** `config:read`

**Response:**

```json
[
  { "name": "web01", "isOverride": true, "inSync": true, "isOffline": false },
  { "name": "db01", "isOverride": false, "inSync": false, "isOffline": true, "error": "visudo: syntax error" }
]
```

`isOverride` — host has its own staged config, distinct from `sudoers/_default`.
`inSync` — the host's last-reported applied config matches what's staged.
`isOffline` — no heartbeat from this host recently.
`error` — the agent's last reported apply error for this host, if any.

---

#### `GET /api/sudoers/snapshots`

List recent (up to 20) historical snapshots of what `/etc/sudoers` actually
contained on a host, as reported by the agent.

**Required permission:** `config:read`

**Query parameters:** `host` (required)

**Response:**

```json
[
  { "sha256": "abc...", "uploaded_at": 1750000000, "content": "alice ALL=(ALL) ALL\n" },
  { "sha256": "def...", "uploaded_at": 1749900000, "content": "..." }
]
```

---

#### `GET /api/sudoers/config`

Fetch the *staged* (desired) sudoers config for a host — not a historical
snapshot. Falls back to the `_default` template when the host has no
override of its own.

**Required permission:** `config:read`

**Query parameters:** `host` (optional — omitted or empty means the global `_default` template)

**Response:**

```json
{ "host": "web01", "content": "alice ALL=(ALL) ALL\n", "is_override": true }
```

`is_override` is `true` only when `host` was given and that host has its own
staged config distinct from `_default`.

---

#### `PUT /api/sudoers/config`

Stage a sudoers config for a host (or the global `_default` when `host` is
omitted). Validated with `visudo -c` before being stored — invalid syntax is
rejected with `400`, it never reaches a host.

**Required permission:** `config:write`, plus a recent **step-up
re-authentication** (see [Step-up re-authentication](04-configuration.md#step-up-re-authentication-for-sudoerssandbox-pushes)
in Chapter 4) — a request without one gets `403` with
`{"error":"stepup_required","auth_source":"local"|"oidc"|"proxy"}` instead of
being applied. `auth_source` tells the client which re-auth flow to run.

**Query parameters:** `host` (optional)

**Request body:** `{ "content": "alice ALL=(ALL) ALL\n" }`

**Response:** `{ "ok": true }`

Every successful push writes an audit-log line (actor, host/key, a coarse
+/- line-count diff) and forwards a `sudoers_config_push` event through
whatever SIEM/webhook forwarding is configured (`internal/siem.SendAudit`) —
see [Session view / access log](07-features.md#session-view--access-log) in Chapter 7.

---

#### `DELETE /api/sudoers/config`

Remove a host's staged override, reverting it to inherit `_default`.

**Required permission:** `config:write`

**Query parameters:** `host` (required)

**Response:** `{ "ok": true }`

---

### OIDC

#### `GET /api/oidc/login`

Start the OIDC Authorization Code Flow.

**No auth required.**

Redirects to the OIDC provider's authorization endpoint. `state` is a random
CSRF token (not an encoded URL) stored server-side in the `oidc_state`
cookie and checked on callback.

**Query parameters:**
- `stepup=1` — step-up re-authentication for a sudoers/sandbox push (see
  [Step-up re-authentication](04-configuration.md#step-up-re-authentication-for-sudoerssandbox-pushes)
  in Chapter 4) instead of a fresh login: adds `prompt=login` so the IdP
  re-collects credentials even with its own active session, and marks the
  *existing* `sudo_session` step-up-valid on return rather than creating a
  new session.
- `return=/some/path` — same-origin path to redirect back to after a
  `stepup=1` round trip (used so the user lands back on the tab they
  stepped up from, e.g. `/config/sandbox`). Ignored for a plain login,
  which always lands on `/`. Rejected (falls back to `/`) if it's not a
  same-origin relative path — this endpoint guards against open redirects
  since the value is caller-controlled.

---

#### `GET /api/oidc/callback`

OIDC provider redirect target after user authentication.

**No auth required.**

Exchanges the authorization code for tokens, verifies the ID token. For a
plain login: sets a session cookie and redirects to `/`. For a `stepup=1`
login (detected via the `oidc_stepup` cookie set by `/api/oidc/login`):
marks the existing session step-up-valid instead, and redirects to the
`return` path from that flow. Configured via `--oidc-redirect-url` (must
match this URL).

---

#### `POST /api/stepup`

Re-verify the current session's password for **local auth mode only** —
the OIDC equivalent is `GET /api/oidc/login?stepup=1` above; this endpoint
is a no-op path for OIDC/proxy sessions (there's no local password to
check).

**Requires an existing valid `sudo_session` cookie** — re-checks that
session's own username's password, does not accept a username in the body.

**Request body:** `{ "password": "..." }`

**Response:** `204 No Content` on success; `401` on a missing/invalid
session or wrong password.

On success, marks the session step-up-valid for
[the configured TTL](04-configuration.md#step-up-re-authentication-for-sudoerssandbox-pushes)
(default 10 minutes), so a subsequent `PUT /api/sudoers/config` or
`PUT /api/sandbox` within that window won't get another `403
stepup_required`.

---

### Infrastructure

#### `GET /healthz`

**No auth required.**

**Response:** `200 OK`, body: `ok`

Used by load balancers, Kubernetes liveness/readiness probes, and monitoring.

---

#### `GET /metrics`

Prometheus metrics in text exposition format.

**Auth:** Same as the rest of the UI (Basic Auth if `--htpasswd` is configured).

See [Chapter 9 — Prometheus Metrics](09-metrics.md) for the complete metric list and example output.

---

## Log Server Admin API

Requires `--health-listen` to be configured on the log server (e.g. `--health-listen :9877`). All endpoints are plain HTTP (no TLS). Access should be restricted at the network level.

All endpoints except `/healthz` and `/metrics` require `Authorization: Bearer <token>` where the token matches the log server's `--approval-token`.

### `GET /healthz`

**No auth.** Returns `200 OK`, body `ok`.

### `GET /metrics`

**No auth.** Returns Prometheus metrics for the log server (see Chapter 9).

### `DELETE /api/sessions/{tsid}`

Permanently delete a session from storage (GDPR).

**Auth:** Bearer token.

In distributed mode, deletes both the PostgreSQL row and the S3/MinIO objects.

**Response:** `204 No Content`

### `GET /api/approvals`

List pending approval requests. Same response shape as the replay server `GET /api/approvals`.

**Auth:** Bearer token.

### `POST /api/approvals/{id}/approve`

**Auth:** Bearer token. Approve a pending request. `200 OK` on success.

### `POST /api/approvals/{id}/deny`

**Auth:** Bearer token. Body: `{ "reason": "..." }` (optional). `200 OK` on success.

### `GET / PUT /api/approval-config`

**Auth:** Bearer token. Read or replace the approval policy. Same shape as the replay server endpoint.

### `GET / PUT /api/jit-policy`

**Auth:** Bearer token. `Content-Type: text/plain`. Read or replace the OPA Rego policy.

---

## Common patterns

### Pagination

List endpoints that support pagination return a `next_cursor` field. Pass it as `cursor=` in the next request. When `next_cursor` is absent or empty, you have reached the last page.

### Error responses

```json
{ "error": "session not found" }
```

### CORS

The replay server does not set CORS headers. Browser access is expected to be same-origin (the React SPA is served from the same host). For cross-origin integrations, use a reverse proxy.

### Sandbox and SIEM config as raw strings

`PUT /api/sandbox` and `GET/PUT /api/jit-policy` accept/return raw YAML or Rego text (wrapped in a JSON `content` field or as `text/plain` respectively) rather than a parsed JSON schema. This avoids round-trip loss of comments and formatting.
