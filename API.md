# sudo-logger API Reference

This document provides a detailed technical reference for all HTTP API endpoints in the `sudo-logger` system.

---

## 1. Replay Server API (Web UI & Integrations)

The Replay Server (`sudo-replay-server`) provides the endpoints used by the web UI, SIEM systems, and chat integrations (e.g., Slack/Mattermost webhooks). All responses are in `application/json` unless otherwise specified.

### 1.1 Identity & Access Management

#### `GET /api/me`
Returns the currently authenticated user's identity and effective role.
*   **Role Required:** *None* (Open to all authenticated users; unauthenticated users get 401, or fallback to proxy mapping).
*   **Response (200 OK):**
    ```json
    {
      "user": "alice",
      "role": "admin",
      "logoutUrl": "/api/oidc/login"
    }
    ```

#### `GET /api/users`
Lists all users managed in the local database.
*   **Role Required:** `admin`
*   **Response (200 OK):**
    ```json
    [
      {
        "username": "alice",
        "role": "admin",
        "created_at": "2026-06-09T12:00:00Z"
      }
    ]
    ```

#### `PUT / POST /api/users`
Creates or updates a local user. During the very first launch (Bootstrap Mode), this endpoint bypasses authentication to allow creating the initial administrator.
*   **Role Required:** `admin` (or Bootstrap Mode)
*   **Request Body:**
    ```json
    {
      "username": "bob",
      "password": "ExamplePassword123!",
      "role": "viewer"
    }
    ```
    *(Note: If updating an existing user, sending an empty password keeps the existing password hash intact).*
*   **Response (204 No Content)**

#### `DELETE /api/users/{username}`
Permanently deletes a local user.
*   **Role Required:** `admin`
*   **Response (204 No Content)**

#### `GET /api/auth-config`
Retrieves the current authentication strategy (Local, OIDC, Proxy). OIDC client secrets are masked as `***`.
*   **Role Required:** `admin`
*   **Response (200 OK):**
    ```json
    {
      "config": {
        "source": "oidc",
        "oidc": {
          "issuer_url": "https://auth.example.com",
          "client_id": "sudo-logger",
          "client_secret": "***"
        },
        "proxy": {
          "user_header": "",
          "groups_header": ""
        },
        "admin_groups": "sudo-admins"
      }
    }
    ```

#### `PUT /api/auth-config`
Updates the authentication strategy.
*   **Role Required:** `admin`
*   **Request Body:** Same as the `GET` response payload. If `client_secret` is sent as `***`, the existing secret in the database is preserved.
*   **Response (204 No Content)**

#### `PUT /api/auth-mapping`
Updates the mapping of External Groups (from OIDC or Proxy) to the `admin` role.
*   **Role Required:** `admin`
*   **Request Body:**
    ```json
    {
      "admin_groups": "sudo-admins, security-ops"
    }
    ```
*   **Response (204 No Content)**

#### `GET /api/oidc/login`
Redirects the user to the configured OIDC Identity Provider to initiate the OAuth2 flow.
*   **Role Required:** *None*

#### `GET /api/oidc/callback`
Handles the redirect back from the OIDC IdP. Validates the `code` and `state`, exchanges them for an ID token, maps roles based on the `groups` claim, sets the `sudo_session` cookie, and redirects the user to `/`.
*   **Role Required:** *None*

---

### 1.2 Sessions & Playback

#### `GET /api/sessions`
Searches and lists recorded sudo sessions.
*   **Role Required:** `viewer` (Viewers only see their own sessions; Admins see all).
*   **Query Parameters:**
    *   `q` (string): Free-text search query.
    *   `from` (string): Start date/time (e.g., `2026-06-01T00:00:00Z`).
    *   `to` (string): End date/time.
    *   `limit` (int): Max results to return (default 50).
    *   `offset` (int): Pagination offset.
    *   `sort` (string): Field to sort by (e.g., `timestamp`).
    *   `order` (string): `asc` or `desc`.
*   **Response (200 OK):**
    ```json
    [
      {
        "tsid": "0000018f-a1b2-c3d4-e5f6-000000000000",
        "timestamp": "2026-06-09T15:30:00Z",
        "user": "alice",
        "host": "web-prod-01",
        "run_as": "root",
        "command": "/bin/bash",
        "duration_ms": 45000,
        "risk_score": 15,
        "status": "complete"
      }
    ]
    ```

#### `GET /api/session/events?tsid={id}`
Streams the raw TTY playback events for the asciinema player.
*   **Role Required:** `viewer` (must own the session unless admin).
*   **Response (200 OK):** Newline-delimited JSON (Asciinema v2 format).
    ```json
    {"version": 2, "width": 80, "height": 24, "timestamp": 1717947000}
    [0.105, "o", "root@web-prod-01:~# "]
    [1.023, "o", "ls -l\r\n"]
    ```

#### `DELETE /api/sessions/{tsid}`
Permanently deletes a session and its associated recordings from disk/S3 (GDPR Right to Erasure).
*   **Role Required:** `admin`
*   **Request Body:**
    ```json
    {
      "reason": "Accidental exposure of sensitive PII in terminal output."
    }
    ```
*   **Response (204 No Content)**

#### `GET /api/access-log`
Returns the audit log detailing who has viewed or deleted which session replays.
*   **Role Required:** `admin`
*   **Response (200 OK):**
    ```json
    [
      {
        "timestamp": "2026-06-09T16:00:00Z",
        "action": "view",
        "actor": "bob",
        "target_tsid": "0000018f-a1b2-c3d4-e5f6-000000000000"
      }
    ]
    ```

#### `GET /api/hosts`
Returns a unique list of all hostnames that have ever submitted a session. Used for UI filtering dropdowns.
*   **Role Required:** `viewer`
*   **Response (200 OK):** `["web-prod-01", "db-main-02"]`

---

### 1.3 Just-In-Time (JIT) Approvals

#### `GET /api/approvals`
Lists pending, active, and recently expired JIT sudo approval requests.
*   **Role Required:** `admin`
*   **Response (200 OK):**
    ```json
    [
      {
        "id": "req-12345",
        "user": "alice",
        "host": "db-main-02",
        "reason": "Restarting stuck postgres process",
        "status": "pending",
        "requested_at": "2026-06-09T16:05:00Z",
        "expires_at": "2026-06-09T16:15:00Z"
      }
    ]
    ```

#### `POST /api/approvals/{id}`
Approves or denies a pending JIT request.
*   **Role Required:** `admin`
*   **Request Body:**
    ```json
    {
      "action": "approve"
    }
    ```
    *(Action can be `"approve"` or `"deny"`).*
*   **Response (200 OK):** Returns the updated approval object.

#### `PUT /api/approvals/{id}`
Revokes an already approved, active window before it expires naturally.
*   **Role Required:** `admin`
*   **Response (200 OK)**

#### `GET /api/approval-config` & `PUT /api/approval-config`
Manages the global configuration for JIT approvals (timeouts, slack webhook URLs).
*   **Role Required:** `admin`
*   **Request/Response Format:**
    ```json
    {
      "enabled": true,
      "default_duration_minutes": 60,
      "webhook_url": "https://hooks.slack.com/services/...",
      "require_justification": true
    }
    ```

#### `POST /api/approvals/callback`
Webhook endpoint designed to receive interactive button clicks directly from Slack or Mattermost.
*   **Role Required:** *None* (Protected by HMAC-SHA256 signature validation against the webhook secret).
*   **Request Body:** URL-encoded payload per Slack/Mattermost specifications.

#### `GET /api/jit-policy`
Public endpoint used by the `sudo-logger-agent` to evaluate whether the current user on the current host requires a justification prompt before executing sudo.
*   **Role Required:** *None*

---

### 1.4 Centralised Sudoers Management

#### `GET /api/sudoers/hosts`
Lists all host machines and their current sudoers configuration sync status.
*   **Role Required:** `admin`
*   **Response (200 OK):**
    ```json
    [
      {
        "hostname": "web-prod-01",
        "status": "in_sync",
        "last_seen": "2026-06-09T16:10:00Z",
        "applied_sha256": "abcdef123456..."
      }
    ]
    ```

#### `GET /api/sudoers/snapshots?host={hostname}`
Retrieves the history of applied sudoers file versions for a host.
*   **Role Required:** `admin`

#### `GET /api/sudoers/config?host={hostname}`
Retrieves the staged sudoers configuration (YAML or raw sudoers text) for a host. If `host=_default`, retrieves the global template.
*   **Role Required:** `admin`

#### `PUT /api/sudoers/config?host={hostname}`
Saves a new staged configuration.
*   **Role Required:** `admin`
*   **Request Body:** Raw text payload containing the `sudoers` file content.
*   **Response (204 No Content)**

#### `DELETE /api/sudoers/config?host={hostname}`
Deletes the specific host override, forcing the agent on that host to fall back to the `_default` global template on its next check-in.
*   **Role Required:** `admin`
*   **Response (204 No Content)**

---

### 1.5 System Configuration & Policies

All endpoints in this section require the `admin` role and use `GET` to retrieve and `PUT` to update configurations.
Responses and Requests share the same JSON shapes.

*   `GET / PUT /api/rules` — Risk scoring engine rules (`risk-rules.yaml` format).
*   `GET / PUT /api/sandbox` — eBPF process sandbox restrictions (preventing sudo from modifying specific files/sockets).
*   `GET / PUT /api/blocked-users` — Array of strings representing users/hosts strictly blocked from executing sudo.
*   `GET / PUT /api/whitelisted-users` — Array of strings representing users exempt from JIT approval prompts.
*   `GET / PUT /api/retention` — Data retention policy (e.g., `{"days_to_keep": 90}`).
*   `GET / PUT /api/siem-config` — Configuration for forwarding events to a remote SIEM (Syslog, HTTP, or stdout).
*   `PUT /api/siem-cert` — Multipart form-data upload for SIEM mTLS certificates (`ca`, `cert`, `key`).

---

### 1.6 Health & Metrics

#### `GET /healthz`
Kubernetes Readiness/Liveness probe.
*   **Role Required:** *None*
*   **Response (200 OK):** `ok\n`

#### `GET /metrics`
Prometheus metrics exposition.
*   **Role Required:** *None*
*   **Response (200 OK):** Prometheus text format containing active sessions, risk distributions, and JIT request counts.

#### `GET /api/report`
Generates a high-level summary report for the UI dashboard (total sessions, high-risk counts, anomaly charts).
*   **Role Required:** `viewer` (returns 200 OK with aggregated JSON statistics).

---

## 2. Log Server API (Agent Facing)

The Log Server (`sudo-logserver`) provides endpoints strictly used by the `sudo-logger-agent` binary running on the monitored host machines.

> **Security Note:** These endpoints are highly sensitive and should never be exposed to the public internet. Authentication is handled via mTLS (Mutual TLS) using client certificates deployed to the agents.

| Method | Endpoint | Description | Payload Format |
| :--- | :--- | :--- | :--- |
| `GET` | `/healthz` | Readiness/Liveness probe. | N/A |
| `POST` | `/api/agent/session` | Called immediately when a user types `sudo`. The agent transmits the command metadata (user, host, command, cwd, env). The server evaluates JIT and Block policies and responds with `allow`, `deny`, or `require_approval`. | JSON |
| `POST` | `/api/agent/events` | Streams the real-time TTY I/O payload chunks to the server for an active session. Uses a custom chunked binary or JSON format depending on config. | Binary/JSON Stream |
| `POST` | `/api/agent/heartbeat` | Periodic check-in from active sessions (every ~3s). Used by the server's watchdog to detect if a host has gone offline or if the agent was forcefully killed. | JSON |
| `POST` | `/api/agent/approval` | Submits a JIT justification string to the server. The agent then polls or waits for a server push to determine if the admin approved the request. | JSON |
| `GET` | `/api/agent/sudoers` | Checks for new centralised sudoers configuration updates specifically staged for the agent's hostname. The agent downloads it, runs `visudo -c`, and applies it atomically. | JSON |
