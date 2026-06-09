# sudo-logger API Reference

This document outlines the HTTP API endpoints provided by the `sudo-logger` system. The system consists of two main API services: the **Replay Server** (UI and admin API) and the **Log Server** (internal agent-facing API).

---

## 1. Replay Server API

The Replay Server (`sudo-replay-server`) provides the endpoints used by the web UI and external integrations (like SIEMs or approval webhooks).

### Authentication & Authorization

Most `/api/*` endpoints require authentication. The required role (`viewer` or `admin`) depends on the endpoint.
Authentication is handled dynamically via the chosen **Authentication Strategy** (Local Database with Basic Auth, OIDC, or External Proxy).

- **Viewer Role:** Can access own sessions and replay them.
- **Admin Role:** Can access all sessions, access logs, configurations, approvals, and delete sessions.

### Identity & Access Management

| Method | Endpoint | Role | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/me` | *Any* | Returns the currently authenticated user's identity and role (`{"user": "name", "role": "admin|viewer"}`). |
| `GET` | `/api/users` | `admin` | Lists all locally managed users. |
| `PUT` / `POST` | `/api/users` | `admin`* | Creates or updates a local user. *(Allowed without auth during initial Bootstrap)*. |
| `DELETE` | `/api/users/{username}` | `admin` | Permanently deletes a local user. |
| `GET` | `/api/auth-config` | `admin` | Returns the current authentication strategy (Local, OIDC, Proxy) and settings. |
| `PUT` | `/api/auth-config` | `admin` | Updates the authentication strategy and settings. |
| `PUT` | `/api/auth-mapping` | `admin` | Updates the OIDC/Proxy group-to-admin role mapping. |
| `GET` | `/api/oidc/login` | *None* | Redirects an unauthenticated user to the configured OIDC IdP. |
| `GET` | `/api/oidc/callback` | *None* | Handles the callback from the OIDC IdP, establishes the session, and redirects to `/`. |

### Sessions & Playback

| Method | Endpoint | Role | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/sessions` | `viewer` | Lists recorded sessions. Admins see all sessions; viewers see only their own. Supports query params `q`, `from`, `to`, `sort`, `order`, `limit`, `offset`. |
| `GET` | `/api/session/events?tsid={id}`| `viewer` | Retrieves the raw playback events (asciinema v2 format) for a specific session. |
| `DELETE`| `/api/sessions/{tsid}` | `admin` | Permanently deletes a session and its associated files (GDPR Right to Erasure). Requires a JSON body `{"reason": "..."}`. |
| `GET` | `/api/access-log` | `admin` | Returns the audit log of who has viewed which session replays. |
| `GET` | `/api/hosts` | `viewer` | Returns a unique list of hostnames that have recorded sessions. |

### Just-In-Time (JIT) Approvals

| Method | Endpoint | Role | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/approvals` | `admin` | Lists all pending and active JIT sudo approval requests and windows. |
| `POST` | `/api/approvals/{id}` | `admin` | Approves (`{"action": "approve"}`) or denies (`{"action": "deny"}`) a specific JIT request. |
| `PUT` | `/api/approvals/{id}` | `admin` | Revokes an already active approval window early. |
| `GET` | `/api/approval-config` | `admin` | Retrieves the JIT approval configuration and webhook settings. |
| `PUT` | `/api/approval-config` | `admin` | Updates the JIT approval configuration. |
| `POST` | `/api/approvals/callback`| *None* | Webhook callback endpoint used by interactive Slack/Mattermost messages to approve/deny requests. Protected by HMAC signature. |
| `GET` | `/api/jit-policy` | *None* | Returns public JIT policy requirements (used by the agent when evaluating if it should prompt for justification). |

### Centralised Sudoers Management

| Method | Endpoint | Role | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/sudoers/hosts` | `admin` | Lists all hosts checking in for sudoers configuration, along with their sync status. |
| `GET` | `/api/sudoers/snapshots` | `admin` | Retrieves the history of applied sudoers snapshots for a specific host. |
| `GET` | `/api/sudoers/config` | `admin` | Retrieves the staged sudoers configuration for a specific host (or the global `_default` template). |
| `PUT` | `/api/sudoers/config` | `admin` | Saves a new staged sudoers configuration for a specific host or template. |
| `DELETE`| `/api/sudoers/config` | `admin` | Deletes a host-specific override, forcing it to fall back to the `_default` template. |

### Policies & Configuration

| Method | Endpoint | Role | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/rules` | `admin` | Retrieves the risk scoring rules (`risk-rules.yaml`). |
| `PUT` | `/api/rules` | `admin` | Updates the risk scoring rules. |
| `GET` | `/api/sandbox` | `admin` | Retrieves the eBPF process sandbox configuration. |
| `PUT` | `/api/sandbox` | `admin` | Updates the eBPF process sandbox configuration. |
| `GET` | `/api/sandbox/templates`| `admin` | Retrieves pre-defined sandbox templates (LocalStore only). |
| `GET` | `/api/blocked-users` | `admin` | Retrieves the list of blocked users/hosts. |
| `PUT` | `/api/blocked-users` | `admin` | Updates the blocked users list. |
| `GET` | `/api/whitelisted-users`| `admin` | Retrieves the list of JIT approval whitelisted users. |
| `PUT` | `/api/whitelisted-users`| `admin` | Updates the whitelisted users. |
| `GET` | `/api/retention` | `admin` | Retrieves data retention policies. |
| `PUT` | `/api/retention` | `admin` | Updates data retention policies. |
| `GET` | `/api/siem-config` | `admin` | Retrieves SIEM forwarding configuration. |
| `PUT` | `/api/siem-config` | `admin` | Updates SIEM forwarding configuration. |
| `PUT` | `/api/siem-cert` | `admin` | Uploads TLS certificates (CA, Client Cert, Client Key) for SIEM forwarding. |

### System & Metrics

| Method | Endpoint | Role | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/healthz` | *None* | Readiness/Liveness probe for Kubernetes. Returns `ok`. |
| `GET` | `/metrics` | *None* | Prometheus metrics (session views, risk distributions). |
| `GET` | `/api/report` | `viewer` | Generates a high-level summary report (session counts, anomalies) for the UI dashboard. |

---

## 2. Log Server API (Agent Facing)

The Log Server (`sudo-logserver`) provides endpoints strictly used by the `sudo-logger-agent` running on the monitored host machines. **These endpoints are highly sensitive and should generally only be accessible from internal networks.** Authentication is handled via mTLS.

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/healthz` | Readiness/Liveness probe. Returns `ok`. |
| `POST` | `/api/agent/session` | Called when a new sudo session starts. Transmits session metadata and evaluates JIT/Block policies. |
| `POST` | `/api/agent/events` | Streams the real-time TTY I/O payload chunks to the server for an active session. |
| `POST` | `/api/agent/heartbeat` | Periodic check-in from active sessions. Identifies network outages. |
| `POST` | `/api/agent/approval` | Submits a JIT justification request to the server, waiting for admin approval. |
| `GET` | `/api/agent/sudoers` | Checks for new centralised sudoers configuration updates for the agent's host. |
