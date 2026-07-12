# Prometheus Metrics

## Overview

Two components expose Prometheus metrics in the standard text exposition format (version 0.0.4). Neither component uses the Prometheus Go client library — metrics are written directly with `fmt.Fprintf` calls, so the output is a minimal hand-crafted text payload.

| Component | Endpoint | Port | Authentication |
|---|---|---|---|
| Replay server | `GET /metrics` | 8080 (or `--listen`) | None — always unauthenticated, regardless of `--htpasswd`/OIDC/`--trusted-user-header` |
| Log server | `GET /metrics` | configured via `--health-listen` | None (plain HTTP, no auth) |

> **Note:** The log server metrics endpoint is disabled by default. It is activated only when `--health-listen` is set (for example `--health-listen :9877`). The endpoint serves plain HTTP with no authentication — restrict access with a firewall rule or network policy.

> **Note:** The replay server's `basicAuthMiddleware` explicitly bypasses `/metrics` (alongside `/healthz`, `/login`, OIDC endpoints, and static assets) before checking any auth configuration — see `go/cmd/replay-server/middleware.go`. This means `/metrics` is unauthenticated even when `--htpasswd`, OIDC, or `--trusted-user-header` is configured for the rest of the UI. Restrict access to this port with a firewall rule or network policy if that matters for your deployment; do not rely on Basic Auth credentials to protect it.

---

## Replay-server metrics

The replay server exposes metrics at `GET /metrics` on its main listen port. The handler (`handleMetrics` in `go/cmd/replay-server/handlers_session.go`) queries the session cache and emits five metric families.

| Metric | Type | Description |
|---|---|---|
| `sudoreplay_sessions_total` | gauge | Total number of sessions in storage (all time, not reset on restart) |
| `sudoreplay_sessions_active` | gauge | Sessions currently being recorded (connection from agent still open) |
| `sudoreplay_sessions_incomplete` | gauge | Sessions that ended without clean termination (marker file `INCOMPLETE` present) |
| `sudoreplay_sessions_by_risk{level="low"}` | gauge | Sessions with risk level `low` |
| `sudoreplay_sessions_by_risk{level="medium"}` | gauge | Sessions with risk level `medium` |
| `sudoreplay_sessions_by_risk{level="high"}` | gauge | Sessions with risk level `high` |
| `sudoreplay_sessions_by_risk{level="critical"}` | gauge | Sessions with risk level `critical` |
| `sudoreplay_session_views_total` | counter | Total session views via the replay UI since the last server restart |

All `sudoreplay_sessions_*` gauge values are computed from the in-process session cache at request time and reflect the current state of storage. `sudoreplay_session_views_total` is an in-memory counter that resets to zero on restart.

### Example output

```
# HELP sudoreplay_sessions_total Total number of recorded sessions.
# TYPE sudoreplay_sessions_total gauge
sudoreplay_sessions_total 1234

# HELP sudoreplay_sessions_active Sessions currently being recorded.
# TYPE sudoreplay_sessions_active gauge
sudoreplay_sessions_active 3

# HELP sudoreplay_sessions_incomplete Sessions that ended without clean termination.
# TYPE sudoreplay_sessions_incomplete gauge
sudoreplay_sessions_incomplete 12

# HELP sudoreplay_sessions_by_risk Number of sessions per risk level.
# TYPE sudoreplay_sessions_by_risk gauge
sudoreplay_sessions_by_risk{level="low"} 800
sudoreplay_sessions_by_risk{level="medium"} 300
sudoreplay_sessions_by_risk{level="high"} 100
sudoreplay_sessions_by_risk{level="critical"} 34

# HELP sudoreplay_session_views_total Total session views via the replay UI since last restart.
# TYPE sudoreplay_session_views_total counter
sudoreplay_session_views_total 567
```

---

## Log-server metrics

The log server exposes metrics at `GET /metrics` on the address configured by `--health-listen`. The endpoint is served on a separate plain-HTTP listener (the main listener is TLS-only). When `--health-listen` is not set the endpoint is not available.

| Metric | Type | Description |
|---|---|---|
| `sudologger_sessions_active` | gauge | Sessions currently being recorded (open connections from agents) |
| `sudologger_sessions_total` | counter | Sessions closed (cleanly or otherwise) since the last server restart |
| `sudologger_sessions_incomplete_total` | counter | Sessions that ended without a `SESSION_END` message since the last server restart |

The two counters (`sudologger_sessions_total` and `sudologger_sessions_incomplete_total`) reset to zero on restart. The gauge (`sudologger_sessions_active`) reflects the current live count.

### Example output

```
# HELP sudologger_sessions_active Sessions currently being recorded.
# TYPE sudologger_sessions_active gauge
sudologger_sessions_active 5

# HELP sudologger_sessions_total Sessions closed since last restart.
# TYPE sudologger_sessions_total counter
sudologger_sessions_total 8421

# HELP sudologger_sessions_incomplete_total Sessions that ended without SESSION_END since last restart.
# TYPE sudologger_sessions_incomplete_total counter
sudologger_sessions_incomplete_total 14
```

---

## Scraping configuration

Add both endpoints to your `prometheus.yml`. Neither endpoint requires credentials — both are unauthenticated regardless of any Basic Auth/OIDC configured elsewhere — but the replay server's `/metrics` is reachable on its normal listen port while the log server's is only reachable when `--health-listen` is set.

```yaml
scrape_configs:
  # Replay server — /metrics bypasses Basic Auth/OIDC/trusted-header auth
  # unconditionally (see go/cmd/replay-server/middleware.go). No credentials
  # needed; restrict access at the network level instead if that matters.
  - job_name: sudo-logger-replay
    static_configs:
      - targets:
          - replay.example.internal:8080
    metrics_path: /metrics
    scheme: http   # or https when --tls-cert is configured

  # Log server — plain HTTP on the --health-listen port.
  # Restrict access at the network level; no authentication is applied.
  - job_name: sudo-logger-server
    static_configs:
      - targets:
          - logserver.example.internal:9877
    metrics_path: /metrics
    scheme: http
```

> **Warning:** Neither `/metrics` endpoint is authenticated. The log server's is plain HTTP with no TLS either. Do not expose port 9877 (or whichever port `--health-listen` is set to), or the replay server's listen port if metrics exposure is a concern, on a public interface. Use a host-based firewall (`firewalld`, `iptables`) or Kubernetes `NetworkPolicy` to limit access to the Prometheus scraper.

---

## Alerting examples

The following alerting rules cover the most operationally significant conditions. Add them to a `sudo-logger-alerts.yaml` rule file and reference it from `prometheus.yml`.

```yaml
groups:
  - name: sudo-logger
    rules:

      # Alert when sessions are ending without a clean SESSION_END.
      # A sustained rise in this counter indicates network interruptions between
      # agents and the log server, or agents crashing mid-session.
      - alert: SudoLoggerIncompleteSessionsRising
        expr: increase(sudologger_sessions_incomplete_total[15m]) > 5
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "sudo-logger: incomplete sessions rising"
          description: >
            {{ $value | humanize }} sessions ended without SESSION_END in the
            last 15 minutes. Check agent connectivity to the log server and
            review journalctl -u sudo-logger-agent on affected hosts.

      # Alert when the number of simultaneously active sessions spikes.
      # An unusually high value may indicate a runaway process or a scripted
      # mass-login event that warrants investigation.
      - alert: SudoLoggerActiveSessionsHigh
        expr: sudoreplay_sessions_active > 50
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "sudo-logger: high number of active sessions"
          description: >
            {{ $value }} sessions are currently being recorded, which is above
            the expected threshold. Investigate for automated scripts or
            credential-sharing behaviour.

      # Alert when the log server's metrics endpoint becomes unreachable.
      # This fires when --health-listen is configured and the scrape fails,
      # indicating the log server process is down or the port is blocked.
      - alert: SudoLogServerDown
        expr: up{job="sudo-logger-server"} == 0
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "sudo-logger: log server is unreachable"
          description: >
            The Prometheus scrape of the log server metrics endpoint has failed
            for 2 minutes. New sudo sessions on monitored hosts will be blocked
            until the log server is restored. Check: systemctl status
            sudo-logserver on the log server host.
```

---

## Metric interpretation guide

### Replay-server gauges vs log-server counters

The two components expose overlapping but not identical data. Understanding the distinction is important when building dashboards or alerts.

**`sudoreplay_sessions_total`** (replay server, gauge) counts every session that exists in storage, including sessions from before the last server restart. This number should only ever increase. If it decreases, sessions were deleted (via the retention API or manual cleanup).

**`sudologger_sessions_total`** (log server, counter) counts sessions closed since the last log server restart. It resets to zero on restart. Use `increase(sudologger_sessions_total[1h])` to see the session rate rather than the raw value.

**`sudoreplay_sessions_active`** (replay server) and **`sudologger_sessions_active`** (log server) should agree when both components access the same storage. A persistent discrepancy indicates the replay server's session cache is stale or a session was not properly closed on the log server.

**`sudoreplay_sessions_incomplete`** (replay server, gauge) reflects the current count of sessions with an `INCOMPLETE` marker file on disk. This is not a per-restart counter — it reflects history. It should remain low on a healthy deployment. A sustained count above zero can indicate recurring network interruptions between agents and the log server, or agents that were killed without a clean shutdown.

**`sudologger_sessions_incomplete_total`** (log server, counter) counts only the incomplete sessions seen since the last restart. Use `increase(sudologger_sessions_incomplete_total[5m]) > 0` to alert on a sudden burst.

### Session risk distribution

The `sudoreplay_sessions_by_risk` labels (`low`, `medium`, `high`, `critical`) are derived from the risk scoring rules in `/etc/sudo-logger/risk-rules.yaml`. A shift in the distribution — for example, a sudden rise in `critical` sessions — can indicate that a new command pattern is being used or that an operator ran an unusual command. The total across all levels should equal `sudoreplay_sessions_total` once all sessions have been scored (scoring is done lazily by the replay server on first access).

### Detecting log server downtime from the replay server

When the log server is down, agents block new sudo sessions. The replay server does not directly track log server availability. To detect log server downtime from Prometheus, use the `up{job="sudo-logger-server"}` metric (which requires `--health-listen` to be configured on the log server) or monitor the rate at which new sessions appear in `sudoreplay_sessions_total`.

---

## Grafana dashboard notes

There is no pre-built Grafana dashboard in the repository, but the following panel queries are useful starting points.

**Sessions recorded per hour:**
```promql
increase(sudologger_sessions_total[1h])
```

**Incomplete session rate (last 15 min):**
```promql
increase(sudologger_sessions_incomplete_total[15m])
```

**Current active sessions:**
```promql
sudoreplay_sessions_active
```

**Risk distribution (stacked bar):**
```promql
sudoreplay_sessions_by_risk
```
Use a bar chart panel with `level` as the legend field.

**Session view rate (replay UI usage):**
```promql
increase(sudoreplay_session_views_total[1h])
```

> **Note:** `sudoreplay_session_views_total` resets on replay server restart. Use `increase()` rather than `rate()` for this counter since restarts cause counter resets that `rate()` handles automatically, but `increase()` is more intuitive for infrequent event counts.

---

## Verifying metrics manually

Both endpoints can be tested with `curl` before Prometheus is configured.

**Replay server (no credentials needed — `/metrics` always bypasses auth):**

```bash
curl -s http://localhost:8080/metrics
```

**Log server health port:**

```bash
curl -s http://localhost:9877/metrics
```

Expected output starts with `# HELP` lines followed by `# TYPE` and metric value lines in the Prometheus text format. If the log server endpoint returns a connection refused error, confirm that `--health-listen` is set in the `sudo-logserver` service file:

```bash
systemctl cat sudo-logserver | grep health-listen
```

A `401 Unauthorized` from the replay server's `/metrics` would indicate a bug — the endpoint is designed to bypass the auth middleware entirely (see `basicAuthMiddleware` in `go/cmd/replay-server/middleware.go`). A 401 elsewhere in the UI is unrelated to `/metrics` access.

---

## Content-Type header

Both endpoints set `Content-Type: text/plain; version=0.0.4; charset=utf-8` on all responses, which matches the Prometheus text exposition format 0.0.4 specification. Prometheus client libraries and the Prometheus server recognise this header and parse the response correctly. The header is set in the handler code regardless of whether any metrics are available, so an empty metric set (all values zero) still returns `200 OK` with the correct content type.

---

## Authentication considerations

### Replay server

The `/metrics` endpoint is served by the same HTTP mux as all other routes, but `basicAuthMiddleware` explicitly allow-lists it (alongside `/healthz`, `/login`, OIDC endpoints, and static assets) and returns before checking any auth configuration. This means:

- `/metrics` is **always unauthenticated** — regardless of `--htpasswd`, OIDC, or `--trusted-user-header` being configured for the rest of the UI.
- No scraper account or credentials are needed, and none can be created for this endpoint specifically.
- If this exposure is a concern, restrict access at the network level (firewall rule, Kubernetes `NetworkPolicy`, or an Ingress rule that blocks `/metrics` from outside the cluster) rather than relying on the application's auth layer.

### Log server

The log server's `/metrics` endpoint (on `--health-listen`) has no authentication. The intent is that this port is only reachable from the Prometheus scraper, not from general network traffic. Enforce this at the network level:

```bash
# Allow only the Prometheus scraper host to reach port 9877
firewall-cmd --zone=internal --add-rich-rule='rule family=ipv4 source address=<prometheus-ip>/32 port port=9877 protocol=tcp accept'
firewall-cmd --zone=public --add-rich-rule='rule family=ipv4 port port=9877 protocol=tcp drop'
```
