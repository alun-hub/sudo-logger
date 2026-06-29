# sudo-logger → Elasticsearch / Kibana

This directory contains an Elasticsearch index template, ILM policy, and a
Kibana dashboard for sudo-logger SIEM events.

## Prerequisites

- Elasticsearch 8.x + Kibana 8.x (OpenSearch 2.x works with minor mapping adjustments)
- sudo-logger replay-server configured with SIEM forwarding (`format: json`, `transport: https`)
- Logstash, Elastic Agent, or a custom ingest pipeline to route events to the index

## Step 1 — Create the ILM policy

```bash
curl -X PUT "https://your-es:9200/_ilm/policy/sudo-logger-policy" \
  -H "Content-Type: application/json" \
  -u elastic:$ES_PASSWORD \
  -d @ilm-policy.json
```

This policy rolls over at 5 GB or 30 days, moves to warm after 30 days, cold
after 90 days, and deletes after 365 days. Adjust to match your retention
requirements.

## Step 2 — Apply the index template

```bash
curl -X PUT "https://your-es:9200/_index_template/sudo-logger" \
  -H "Content-Type: application/json" \
  -u elastic:$ES_PASSWORD \
  -d @index-template.json
```

## Step 3 — Create the write alias

```bash
curl -X PUT "https://your-es:9200/sudo-logger-000001" \
  -H "Content-Type: application/json" \
  -u elastic:$ES_PASSWORD \
  -d '{"aliases":{"sudo-logger":{"is_write_index":true}}}'
```

## Step 4 — Configure sudo-logger SIEM forwarding

In `/etc/sudo-logger/siem.yaml` on the replay server:

```yaml
enabled: true
transport: https
format: json
https:
  url: https://logstash.internal:8080/sudo-logger
  token: your-logstash-bearer-token
replay_url_base: https://replay.example.com
```

Or use Logstash with an HTTP input to receive events and index them:

```
input {
  http {
    port => 8080
    codec => json
  }
}
filter {
  mutate {
    add_field => { "@timestamp" => "%{start_time}" }
  }
}
output {
  elasticsearch {
    hosts => ["https://your-es:9200"]
    index => "sudo-logger"
    user => "logstash_writer"
    password => "${ES_PASSWORD}"
  }
}
```

## Step 5 — Import the Kibana dashboard

In Kibana: **Stack Management → Saved Objects → Import** → select `dashboard.ndjson`.

The dashboard includes:

| Panel | Description |
|---|---|
| Sessions over time | Bar chart of session count by day |
| Top users | Horizontal bar of users with most sessions |
| Risk score distribution | Histogram across Low/Medium/High/Critical bands |
| High-risk sessions | Sortable table of sessions with risk_score ≥ 50 |
| Incomplete sessions | Count of sessions where the agent lost the connection mid-recording |

## Event schema

Each event is a flat JSON object with these fields:

| Field | Type | Description |
|---|---|---|
| `session_id` | keyword | Unique session identifier |
| `user` | keyword | Username that ran sudo |
| `host` | keyword | Hostname where sudo ran |
| `runas` | keyword | User the command ran as (usually root) |
| `runas_uid` / `runas_gid` | integer | UID/GID of the runas user |
| `command` | text+keyword | Command string |
| `resolved_command` | keyword | Fully resolved binary path |
| `cwd` | keyword | Working directory at session start |
| `flags` | keyword | sudo flags (login_shell, preserve_env, etc.) |
| `start_time` | date | Session start (RFC 3339) |
| `end_time` | date | Session end (RFC 3339) |
| `duration_s` | float | Duration in seconds |
| `exit_code` | integer | Exit code of the sudo process |
| `incomplete` | boolean | True if the agent lost connection before SESSION_END |
| `risk_score` | integer | 0–100 score from risk-scoring rules |
| `risk_reasons` | keyword[] | Rule names that contributed to the score |
| `replay_url` | keyword | Direct link to the session in the replay UI |
