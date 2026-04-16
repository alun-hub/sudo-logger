# JIT-åtkomst för sudo — TODO

> Planerad funktion: Kräv en giltig tidsbegränsad biljett innan sudo tillåts.
> Auto-approve via policy-regler. Webhook-notifikation till externt system.

## Flöde

```
sudo <cmd>
  │
  ▼
plugin_open() → SESSION_START → shipper
  │
  ▼
shipper: GET /api/jit/validate?user=X&host=Y&cmd=Z  (replay-server)
  │
  ├─ Giltig biljett        → SESSION_READY  → sudo körs
  ├─ Auto-approve matchar  → skapar biljett + webhook → SESSION_READY
  └─ Ingen biljett/nekas   → SESSION_DENIED
       "Ingen JIT-biljett. Kör: sudo-jit request --duration 4h"
```

## Komponenter

### Protokoll
- `go/internal/protocol/protocol.go` — lägg till `MsgSessionDenied = 0x0b`
- `plugin/plugin.c` rad ~640 — hantera `MSG_SESSION_DENIED` med tydligt banner

### Shipper
- `go/cmd/shipper/main.go` rad ~328 — anropa JIT-validate innan SESSION_READY
- Ny config i `shipper.conf`: `JIT_ENDPOINT`, `JIT_TIMEOUT` (fail-open/closed)

### Replay-server (nya endpoints)
- `GET  /api/jit/validate` — shipper frågar om giltig biljett
- `POST /api/jit/request`  — användare/CLI begär biljett
- `GET  /api/jit/tickets`  — lista aktiva biljetter
- `DELETE /api/jit/tickets/{id}` — återkalla biljett

### Nya interna paket
- `go/internal/jit/store.go`   — in-memory biljett-store + JSON-persistens
- `go/internal/jit/policy.go`  — policy-engine (läser jit-policy.yaml)
- `go/internal/jit/webhook.go` — webhook-sändare (likt siem/sender.go)
- `go/internal/jit/client.go`  — HTTP-klient för shipper → replay-server

### CLI
- `go/cmd/sudo-jit/main.go` — `sudo-jit request/list/revoke`

### Konfiguration (ny fil)
- `configs/jit-policy.yaml` → installeras som `/etc/sudo-logger/jit-policy.yaml`

```yaml
enabled: true

auto_approve:
  - name: "ops-all-hours"
    match:
      groups: ["ops", "sre"]
      commands: [".*"]
    ticket_duration: 4h
  - name: "dev-readonly"
    match:
      groups: ["dev"]
      commands: ["^/usr/bin/journalctl", "^/bin/systemctl status"]
    ticket_duration: 2h

deny_patterns:
  - "^/bin/rm\\s+-rf"
  - "^/usr/bin/dd"

webhook:
  enabled: true
  url: ""
  events: ["ticket_created", "ticket_denied", "ticket_expired"]
```

### RPM
- `rpm/sudo-logger-replay.spec` — ny config-fil + ny binary `sudo-jit`

## Webhook-payload (exempel)

```json
{
  "event": "ticket_created",
  "ticket_id": "abc123",
  "user": "alice",
  "host": "prod-db-01",
  "expires_at": "2026-04-05T18:00:00Z",
  "auto_approved": true,
  "policy_rule": "ops-all-hours"
}
```

## Verifiering

1. Enhetstest policy-engine: grupper, kommandomönster, tidsfönster, deny-patterns
2. Integrationstest: `sudo true` utan biljett → SESSION_DENIED
3. Manuellt: `sudo-jit request --duration 1h` → `sudo true` → SESSION_READY
4. Webhook: verifiera `ticket_created`-event vid auto-approve
5. Fail-open: stäng replay-server → verifiera beteende per `JIT_TIMEOUT`-config
6. Återkalla: `sudo-jit revoke <id>` → `sudo true` → SESSION_DENIED
