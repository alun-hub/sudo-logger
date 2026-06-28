# Plan 02 — Test Coverage

**Goal:** Raise test coverage on critical paths to ≥60%. Prioritise the code that can
cause data loss, terminal freeze, or silent audit gaps.

**Current state (2026-06-28):**
```
cmd/agent          15.2%  ← freeze logic, ACK handling
cmd/replay-server  11.3%
cmd/server         32.5%
internal/config     0.0%
internal/store     20.6%  ← approval, sudoers, heartbeat all at 0%
internal/iolog     69.4%  (already decent)
internal/protocol  64.9%  (already decent)
internal/siem      46.1%
```

**Why it matters:** For a security tool that freezes user terminals, 15% coverage on the
agent is a red flag. Experienced contributors will not trust code they cannot test safely.

**Status:** NOT STARTED

---

## Tasks

### 2.1 — Agent: ACK timeout & freeze logic (`cmd/agent/plugin.go`)
This is the highest-priority area — it is the product's core differentiator.

- [ ] Identify the functions responsible for: ACK waiting, freeze trigger, unfreeze
- [ ] Write a test that simulates server going silent → verify freeze is triggered
- [ ] Write a test that simulates server recovering → verify unfreeze
- [ ] Write a test for ACK arriving within deadline → no freeze
- [ ] Write a test for partial chunk delivery (truncation scenario)
- [ ] Target: these specific functions at ≥80% coverage

Approach: use an in-process fake server (net.Pipe or a test TLS listener) rather than
mocking — this tests the real network path.

### 2.2 — Agent: sandbox (`cmd/agent/sandbox.go`, `cmd/agent/sandbox_test.go`)
- [ ] Review existing sandbox_test.go to understand what is already covered
- [ ] Add tests for: sandbox rule evaluation, deny paths, allow paths
- [ ] Add test for malformed sandbox config (should fail safe, not panic)
- [ ] Target: ≥60%

### 2.3 — Store: session lifecycle (`internal/store/local.go`)
Focus on the most-used paths that are currently at 0%:

- [ ] `SaveSudoersSnapshot` / `ListSudoersSnapshots` — round-trip test
- [ ] `SaveHeartbeat` / `GetLastSeen` — round-trip test
- [ ] `runCleanupWorker` / `doCleanup` — test with synthetic old sessions
- [ ] `unescapeJSONString` — table-driven test (currently 0%, pure function)
- [ ] `validSudoersHost` — table-driven test (currently 0%, pure function)
- [ ] Target: raise store from 20.6% to ≥50%

### 2.4 — Store: approval (`internal/store/local_approval.go`)
All approval functions are at 0%:

- [ ] `CreateApprovalRequest` / `ListApprovalRequests` / `DeleteApprovalRequest`
- [ ] `HasApprovalWindow` / `CreateApprovalWindow`
- [ ] `loadApprovalStore` / `saveApprovalStore`
- [ ] Write an integration test that exercises the full approval lifecycle
- [ ] Target: ≥70% for the approval package

### 2.5 — Config (`internal/config/`)
- [ ] Identify all config fields and their types
- [ ] Write table-driven tests for: valid config, missing required fields, type errors
- [ ] Write tests for environment variable overrides (if any)
- [ ] Write a test for the zero-value / default config
- [ ] Target: ≥60%

### 2.6 — Server: callback & approval (`cmd/server/callback_test.go`, `approval_test.go`)
- [ ] Review existing tests to find gaps
- [ ] Add tests for: session rejection, malformed chunk handling, duplicate sessions
- [ ] Add tests for: approval expiry, concurrent approval requests
- [ ] Target: raise server from 32.5% to ≥50%

### 2.7 — CI coverage gate (depends on Plan 01)
- [ ] After Plan 01 is done, configure codecov to fail PR if coverage drops >2%
- [ ] Add `.codecov.yml` to project root with:
  ```yaml
  coverage:
    status:
      patch:
        default:
          target: auto
          threshold: 2%
  ```

---

## Files to create / modify

| File | Action |
|------|--------|
| `go/cmd/agent/plugin_test.go` | MODIFY — add ACK/freeze tests |
| `go/cmd/agent/sandbox_test.go` | MODIFY — add gap coverage |
| `go/internal/store/local_test.go` | MODIFY — add session/sudoers/cleanup tests |
| `go/internal/store/local_approval_test.go` | CREATE |
| `go/internal/config/config_test.go` | CREATE |
| `go/cmd/server/approval_test.go` | MODIFY — add gap coverage |
| `.codecov.yml` | CREATE |

---

## Testing principles

- Prefer `net.Pipe` / in-process fake servers over mocks for network code
- Use `t.TempDir()` for all file-system tests (auto-cleaned)
- Table-driven tests (`[]struct{ name, input, want }`) for pure functions
- No external dependencies (no running PostgreSQL, no real TLS certs) unless
  the test is explicitly tagged `//go:build integration`

---

## Definition of done

- `cmd/agent` ≥ 50% (freeze + ACK paths explicitly covered)
- `internal/store` ≥ 50%
- `internal/config` ≥ 60%
- `cmd/server` ≥ 50%
- `local_approval` ≥ 70%
- codecov gate active (coverage cannot drop by >2% in a PR)
