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

**Status:** IN PROGRESS

---

## Tasks

### 2.1 — Agent: ACK timeout & freeze logic (`cmd/agent/plugin.go`)
This is the highest-priority area — it is the product's core differentiator.

> **Known issue (FIXED 2026-06-28):** `TestHandlePluginConn_Success` and
> `TestHandlePluginConn_Denied` had a data race on Go 1.25. Fixed by removing the
> save/restore global defer pattern and adding a 100ms settle time after `<-done`.

- [x] Identify the functions responsible for: ACK waiting, freeze trigger, unfreeze
      (markDead, markAlive, heartbeat goroutine — all in handlePluginConn)
- [x] Write a test for server unreachable → MsgSessionError (TestHandlePluginConn_ServerUnreachable)
- [x] Write a test that simulates server going silent → verify freeze detected (TestHandlePluginConn_FreezeOnServerClose)
- [x] Write a test for chunks buffered during outage (TestHandlePluginConn_DeadBuffering)
- [ ] Write a test that simulates server recovering → verify unfreeze
      NOTE: markAlive() requires the heartbeat goroutine to see 2 consecutive HeartbeatAcks
      after silence. Since the agent does not auto-reconnect, this path cannot be tested
      without either production-code refactoring or a 6s+ test. Deferred.
- [x] Write a test for ACK arriving within deadline → no freeze
      (existing TestHandlePluginConn_Success covers this path)
- [ ] Write a test for partial chunk delivery (truncation scenario)
      NOTE: requires instrumenting the ackLagLimit (currently a 5s const). Deferred.
- [ ] Target: these specific functions at ≥80% coverage (currently ~17%)

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
- [x] `SaveHeartbeat` / `GetLastSeen` — round-trip test (3 tests: round-trip, multi-host, timestamp advance)
- [ ] `runCleanupWorker` / `doCleanup` — test with synthetic old sessions
- [ ] `unescapeJSONString` — table-driven test (currently 0%, pure function)
- [ ] `validSudoersHost` — table-driven test (currently 0%, pure function)
- [ ] Target: raise store from 20.6% to ≥50%

### 2.4 — Store: approval (`internal/store/local_approval.go`)
All approval functions are at 0%:

- [x] `CreateApprovalRequest` / `ListApprovalRequests` / `DeleteApprovalRequest`
- [x] `HasApprovalWindow` / `CreateApprovalWindow`
- [x] `loadApprovalStore` / `saveApprovalStore` (persist round-trip test)
- [x] Write an integration test that exercises the full approval lifecycle
- [x] Target: ≥70% for the approval package

### 2.5 — Config (`internal/config/`)
Note: `internal/config` contains only `ResolveSecret` — no config struct. All relevant
paths are now covered.

- [x] Write table-driven tests for: flag priority, env var fallback, file fallback, CRLF trim, missing file error
- [x] Write tests for environment variable overrides
- [x] Target: ≥60%

### 2.6 — Server: callback & approval (`cmd/server/callback_test.go`, `approval_test.go`)
- [ ] Review existing tests to find gaps
- [ ] Add tests for: session rejection, malformed chunk handling, duplicate sessions
- [ ] Add tests for: approval expiry, concurrent approval requests
- [ ] Target: raise server from 32.5% to ≥50%

### 2.7 — CI coverage gate (depends on Plan 01)
- [x] Add `.codecov.yml` with 40% project target, 50% patch target, 2% threshold

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
