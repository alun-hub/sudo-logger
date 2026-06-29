# Plan 03 — Refactoring

**Goal:** Break up God files so contributors can navigate and modify the codebase without
reading 3000+ line files. No behaviour changes — pure structural cleanup.

**Current pain points (2026-06-28):**
```
go/cmd/replay-server/main.go    3 679 lines  ← God file
go/internal/store/local.go      1 814 lines  ← 5 responsibilities in one file
go/internal/store/distributed.go 1 714 lines
go/cmd/server/main.go           1 106 lines
go/cmd/agent/ebpf.go            1 246 lines
```

**Why it matters:** A new contributor wanting to fix a replay-server bug must read
3679 lines before finding the right function. This directly reduces contribution rate.

**Status:** NOT STARTED

---

## Tasks

### 3.1 — Split `go/cmd/replay-server/main.go` (highest priority)

Target structure after split:
```
go/cmd/replay-server/
  main.go            ~100 lines  (startup, flag parsing, server init only)
  routes.go          ~100 lines  (all http.HandleFunc / router setup)
  handlers_session.go ~300 lines  (session list, detail, replay endpoints)
  handlers_admin.go   ~300 lines  (user mgmt, role, config endpoints)
  handlers_auth.go    ~200 lines  (login, logout, OIDC, token endpoints)
  middleware.go       ~150 lines  (auth middleware, RBAC checks, logging)
  websocket.go        ~200 lines  (replay websocket handler)
  config.go           ~100 lines  (server config struct, load, defaults)
```

Steps:
- [x] Read main.go fully and catalogue all top-level functions by category
- [x] Create the new files as empty shells with correct package declaration
- [x] Move functions one category at a time, verify `go build ./...` after each move
- [x] Ensure no circular imports are introduced
- [x] Run `go test ./cmd/replay-server/...` after each move
- [x] Run `pre-commit run --all-files` before committing

### 3.2 — Split `go/internal/store/local.go`

The file currently handles: sessions, sudoers snapshots, heartbeat, approval windows,
and risk cache. Each belongs in its own file.

Target structure:
```
go/internal/store/
  local.go               (keep: store init, Open/Close, core session CRUD)
  local_sessions.go      (scanAllSessions, parseSessionRecord, localReadEvents)
  local_sudoers.go       (SaveSudoersSnapshot, ListSudoersSnapshots, etc.)
  local_heartbeat.go     (SaveHeartbeat, GetLastSeen)
  local_cleanup.go       (runCleanupWorker, doCleanup, retention logic)
  local_risk.go          (localLoadRiskCache, localSaveRiskCache)
  local_approval.go      (already exists — verify it's complete)
```

Steps:
- [x] Map every function in local.go to its target file
- [x] Create new files with package declaration
- [x] Move functions group by group, compile-check after each
- [x] Run full test suite after all moves
- [x] Ensure `local_test.go` imports still work (may need to update test file locations)

### 3.3 — Split `go/cmd/server/main.go`

Target structure:
```
go/cmd/server/
  main.go          (startup, flag parsing, TLS setup, listener)
  handler.go       (chunk receive, session open/close handlers)
  heartbeat.go     (heartbeat handling and tracking)
  config.go        (server config struct, load, validate)
```

Steps:
- [x] Catalogue functions in main.go by responsibility
- [x] Move in groups, compile-check after each
- [x] Run test suite after all moves

### 3.4 — Review `go/cmd/agent/ebpf.go` (1246 lines)
- [ ] Read the file and determine if it can be split meaningfully
- [ ] If it contains both BPF program loading AND event processing: split them
- [ ] If it is inherently monolithic (one concern, just verbose): leave it, document why
- [ ] Decision to be logged here before any changes are made

### 3.5 — Verify no behaviour changes
- [ ] `go test -race ./...` passes after all splits
- [ ] Manual smoke test: start replay-server, log in, view a session, replay it
- [ ] `pre-commit run --all-files` passes

---

## Rules for this refactor

1. **No logic changes.** Move code only. If you notice a bug while moving, file a separate
   issue and leave a `// TODO:` comment — do not fix it in this PR.
2. **One commit per file split.** Easier to review and bisect.
3. **Keep existing test files working.** Do not rename packages.
4. **Run `go build ./...` after every move.** Do not accumulate broken states.

---

## Files to create

| File | Moved from |
|------|-----------|
| `go/cmd/replay-server/routes.go` | `main.go` |
| `go/cmd/replay-server/handlers_session.go` | `main.go` |
| `go/cmd/replay-server/handlers_admin.go` | `main.go` |
| `go/cmd/replay-server/handlers_auth.go` | `main.go` |
| `go/cmd/replay-server/middleware.go` | `main.go` |
| `go/cmd/replay-server/websocket.go` | `main.go` |
| `go/cmd/replay-server/config.go` | `main.go` |
| `go/internal/store/local_sessions.go` | `local.go` |
| `go/internal/store/local_sudoers.go` | `local.go` |
| `go/internal/store/local_heartbeat.go` | `local.go` |
| `go/internal/store/local_cleanup.go` | `local.go` |
| `go/internal/store/local_risk.go` | `local.go` |
| `go/cmd/server/handler.go` | `main.go` |
| `go/cmd/server/heartbeat.go` | `main.go` |
| `go/cmd/server/config.go` | `main.go` |

---

## Definition of done

- No single Go file in `cmd/` or `internal/` exceeds 600 lines (excluding vendor)
- All tests pass
- `go vet ./...` and `staticcheck ./...` produce no new warnings
- A new contributor can find "where does the websocket replay handler live?" in <30 seconds
