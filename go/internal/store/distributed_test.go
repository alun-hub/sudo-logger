package store

// Tests for DistributedStore (Postgres + S3 backend), covering the
// priority order from the test-coverage plan: applySchema, session
// lifecycle (CreateSession/ListSessions/ReadEvents/OpenCast), IsBlocked,
// RBAC persistence, S3 key derivation/upload/delete, RiskCache, approval
// workflow, and access log.
//
// Every test in this file spins up a real ephemeral Postgres container via
// testcontainers-go and skips cleanly (t.Skip, not fail) when no container
// runtime is reachable — see newTestPostgresDSN in distributed_infra_test.go.

import (
	"context"
	"os"
	"testing"
	"time"

	"sudo-logger/internal/iolog"
)

func distTestMeta(user, host string) iolog.SessionMeta {
	return iolog.SessionMeta{
		SessionID: host + "-" + user + "-1-2-aabbccdd",
		User:      user,
		Host:      host,
		RunasUser: "root",
		Cwd:       "/home/" + user,
		Command:   "/bin/bash",
		Rows:      50,
		Cols:      220,
	}
}

// ── applySchema ───────────────────────────────────────────────────────────────

func TestApplySchema_IdempotentReapply(t *testing.T) {
	d, _ := newDistributedTestStore(t) // already applies schema once via newDistributedStore
	ctx := t.Context()

	// Re-applying against the same pool must be a no-op fast path (version
	// check short-circuits) and must not error.
	if err := applySchema(ctx, d.db); err != nil {
		t.Fatalf("applySchema (second call): %v", err)
	}

	var version int
	if err := d.db.QueryRow(ctx, `SELECT version FROM sudo_schema_version LIMIT 1`).Scan(&version); err != nil {
		t.Fatalf("query schema version: %v", err)
	}
	if version != currentSchemaVersion {
		t.Errorf("schema version = %d, want %d", version, currentSchemaVersion)
	}
}

// ── s3Key / bufferPath (pure, no container needed) ───────────────────────────

func TestS3KeyAndBufferPath(t *testing.T) {
	d := &DistributedStore{cfg: Config{S3Prefix: "sessions/", BufferDir: "/var/lib/sudo-logger/buffer"}}

	if got, want := d.s3Key("alice/host1_20260101-000000"), "sessions/alice/host1_20260101-000000/session.cast"; got != want {
		t.Errorf("s3Key = %q, want %q", got, want)
	}
	if got, want := d.bufferPath("alice/host1_20260101-000000"), "/var/lib/sudo-logger/buffer/alice/host1_20260101-000000/session.cast"; got != want {
		t.Errorf("bufferPath = %q, want %q", got, want)
	}
}

// ── Session lifecycle: CreateSession / ListSessions / ReadEvents / OpenCast ──

func TestDistributedStore_CreateSessionAndListSessions(t *testing.T) {
	d, _ := newDistributedTestStore(t)
	ctx := t.Context()

	w, err := d.CreateSession(ctx, distTestMeta("alice", "host1"), time.Now())
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	tsid := w.TSID()
	if err := w.MarkActive(); err != nil {
		t.Fatalf("MarkActive: %v", err)
	}
	defer w.Close()

	records, err := d.ListSessions(ctx)
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	var found *SessionRecord
	for i := range records {
		if records[i].TSID == tsid {
			found = &records[i]
		}
	}
	if found == nil {
		t.Fatalf("session %s not found in ListSessions", tsid)
	}
	if found.User != "alice" || found.Host != "host1" || !found.InProgress {
		t.Errorf("session record = %+v, want user=alice host=host1 in_progress=true", found)
	}
}

func TestDistributedStore_OpenCast_InProgressReadsLocalBuffer(t *testing.T) {
	d, _ := newDistributedTestStore(t)
	ctx := t.Context()

	w, err := d.CreateSession(ctx, distTestMeta("alice", "host1"), time.Now())
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	tsid := w.TSID()
	if err := w.MarkActive(); err != nil {
		t.Fatalf("MarkActive: %v", err)
	}
	if err := w.WriteOutput([]byte("hello from the buffer"), 1); err != nil {
		t.Fatalf("WriteOutput: %v", err)
	}
	if err := w.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	defer w.Close()

	events, err := d.ReadEvents(ctx, tsid)
	if err != nil {
		t.Fatalf("ReadEvents: %v", err)
	}
	found := false
	for _, e := range events {
		if e.Kind == "o" && string(e.Data) == "hello from the buffer" {
			found = true
		}
	}
	if !found {
		t.Errorf("ReadEvents did not include the written output event, got: %+v", events)
	}
}

func TestDistributedStore_OpenCast_AfterCloseUploadsToS3(t *testing.T) {
	d, fakeS3 := newDistributedTestStore(t)
	ctx := t.Context()

	w, err := d.CreateSession(ctx, distTestMeta("alice", "host1"), time.Now())
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	tsid := w.TSID()
	if err := w.MarkActive(); err != nil {
		t.Fatalf("MarkActive: %v", err)
	}
	if err := w.WriteOutput([]byte("uploaded content"), 1); err != nil {
		t.Fatalf("WriteOutput: %v", err)
	}
	if err := w.MarkDone(); err != nil {
		t.Fatalf("MarkDone: %v", err)
	}
	if err := w.Close(); err != nil { // triggers async S3 upload
		t.Fatalf("Close: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for !fakeS3.has("test-bucket", d.s3Key(tsid)) {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for async S3 upload to complete")
		}
		time.Sleep(50 * time.Millisecond)
	}

	// The local buffer file must be removed once the upload succeeds.
	if _, err := os.Stat(d.bufferPath(tsid)); !os.IsNotExist(err) {
		t.Errorf("local buffer file should be removed after successful S3 upload, stat err: %v", err)
	}

	rc, err := d.OpenCast(ctx, tsid)
	if err != nil {
		t.Fatalf("OpenCast after upload: %v", err)
	}
	defer rc.Close()
	data := make([]byte, 4096)
	n, _ := rc.Read(data)
	if n == 0 {
		t.Error("OpenCast returned no data after S3 upload")
	}
}

func TestDistributedStore_OpenCast_InProgressWithoutBufferReturnsEmptyCast(t *testing.T) {
	// Simulates a session whose local buffer is gone (e.g. server restarted
	// mid-session) but the DB still marks it in_progress and it hasn't been
	// uploaded to S3 yet — OpenCast must return a minimal empty cast, not
	// an error, so the replay UI doesn't break on a live session.
	d, _ := newDistributedTestStore(t)
	ctx := t.Context()

	w, err := d.CreateSession(ctx, distTestMeta("alice", "host1"), time.Now())
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	tsid := w.TSID()
	if err := w.MarkActive(); err != nil {
		t.Fatalf("MarkActive: %v", err)
	}
	if err := os.Remove(d.bufferPath(tsid)); err != nil {
		t.Fatalf("remove buffer to simulate loss: %v", err)
	}

	rc, err := d.OpenCast(ctx, tsid)
	if err != nil {
		t.Fatalf("OpenCast should not error for an in-progress session with no buffer: %v", err)
	}
	rc.Close()
}

func TestDistributedStore_OpenCast_MissingSessionErrors(t *testing.T) {
	d, _ := newDistributedTestStore(t)
	if _, err := d.OpenCast(t.Context(), "nobody/nowhere_20260101-000000"); err == nil {
		t.Error("OpenCast should error for a session that was never created")
	}
}

// ── doUpload / deleteS3Session ────────────────────────────────────────────────

func TestDoUpload_And_DeleteS3Session(t *testing.T) {
	d, fakeS3 := newDistributedTestStore(t)
	ctx := t.Context()

	w, err := d.CreateSession(ctx, distTestMeta("alice", "host1"), time.Now())
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	tsid := w.TSID()
	if err := w.WriteOutput([]byte("payload"), 1); err != nil {
		t.Fatalf("WriteOutput: %v", err)
	}
	if err := w.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	dw := w.(*distributedWriter)
	if err := dw.doUpload(d.bufferPath(tsid)); err != nil {
		t.Fatalf("doUpload: %v", err)
	}
	if !fakeS3.has("test-bucket", d.s3Key(tsid)) {
		t.Fatal("doUpload did not put the object into the fake S3 server")
	}
	w.Close()

	d.deleteS3Session(ctx, tsid)
	if fakeS3.has("test-bucket", d.s3Key(tsid)) {
		t.Error("deleteS3Session did not remove the object from S3")
	}
}

// ── IsBlocked ─────────────────────────────────────────────────────────────────

func TestDistributedStore_IsBlocked(t *testing.T) {
	d, _ := newDistributedTestStore(t)
	ctx := t.Context()

	if err := d.SaveBlockedPolicy(ctx, BlockedPolicy{
		BlockMessage: "Access denied",
		Users:        []BlockedUserEntry{{Username: "mallory", Hosts: []string{}, Reason: "bad actor"}},
	}); err != nil {
		t.Fatalf("SaveBlockedPolicy: %v", err)
	}

	blocked, reason, err := d.IsBlocked(ctx, "mallory", "anyhost")
	if err != nil {
		t.Fatalf("IsBlocked: %v", err)
	}
	if !blocked || reason != "Access denied" {
		t.Errorf("IsBlocked(mallory) = (%v, %q), want (true, %q)", blocked, reason, "Access denied")
	}

	blocked, _, err = d.IsBlocked(ctx, "alice", "anyhost")
	if err != nil {
		t.Fatalf("IsBlocked: %v", err)
	}
	if blocked {
		t.Error("IsBlocked(alice) should be false — alice was never blocked")
	}

	// Test canceled context behavior
	cancelCtx, cancel := context.WithCancel(ctx)
	cancel()
	_, _, err = d.IsBlocked(cancelCtx, "mallory", "anyhost")
	if err == nil {
		t.Error("IsBlocked with canceled context should return a non-nil error")
	}
}

// ── IsWhitelisted ─────────────────────────────────────────────────────────────

func TestDistributedStore_IsWhitelisted(t *testing.T) {
	d, _ := newDistributedTestStore(t)
	ctx := t.Context()

	if err := d.SaveWhitelistPolicy(ctx, WhitelistPolicy{
		Users: []WhitelistedUserEntry{
			{Username: "bob", Hosts: []string{}, Reason: "bypass JIT"},
			{Username: "charlie", Hosts: []string{"host1"}, Reason: "bypass JIT on host1"},
		},
	}); err != nil {
		t.Fatalf("SaveWhitelistPolicy: %v", err)
	}

	// Normal whitelist lookup: bob (all hosts)
	whitelisted, err := d.IsWhitelisted(ctx, "bob", "anyhost")
	if err != nil {
		t.Fatalf("IsWhitelisted(bob): %v", err)
	}
	if !whitelisted {
		t.Error("IsWhitelisted(bob, anyhost) = false, want true (all hosts)")
	}

	// Normal whitelist lookup: charlie on host1 (allowed)
	whitelisted, err = d.IsWhitelisted(ctx, "charlie", "host1")
	if err != nil {
		t.Fatalf("IsWhitelisted(charlie, host1): %v", err)
	}
	if !whitelisted {
		t.Error("IsWhitelisted(charlie, host1) = false, want true")
	}

	// Normal whitelist lookup: charlie on host2 (not allowed)
	whitelisted, err = d.IsWhitelisted(ctx, "charlie", "host2")
	if err != nil {
		t.Fatalf("IsWhitelisted(charlie, host2): %v", err)
	}
	if whitelisted {
		t.Error("IsWhitelisted(charlie, host2) = true, want false")
	}

	// Normal whitelist lookup: alice (never whitelisted)
	whitelisted, err = d.IsWhitelisted(ctx, "alice", "anyhost")
	if err != nil {
		t.Fatalf("IsWhitelisted(alice): %v", err)
	}
	if whitelisted {
		t.Error("IsWhitelisted(alice) = true, want false")
	}

	// Test canceled context behavior
	cancelCtx, cancel := context.WithCancel(ctx)
	cancel()
	_, err = d.IsWhitelisted(cancelCtx, "bob", "anyhost")
	if err == nil {
		t.Error("IsWhitelisted with canceled context should return a non-nil error")
	}
}


// ── RBAC: Users / Roles / AuthConfig ──────────────────────────────────────────

func TestDistributedStore_RBAC(t *testing.T) {
	d, _ := newDistributedTestStore(t)
	ctx := t.Context()

	// Users.
	u := User{Username: "alice", PasswordHash: "hash1", Role: "admin", Source: "local"}
	if err := d.UpsertUser(ctx, u); err != nil {
		t.Fatalf("UpsertUser: %v", err)
	}
	got, err := d.GetUser(ctx, "alice")
	if err != nil || got == nil {
		t.Fatalf("GetUser: %v, %+v", err, got)
	}
	if got.Role != "admin" || got.PasswordHash != "hash1" { // pragma: allowlist secret
		t.Errorf("GetUser = %+v, want role=admin hash=hash1", got)
	}
	users, err := d.ListUsers(ctx)
	if err != nil || len(users) != 1 {
		t.Fatalf("ListUsers: %v, count=%d", err, len(users))
	}
	if err := d.DeleteUser(ctx, "alice"); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	if got, err := d.GetUser(ctx, "alice"); err != nil || got != nil {
		t.Errorf("user still present after DeleteUser: err=%v got=%+v", err, got)
	}

	// Roles.
	roles, err := d.GetRoles(ctx)
	if err != nil {
		t.Fatalf("GetRoles: %v", err)
	}
	foundAdmin := false
	for _, r := range roles {
		if r.Name == "admin" && r.BuiltIn {
			foundAdmin = true
		}
	}
	if !foundAdmin {
		t.Error("GetRoles did not include the built-in admin role")
	}
	def := RoleDefinition{Name: "operator", Permissions: []Permission{PermSessionsListOwn}}
	if err := d.UpsertRole(ctx, def); err != nil {
		t.Fatalf("UpsertRole: %v", err)
	}
	role, err := d.GetRole(ctx, "operator")
	if err != nil || role.Name != "operator" {
		t.Fatalf("GetRole(operator): %v, %+v", err, role)
	}
	if err := d.DeleteRole(ctx, "operator"); err != nil {
		t.Fatalf("DeleteRole: %v", err)
	}
	if err := d.UpsertRole(ctx, RoleDefinition{Name: "admin"}); err == nil {
		t.Error("UpsertRole should refuse to modify the built-in admin role")
	}
	if err := d.DeleteRole(ctx, "admin"); err == nil {
		t.Error("DeleteRole should refuse to delete the built-in admin role")
	}

	// Auth config.
	authCfg := AuthConfig{Source: "proxy", AdminGroups: []string{"admins"}}
	if err := d.SetAuthConfig(ctx, authCfg); err != nil {
		t.Fatalf("SetAuthConfig: %v", err)
	}
	gotAuth, err := d.GetAuthConfig(ctx)
	if err != nil {
		t.Fatalf("GetAuthConfig: %v", err)
	}
	if gotAuth.Source != "proxy" {
		t.Errorf("GetAuthConfig.Source = %q, want proxy", gotAuth.Source)
	}
}

// ── RiskCache ─────────────────────────────────────────────────────────────────

func TestDistributedStore_RiskCache(t *testing.T) {
	d, _ := newDistributedTestStore(t)
	ctx := t.Context()

	w, err := d.CreateSession(ctx, distTestMeta("alice", "host1"), time.Now())
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	tsid := w.TSID()
	defer w.Close()

	if err := d.SaveRiskCache(ctx, tsid, "hash-v1", 60, []string{"reason one", "reason two"}); err != nil {
		t.Fatalf("SaveRiskCache: %v", err)
	}
	rc, err := d.GetRiskCache(ctx, tsid, "hash-v1")
	if err != nil {
		t.Fatalf("GetRiskCache: %v", err)
	}
	if rc == nil || rc.Score != 60 || len(rc.Reasons) != 2 {
		t.Fatalf("GetRiskCache = %+v, want score=60 with 2 reasons", rc)
	}

	// A rules-hash mismatch (rules changed since caching) must be a miss.
	stale, err := d.GetRiskCache(ctx, tsid, "hash-v2-different")
	if err != nil {
		t.Fatalf("GetRiskCache (stale): %v", err)
	}
	if stale != nil {
		t.Error("GetRiskCache should report a cache miss when the rules hash has changed")
	}
}

// ── RecordView / ListAccessLog ────────────────────────────────────────────────

func TestDistributedStore_RecordViewAndListAccessLog(t *testing.T) {
	d, _ := newDistributedTestStore(t)
	ctx := t.Context()

	w, err := d.CreateSession(ctx, distTestMeta("alice", "host1"), time.Now())
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	tsid := w.TSID()
	defer w.Close()

	if err := d.RecordView(ctx, tsid, "bob", "/replay/"+tsid); err != nil {
		t.Fatalf("RecordView: %v", err)
	}
	entries, err := d.ListAccessLog(ctx, "", 10)
	if err != nil {
		t.Fatalf("ListAccessLog: %v", err)
	}
	if len(entries) != 1 || entries[0].Viewer != "bob" || entries[0].TSID != tsid {
		t.Errorf("ListAccessLog = %+v, want one entry viewer=bob tsid=%s", entries, tsid)
	}
}

// ── Approval workflow ──────────────────────────────────────────────────────────

func TestDistributedStore_ApprovalWorkflow(t *testing.T) {
	d, _ := newDistributedTestStore(t)
	ctx := t.Context()

	req := ApprovalRequest{
		ID:          "REQ-1",
		User:        "alice",
		Host:        "host1",
		Command:     "systemctl restart nginx",
		SubmittedAt: time.Now(),
		ExpiresAt:   time.Now().Add(time.Hour),
	}
	if err := d.CreateApprovalRequest(ctx, req); err != nil {
		t.Fatalf("CreateApprovalRequest: %v", err)
	}
	pending, err := d.ListApprovalRequests(ctx)
	if err != nil {
		t.Fatalf("ListApprovalRequests: %v", err)
	}
	if len(pending) != 1 || pending[0].ID != "REQ-1" {
		t.Fatalf("ListApprovalRequests = %+v, want one entry with ID=REQ-1", pending)
	}

	deleted, err := d.DeleteApprovalRequest(ctx, "REQ-1")
	if err != nil {
		t.Fatalf("DeleteApprovalRequest: %v", err)
	}
	if deleted == nil || deleted.User != "alice" {
		t.Errorf("DeleteApprovalRequest returned %+v, want the deleted request", deleted)
	}
	pending, err = d.ListApprovalRequests(ctx)
	if err != nil {
		t.Fatalf("ListApprovalRequests (after delete): %v", err)
	}
	if len(pending) != 0 {
		t.Errorf("ListApprovalRequests after delete = %+v, want empty", pending)
	}

	// Approval windows (JIT bypass for a limited time).
	if _, has, _ := d.HasApprovalWindow(ctx, "alice", "host1"); has {
		t.Error("HasApprovalWindow should be false before any window is created")
	}
	if err := d.CreateApprovalWindow(ctx, "alice", "host1", "admin", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("CreateApprovalWindow: %v", err)
	}
	_, has, err := d.HasApprovalWindow(ctx, "alice", "host1")
	if err != nil {
		t.Fatalf("HasApprovalWindow: %v", err)
	}
	if !has {
		t.Error("HasApprovalWindow should be true after CreateApprovalWindow")
	}
}

// ── DeleteSession (GDPR path) ──────────────────────────────────────────────────

func TestDistributedStore_DeleteSession(t *testing.T) {
	d, _ := newDistributedTestStore(t)
	ctx := t.Context()

	w, err := d.CreateSession(ctx, distTestMeta("alice", "host1"), time.Now())
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	tsid := w.TSID()
	if err := w.MarkDone(); err != nil {
		t.Fatalf("MarkDone: %v", err)
	}
	w.Close()

	if err := d.DeleteSession(ctx, tsid, "GDPR request", "admin"); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}

	records, err := d.ListSessions(ctx)
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	for _, r := range records {
		if r.TSID == tsid {
			t.Fatalf("session %s still present after DeleteSession", tsid)
		}
	}

	var count int
	if err := d.db.QueryRow(ctx, `SELECT count(*) FROM sudo_deletion_log WHERE tsid=$1`, tsid).Scan(&count); err != nil {
		t.Fatalf("query deletion log: %v", err)
	}
	if count != 1 {
		t.Errorf("sudo_deletion_log entries for %s = %d, want 1", tsid, count)
	}
}

func TestDistributedStore_DeleteSession_RefusesInProgress(t *testing.T) {
	d, _ := newDistributedTestStore(t)
	ctx := t.Context()

	w, err := d.CreateSession(ctx, distTestMeta("alice", "host1"), time.Now())
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	tsid := w.TSID()
	defer w.Close()
	// Never called MarkDone — session stays in_progress=TRUE.

	if err := d.DeleteSession(ctx, tsid, "attempted deletion", "attacker"); err == nil {
		t.Error("DeleteSession should refuse to delete a session with a live active writer")
	}
}
