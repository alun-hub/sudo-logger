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
	"sudo-logger/internal/protocol"
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

// ── Sudoers snapshot/error/heartbeat tracking ─────────────────────────────────

func TestDistributedStore_SudoersSnapshots(t *testing.T) {
	d, _ := newDistributedTestStore(t)
	ctx := t.Context()

	if hosts, err := d.ListSudoersHosts(ctx); err != nil || len(hosts) != 0 {
		t.Fatalf("ListSudoersHosts before any snapshot = %v, %v; want empty, nil", hosts, err)
	}

	snap1 := &protocol.SudoersSnapshot{Host: "host1", Content: "root ALL=(ALL) ALL\n", SHA256: "sha-a"}
	if err := d.SaveSudoersSnapshot(ctx, snap1); err != nil {
		t.Fatalf("SaveSudoersSnapshot: %v", err)
	}
	// Same host, different content/hash — a second snapshot, not an update.
	snap2 := &protocol.SudoersSnapshot{Host: "host1", Content: "root ALL=(ALL) ALL\n%wheel ALL=(ALL) ALL\n", SHA256: "sha-b"}
	if err := d.SaveSudoersSnapshot(ctx, snap2); err != nil {
		t.Fatalf("SaveSudoersSnapshot (2nd): %v", err)
	}
	// Re-saving the same (host, sha256) must upsert, not duplicate.
	if err := d.SaveSudoersSnapshot(ctx, snap1); err != nil {
		t.Fatalf("SaveSudoersSnapshot (re-save): %v", err)
	}

	hosts, err := d.ListSudoersHosts(ctx)
	if err != nil {
		t.Fatalf("ListSudoersHosts: %v", err)
	}
	if len(hosts) != 1 || hosts[0] != "host1" {
		t.Errorf("ListSudoersHosts = %v, want [host1]", hosts)
	}

	snaps, err := d.ListSudoersSnapshots(ctx, "host1", 10)
	if err != nil {
		t.Fatalf("ListSudoersSnapshots: %v", err)
	}
	if len(snaps) != 2 {
		t.Fatalf("ListSudoersSnapshots returned %d entries, want 2 (re-save must upsert, not duplicate)", len(snaps))
	}
	// Newest (by uploaded_at) first — the re-saved snap1 should now be most recent.
	if snaps[0].SHA256 != "sha-a" {
		t.Errorf("ListSudoersSnapshots[0].SHA256 = %q, want sha-a (most recently uploaded)", snaps[0].SHA256)
	}
}

func TestDistributedStore_ListSudoersConfigs(t *testing.T) {
	d, _ := newDistributedTestStore(t)
	ctx := t.Context()

	if err := d.SetConfig(ctx, "sudoers/host1", "config-content-1"); err != nil {
		t.Fatalf("SetConfig: %v", err)
	}
	if err := d.SetConfig(ctx, "sudoers/host2", "config-content-2"); err != nil {
		t.Fatalf("SetConfig: %v", err)
	}
	// A non-sudoers key must not appear in ListSudoersConfigs.
	if err := d.SetConfig(ctx, "risk-rules.yaml", "irrelevant"); err != nil {
		t.Fatalf("SetConfig: %v", err)
	}

	configs, err := d.ListSudoersConfigs(ctx)
	if err != nil {
		t.Fatalf("ListSudoersConfigs: %v", err)
	}
	if len(configs) != 2 || !configs["host1"] || !configs["host2"] {
		t.Errorf("ListSudoersConfigs = %v, want map with host1 and host2 only", configs)
	}
}

func TestDistributedStore_SudoersError(t *testing.T) {
	d, _ := newDistributedTestStore(t)
	ctx := t.Context()

	if serr, err := d.GetSudoersError(ctx, "host1"); err != nil || serr != nil {
		t.Fatalf("GetSudoersError before any error = %v, %v; want nil, nil", serr, err)
	}

	want := protocol.SudoersError{Host: "host1", Error: "visudo: syntax error", SHA256: "sha-x", Ts: 1234567890}
	if err := d.SaveSudoersError(ctx, want); err != nil {
		t.Fatalf("SaveSudoersError: %v", err)
	}

	got, err := d.GetSudoersError(ctx, "host1")
	if err != nil {
		t.Fatalf("GetSudoersError: %v", err)
	}
	if got == nil || *got != want {
		t.Errorf("GetSudoersError = %+v, want %+v", got, want)
	}

	// A different host must not see host1's error.
	if serr, err := d.GetSudoersError(ctx, "host2"); err != nil || serr != nil {
		t.Errorf("GetSudoersError(host2) = %v, %v; want nil, nil", serr, err)
	}
}

func TestDistributedStore_Heartbeat(t *testing.T) {
	d, _ := newDistributedTestStore(t)
	ctx := t.Context()

	if ts, err := d.GetLastSeen(ctx, "host1"); err != nil || ts != 0 {
		t.Fatalf("GetLastSeen before any heartbeat = %d, %v; want 0, nil", ts, err)
	}

	before := time.Now().Unix()
	if err := d.SaveHeartbeat(ctx, "host1"); err != nil {
		t.Fatalf("SaveHeartbeat: %v", err)
	}
	after := time.Now().Unix()

	ts, err := d.GetLastSeen(ctx, "host1")
	if err != nil {
		t.Fatalf("GetLastSeen: %v", err)
	}
	if ts < before || ts > after {
		t.Errorf("GetLastSeen = %d, want between %d and %d", ts, before, after)
	}

	// A second heartbeat must update, not duplicate, the stored timestamp.
	time.Sleep(1100 * time.Millisecond)
	if err := d.SaveHeartbeat(ctx, "host1"); err != nil {
		t.Fatalf("SaveHeartbeat (2nd): %v", err)
	}
	ts2, err := d.GetLastSeen(ctx, "host1")
	if err != nil {
		t.Fatalf("GetLastSeen (2nd): %v", err)
	}
	if ts2 <= ts {
		t.Errorf("GetLastSeen after 2nd heartbeat = %d, want > %d", ts2, ts)
	}
}

// ── Blocked/whitelist policy readers ──────────────────────────────────────────

func TestDistributedStore_GetBlockedPolicy(t *testing.T) {
	d, _ := newDistributedTestStore(t)
	ctx := t.Context()

	empty, err := d.GetBlockedPolicy(ctx)
	if err != nil {
		t.Fatalf("GetBlockedPolicy (empty): %v", err)
	}
	if len(empty.Users) != 0 {
		t.Errorf("GetBlockedPolicy (empty) = %+v, want no users", empty)
	}

	policy := BlockedPolicy{
		BlockMessage: "contact IT",
		Users: []BlockedUserEntry{
			{Username: "eve", Hosts: []string{"host1", "host2"}, Reason: "compromised", BlockedAt: 1000},
			{Username: "mallory", Hosts: nil, Reason: "all hosts", BlockedAt: 2000},
		},
	}
	if err := d.SaveBlockedPolicy(ctx, policy); err != nil {
		t.Fatalf("SaveBlockedPolicy: %v", err)
	}

	got, err := d.GetBlockedPolicy(ctx)
	if err != nil {
		t.Fatalf("GetBlockedPolicy: %v", err)
	}
	if got.BlockMessage != "contact IT" {
		t.Errorf("GetBlockedPolicy.BlockMessage = %q, want %q", got.BlockMessage, "contact IT")
	}
	if len(got.Users) != 2 {
		t.Fatalf("GetBlockedPolicy.Users = %+v, want 2 entries", got.Users)
	}
	byName := map[string]BlockedUserEntry{}
	for _, u := range got.Users {
		byName[u.Username] = u
	}
	if len(byName["eve"].Hosts) != 2 || byName["eve"].Reason != "compromised" {
		t.Errorf("GetBlockedPolicy eve entry = %+v", byName["eve"])
	}
	if len(byName["mallory"].Hosts) != 0 {
		t.Errorf("GetBlockedPolicy mallory entry (nil hosts = all hosts) = %+v, want empty Hosts", byName["mallory"])
	}
}

func TestDistributedStore_GetWhitelistPolicy(t *testing.T) {
	d, _ := newDistributedTestStore(t)
	ctx := t.Context()

	empty, err := d.GetWhitelistPolicy(ctx)
	if err != nil {
		t.Fatalf("GetWhitelistPolicy (empty): %v", err)
	}
	if len(empty.Users) != 0 {
		t.Errorf("GetWhitelistPolicy (empty) = %+v, want no users", empty)
	}

	policy := WhitelistPolicy{
		Users: []WhitelistedUserEntry{
			{Username: "trusted-svc", Hosts: []string{"host1"}, Reason: "automation"},
		},
	}
	if err := d.SaveWhitelistPolicy(ctx, policy); err != nil {
		t.Fatalf("SaveWhitelistPolicy: %v", err)
	}

	got, err := d.GetWhitelistPolicy(ctx)
	if err != nil {
		t.Fatalf("GetWhitelistPolicy: %v", err)
	}
	if len(got.Users) != 1 || got.Users[0].Username != "trusted-svc" || len(got.Users[0].Hosts) != 1 {
		t.Errorf("GetWhitelistPolicy = %+v, want one trusted-svc entry with 1 host", got.Users)
	}
}

// ── Session state transitions (writer methods + store-level markers) ─────────

func TestDistributedStore_WriterStateTransitions(t *testing.T) {
	d, _ := newDistributedTestStore(t)
	ctx := t.Context()

	meta := distTestMeta("alice", "host1")
	w, err := d.CreateSession(ctx, meta, time.Now())
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	tsid := w.TSID()
	defer w.Close()

	if err := w.WriteInput([]byte("ls\n"), 1); err != nil {
		t.Fatalf("WriteInput: %v", err)
	}
	if err := w.WriteResize(80, 24, 2); err != nil {
		t.Fatalf("WriteResize: %v", err)
	}
	if err := w.WriteExitCode(7); err != nil {
		t.Fatalf("WriteExitCode: %v", err)
	}
	if err := w.MarkIncomplete(); err != nil {
		t.Fatalf("MarkIncomplete: %v", err)
	}

	rec := findSessionRecord(t, d, ctx, tsid)
	if rec.ExitCode != 7 {
		t.Errorf("ExitCode = %d, want 7", rec.ExitCode)
	}
	if !rec.Incomplete {
		t.Error("Incomplete = false after MarkIncomplete, want true")
	}
	if rec.InProgress {
		t.Error("InProgress = true after MarkIncomplete, want false")
	}
}

func TestDistributedStore_WriterMarkNetworkOutage(t *testing.T) {
	d, _ := newDistributedTestStore(t)
	ctx := t.Context()

	w, err := d.CreateSession(ctx, distTestMeta("alice", "host1"), time.Now())
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	tsid := w.TSID()
	defer w.Close()

	if err := w.MarkNetworkOutage(); err != nil {
		t.Fatalf("MarkNetworkOutage: %v", err)
	}

	rec := findSessionRecord(t, d, ctx, tsid)
	if !rec.NetworkOutage || !rec.Incomplete || rec.InProgress {
		t.Errorf("record after MarkNetworkOutage = %+v, want NetworkOutage=true Incomplete=true InProgress=false", rec)
	}
}

func TestDistributedStore_MarkSessionNetworkOutage(t *testing.T) {
	// Distinct from the writer's MarkNetworkOutage above: this is the
	// store-level path keyed by session_id, used when the server has no
	// live writer at hand (SESSION_ABANDON arriving on a fresh connection).
	d, _ := newDistributedTestStore(t)
	ctx := t.Context()

	meta := distTestMeta("alice", "host1")
	w, err := d.CreateSession(ctx, meta, time.Now())
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	tsid := w.TSID()
	defer w.Close()

	if err := d.MarkSessionNetworkOutage(ctx, meta.SessionID); err != nil {
		t.Fatalf("MarkSessionNetworkOutage: %v", err)
	}

	rec := findSessionRecord(t, d, ctx, tsid)
	if !rec.NetworkOutage {
		t.Errorf("NetworkOutage = false after MarkSessionNetworkOutage, want true")
	}
}

func TestDistributedStore_UpdateDivergenceStatus(t *testing.T) {
	d, _ := newDistributedTestStore(t)
	ctx := t.Context()

	w, err := d.CreateSession(ctx, distTestMeta("alice", "host1"), time.Now())
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	tsid := w.TSID()
	defer w.Close()

	if err := d.UpdateDivergenceStatus(ctx, tsid, "confirmed", "matched-tsid-123"); err != nil {
		t.Fatalf("UpdateDivergenceStatus: %v", err)
	}

	rec := findSessionRecord(t, d, ctx, tsid)
	if rec.DivergenceStatus != "confirmed" || rec.MatchedSessionID != "matched-tsid-123" {
		t.Errorf("record after UpdateDivergenceStatus = %+v, want status=confirmed matched=matched-tsid-123", rec)
	}
}

func TestDistributedStore_SandboxViolation(t *testing.T) {
	d, _ := newDistributedTestStore(t)
	ctx := t.Context()

	meta := distTestMeta("alice", "host1")
	w, err := d.CreateSession(ctx, meta, time.Now())
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	tsid := w.TSID()
	defer w.Close()

	if violated, err := d.HasSandboxViolation(ctx, tsid); err != nil || violated {
		t.Fatalf("HasSandboxViolation before any alert = %v, %v; want false, nil", violated, err)
	}

	alert := protocol.SandboxAlert{SessionID: meta.SessionID, Pid: 4242, Comm: "nc", Type: 1, Ts: time.Now().Unix()}
	if err := d.RecordSandboxViolation(ctx, meta.SessionID, alert); err != nil {
		t.Fatalf("RecordSandboxViolation: %v", err)
	}

	violated, err := d.HasSandboxViolation(ctx, tsid)
	if err != nil {
		t.Fatalf("HasSandboxViolation: %v", err)
	}
	if !violated {
		t.Error("HasSandboxViolation = false after RecordSandboxViolation, want true")
	}
}

func TestDistributedStore_HasSandboxViolation_MissingSession(t *testing.T) {
	d, _ := newDistributedTestStore(t)
	ctx := t.Context()

	if violated, err := d.HasSandboxViolation(ctx, "no-such-tsid"); err != nil || violated {
		t.Errorf("HasSandboxViolation(missing) = %v, %v; want false, nil", violated, err)
	}
}

// findSessionRecord is a test helper: fetches a single session by tsid via
// ListSessions, failing the test if it isn't found.
func findSessionRecord(t *testing.T, d *DistributedStore, ctx context.Context, tsid string) SessionRecord {
	t.Helper()
	records, err := d.ListSessions(ctx)
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	for _, r := range records {
		if r.TSID == tsid {
			return r
		}
	}
	t.Fatalf("session %s not found in ListSessions", tsid)
	return SessionRecord{}
}

// ── WatchSessions ──────────────────────────────────────────────────────────────

func TestDistributedStore_WatchSessions(t *testing.T) {
	d, _ := newDistributedTestStore(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	ch := make(chan string, 4)
	go d.WatchSessions(ctx, ch)
	// Let the goroutine acquire its advisory lock and record its starting
	// "lastCheck" timestamp before any session exists — WatchSessions only
	// reports sessions whose updated_at moves past that point.
	time.Sleep(300 * time.Millisecond)

	w, err := d.CreateSession(ctx, distTestMeta("alice", "host1"), time.Now())
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	tsid := w.TSID()
	if err := w.MarkDone(); err != nil {
		t.Fatalf("MarkDone: %v", err)
	}
	defer w.Close()

	select {
	case got := <-ch:
		if got != tsid {
			t.Errorf("WatchSessions sent %q, want %q", got, tsid)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("WatchSessions did not report the completed session within 8s (poll interval is 5s)")
	}
}

// ── GetConfig/SetConfig ────────────────────────────────────────────────────────

func TestDistributedStore_GetSetConfig(t *testing.T) {
	d, _ := newDistributedTestStore(t)
	ctx := t.Context()

	if v, err := d.GetConfig(ctx, "no-such-key"); err != nil || v != "" {
		t.Fatalf("GetConfig(missing) = %q, %v; want empty, nil", v, err)
	}

	if err := d.SetConfig(ctx, "risk-rules.yaml", "rules: []"); err != nil {
		t.Fatalf("SetConfig: %v", err)
	}
	if v, err := d.GetConfig(ctx, "risk-rules.yaml"); err != nil || v != "rules: []" {
		t.Fatalf("GetConfig = %q, %v; want %q, nil", v, err, "rules: []")
	}

	// Upsert: setting the same key again must replace, not duplicate.
	if err := d.SetConfig(ctx, "risk-rules.yaml", "rules: [updated]"); err != nil {
		t.Fatalf("SetConfig (update): %v", err)
	}
	if v, err := d.GetConfig(ctx, "risk-rules.yaml"); err != nil || v != "rules: [updated]" {
		t.Fatalf("GetConfig after update = %q, %v; want %q, nil", v, err, "rules: [updated]")
	}

	// SetConfig with an empty value deletes the key (see SetConfig's doc comment).
	if err := d.SetConfig(ctx, "risk-rules.yaml", ""); err != nil {
		t.Fatalf("SetConfig (delete): %v", err)
	}
	if v, err := d.GetConfig(ctx, "risk-rules.yaml"); err != nil || v != "" {
		t.Fatalf("GetConfig after delete = %q, %v; want empty, nil", v, err)
	}
}

// ── doCleanup ────────────────────────────────────────────────────────────────

func TestDistributedStore_DoCleanup_RemovesExpiredSessions(t *testing.T) {
	d, _ := newDistributedTestStore(t)
	ctx := t.Context()

	// An old, completed session — should be removed by cleanup.
	oldStart := time.Now().AddDate(0, 0, -10)
	wOld, err := d.CreateSession(ctx, distTestMeta("alice", "old-host"), oldStart)
	if err != nil {
		t.Fatalf("CreateSession (old): %v", err)
	}
	oldTSID := wOld.TSID()
	if err := wOld.MarkDone(); err != nil {
		t.Fatalf("MarkDone (old): %v", err)
	}
	wOld.Close()
	// Backdate start_time directly: CreateSession always stamps "now", and
	// doCleanup's query filters on start_time, not session age otherwise.
	if _, err := d.db.Exec(ctx, `UPDATE sudo_sessions SET start_time=$1 WHERE tsid=$2`,
		oldStart.Unix(), oldTSID); err != nil {
		t.Fatalf("backdate old session: %v", err)
	}

	// A recent, completed session — must survive cleanup.
	wRecent, err := d.CreateSession(ctx, distTestMeta("bob", "new-host"), time.Now())
	if err != nil {
		t.Fatalf("CreateSession (recent): %v", err)
	}
	recentTSID := wRecent.TSID()
	if err := wRecent.MarkDone(); err != nil {
		t.Fatalf("MarkDone (recent): %v", err)
	}
	wRecent.Close()

	policy := RetentionPolicy{Enabled: true, Days: 7}
	if err := d.SetConfig(ctx, "retention_policy", string(toJSON(policy))); err != nil {
		t.Fatalf("SetConfig retention_policy: %v", err)
	}

	// 0x434c4e50 mirrors the unexported lockID constant doCleanup uses
	// internally; any unused advisory-lock ID works equally for the test.
	d.doCleanup(ctx, 0x434c4e50)

	records, err := d.ListSessions(ctx)
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	var sawOld, sawRecent bool
	for _, r := range records {
		if r.TSID == oldTSID {
			sawOld = true
		}
		if r.TSID == recentTSID {
			sawRecent = true
		}
	}
	if sawOld {
		t.Error("doCleanup did not remove the expired session")
	}
	if !sawRecent {
		t.Error("doCleanup incorrectly removed the non-expired session")
	}
}

func TestDistributedStore_DoCleanup_PurgesExpiredApprovalRequests(t *testing.T) {
	d, _ := newDistributedTestStore(t)
	ctx := t.Context()

	expired := ApprovalRequest{
		ID: "req-expired", User: "alice", Host: "host1", Command: "reboot",
		SubmittedAt: time.Now().Add(-2 * time.Hour),
		ExpiresAt:   time.Now().Add(-1 * time.Hour),
	}
	if err := d.CreateApprovalRequest(ctx, expired); err != nil {
		t.Fatalf("CreateApprovalRequest (expired): %v", err)
	}
	live := ApprovalRequest{
		ID: "req-live", User: "bob", Host: "host1", Command: "systemctl restart nginx",
		SubmittedAt: time.Now(),
		ExpiresAt:   time.Now().Add(1 * time.Hour),
	}
	if err := d.CreateApprovalRequest(ctx, live); err != nil {
		t.Fatalf("CreateApprovalRequest (live): %v", err)
	}

	d.doCleanup(ctx, 0x434c4e51)

	// ListApprovalRequests itself filters out expired rows, so it can't tell
	// us whether doCleanup actually deleted the row vs. it just being
	// filtered — query sudo_approval_requests directly instead.
	var expiredCount, liveCount int
	if err := d.db.QueryRow(ctx, `SELECT count(*) FROM sudo_approval_requests WHERE id=$1`, "req-expired").Scan(&expiredCount); err != nil {
		t.Fatalf("query req-expired: %v", err)
	}
	if err := d.db.QueryRow(ctx, `SELECT count(*) FROM sudo_approval_requests WHERE id=$1`, "req-live").Scan(&liveCount); err != nil {
		t.Fatalf("query req-live: %v", err)
	}
	if expiredCount != 0 {
		t.Error("doCleanup did not purge the expired approval request")
	}
	if liveCount != 1 {
		t.Error("doCleanup incorrectly purged the live approval request")
	}
}
