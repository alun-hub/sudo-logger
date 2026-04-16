package store_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sudo-logger/internal/iolog"
	"sudo-logger/internal/store"
)

// ── GetBlockedPolicy / SaveBlockedPolicy ──────────────────────────────────────

func TestLocalStoreGetBlockedPolicyEmpty(t *testing.T) {
	s, _ := newLocalStore(t)
	defer s.Close()

	ctx := context.Background()
	p, err := s.GetBlockedPolicy(ctx)
	if err != nil {
		t.Fatalf("GetBlockedPolicy: %v", err)
	}
	if len(p.Users) != 0 {
		t.Errorf("expected empty policy, got %d users", len(p.Users))
	}
}

func TestLocalStoreSaveAndGetBlockedPolicy(t *testing.T) {
	tmpDir := t.TempDir()
	blockedPath := filepath.Join(tmpDir, "blocked-users.yaml")

	s, err := store.New(store.Config{
		Backend:          "local",
		LogDir:           tmpDir,
		BlockedUsersPath: blockedPath,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer s.Close()

	ls := s.(*store.LocalStore)
	ctx := context.Background()

	policy := store.BlockedPolicy{
		BlockMessage: "Access denied",
		Users: []store.BlockedUserEntry{
			{Username: "mallory", Hosts: []string{}, Reason: "bad actor"},
			{Username: "attacker", Hosts: []string{"host1", "host2"}, Reason: "suspicious"},
		},
	}
	if err := ls.SaveBlockedPolicy(ctx, policy); err != nil {
		t.Fatalf("SaveBlockedPolicy: %v", err)
	}

	// File must exist on disk.
	if _, err := os.Stat(blockedPath); err != nil {
		t.Fatalf("blocked-users.yaml not written: %v", err)
	}

	// In-memory state is NOT updated synchronously by SaveBlockedPolicy;
	// reload it by creating a new store pointing at the same file.
	s2, err := store.New(store.Config{
		Backend:          "local",
		LogDir:           tmpDir,
		BlockedUsersPath: blockedPath,
	})
	if err != nil {
		t.Fatalf("New (reload): %v", err)
	}
	defer s2.Close()

	ls2 := s2.(*store.LocalStore)
	p, err := ls2.GetBlockedPolicy(ctx)
	if err != nil {
		t.Fatalf("GetBlockedPolicy (reload): %v", err)
	}
	if p.BlockMessage != "Access denied" {
		t.Errorf("BlockMessage: got %q, want %q", p.BlockMessage, "Access denied")
	}
	if len(p.Users) != 2 {
		t.Fatalf("Users: got %d, want 2", len(p.Users))
	}

	byName := make(map[string]store.BlockedUserEntry)
	for _, u := range p.Users {
		byName[u.Username] = u
	}

	if _, ok := byName["mallory"]; !ok {
		t.Error("mallory missing from reloaded policy")
	}
	if u := byName["attacker"]; len(u.Hosts) != 2 {
		t.Errorf("attacker hosts: got %v, want [host1 host2]", u.Hosts)
	}
}

// ── WatchSessions ─────────────────────────────────────────────────────────────

// TestLocalStoreWatchSessionsACTIVERemoval verifies that removing an ACTIVE
// marker file causes WatchSessions to send the session TSID on the channel.
func TestLocalStoreWatchSessionsACTIVERemoval(t *testing.T) {
	s, dir := newLocalStore(t)
	defer s.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ch := make(chan string, 4)
	go s.WatchSessions(ctx, ch)

	// Give fsnotify time to set up watches before we write files.
	time.Sleep(50 * time.Millisecond)

	start := time.Date(2026, 4, 15, 12, 0, 0, 0, time.UTC)
	tsid := seedSession(t, dir, "watchuser", "watchhost", start)
	sessDir := filepath.Join(dir, tsid)

	// Write then remove the ACTIVE marker — this is what MarkActive/MarkDone do.
	activePath := filepath.Join(sessDir, "ACTIVE")
	if err := os.WriteFile(activePath, []byte{}, 0o640); err != nil {
		t.Fatalf("create ACTIVE: %v", err)
	}
	// Give the watcher time to notice the CREATE and add the subdirectory.
	time.Sleep(100 * time.Millisecond)
	if err := os.Remove(activePath); err != nil {
		t.Fatalf("remove ACTIVE: %v", err)
	}

	select {
	case got := <-ch:
		if got != tsid {
			t.Errorf("WatchSessions: got TSID %q, want %q", got, tsid)
		}
	case <-ctx.Done():
		t.Fatal("timeout: WatchSessions did not send TSID after ACTIVE removal")
	}
}

// TestLocalStoreWatchSessionsINCOMPLETE verifies that creating an INCOMPLETE
// marker also triggers a notification.
func TestLocalStoreWatchSessionsINCOMPLETE(t *testing.T) {
	s, dir := newLocalStore(t)
	defer s.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ch := make(chan string, 4)
	go s.WatchSessions(ctx, ch)

	time.Sleep(50 * time.Millisecond)

	start := time.Date(2026, 4, 15, 12, 1, 0, 0, time.UTC)
	tsid := seedSession(t, dir, "watchuser2", "watchhost2", start)
	sessDir := filepath.Join(dir, tsid)

	// Write ACTIVE first so the watcher adds the subdirectory.
	activePath := filepath.Join(sessDir, "ACTIVE")
	if err := os.WriteFile(activePath, []byte{}, 0o640); err != nil {
		t.Fatalf("create ACTIVE: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	// Now create INCOMPLETE.
	incompletePath := filepath.Join(sessDir, "INCOMPLETE")
	if err := os.WriteFile(incompletePath, []byte{}, 0o640); err != nil {
		t.Fatalf("create INCOMPLETE: %v", err)
	}

	select {
	case got := <-ch:
		if got != tsid {
			t.Errorf("WatchSessions INCOMPLETE: got TSID %q, want %q", got, tsid)
		}
	case <-ctx.Done():
		t.Fatal("timeout: WatchSessions did not send TSID after INCOMPLETE creation")
	}
}

// testMeta returns a SessionMeta suitable for test sessions.
func testMeta(user, host string) iolog.SessionMeta {
	return iolog.SessionMeta{
		SessionID: fmt.Sprintf("%s-%s-1-2-aabbccdd", host, user),
		User:      user,
		Host:      host,
		RunasUser: "root",
		Cwd:       "/home/" + user,
		Command:   "/bin/bash",
		Rows:      50,
		Cols:      220,
	}
}

func newLocalStore(t *testing.T) (*store.LocalStore, string) {
	t.Helper()
	dir := t.TempDir()
	s, err := store.New(store.Config{
		Backend: "local",
		LogDir:  dir,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s.(*store.LocalStore), dir
}

// TestLocalStoreCreateSession verifies that CreateSession creates session.cast
// in the expected path under logDir.
func TestLocalStoreCreateSession(t *testing.T) {
	s, dir := newLocalStore(t)
	defer s.Close()

	ctx := context.Background()
	start := time.Date(2026, 4, 8, 10, 0, 0, 0, time.UTC)
	meta := testMeta("alice", "host1")

	w, err := s.CreateSession(ctx, meta, start)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	defer w.Close()

	// TSID format: user/host_timestamp
	tsid := w.TSID()
	if !strings.HasPrefix(tsid, "alice/host1_") {
		t.Errorf("TSID %q does not start with alice/host1_", tsid)
	}

	castPath := filepath.Join(dir, tsid, "session.cast")
	if _, err := os.Stat(castPath); err != nil {
		t.Errorf("session.cast not found at %s: %v", castPath, err)
	}
}

// TestLocalWriterMarkers verifies the ACTIVE, INCOMPLETE, and MarkDone marker operations.
func TestLocalWriterMarkers(t *testing.T) {
	s, dir := newLocalStore(t)
	defer s.Close()

	ctx := context.Background()
	w, err := s.CreateSession(ctx, testMeta("bob", "host2"), time.Now())
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	sessDir := filepath.Join(dir, w.TSID())

	// MarkActive — ACTIVE file should appear.
	if err := w.MarkActive(); err != nil {
		t.Fatalf("MarkActive: %v", err)
	}
	if _, err := os.Stat(filepath.Join(sessDir, "ACTIVE")); err != nil {
		t.Errorf("ACTIVE not found after MarkActive: %v", err)
	}

	// MarkDone — ACTIVE file should disappear.
	if err := w.MarkDone(); err != nil {
		t.Fatalf("MarkDone: %v", err)
	}
	if _, err := os.Stat(filepath.Join(sessDir, "ACTIVE")); err == nil {
		t.Error("ACTIVE still exists after MarkDone")
	}

	// MarkIncomplete — INCOMPLETE file should appear.
	if err := w.MarkIncomplete(); err != nil {
		t.Fatalf("MarkIncomplete: %v", err)
	}
	if _, err := os.Stat(filepath.Join(sessDir, "INCOMPLETE")); err != nil {
		t.Errorf("INCOMPLETE not found after MarkIncomplete: %v", err)
	}

	w.Close()
}

// TestLocalWriterWriteExitCode verifies the exit_code file content.
func TestLocalWriterWriteExitCode(t *testing.T) {
	s, dir := newLocalStore(t)
	defer s.Close()

	ctx := context.Background()
	w, err := s.CreateSession(ctx, testMeta("carol", "host3"), time.Now())
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	defer w.Close()

	if err := w.WriteExitCode(42); err != nil {
		t.Fatalf("WriteExitCode: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, w.TSID(), "exit_code"))
	if err != nil {
		t.Fatalf("read exit_code: %v", err)
	}
	if strings.TrimSpace(string(data)) != "42" {
		t.Errorf("exit_code content: got %q, want %q", string(data), "42")
	}
}

// seedSession writes a minimal session directory with a cast file.
func seedSession(t *testing.T, logDir, user, host string, start time.Time, events ...string) string {
	t.Helper()
	ts := start.UTC().Format("20060102-150405")
	sessDir := filepath.Join(logDir, user, fmt.Sprintf("%s_%s", host, ts))
	if err := os.MkdirAll(sessDir, 0o750); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	hdr := map[string]any{
		"version":    2,
		"width":      220,
		"height":     50,
		"timestamp":  start.Unix(),
		"session_id": fmt.Sprintf("%s-%s", host, user),
		"user":       user,
		"host":       host,
		"runas_user": "root",
		"command":    "/bin/bash",
	}
	b, _ := json.Marshal(hdr)
	castContent := string(b) + "\n"
	for i, ev := range events {
		line, _ := json.Marshal([]any{float64(i) + 0.1, "o", ev})
		castContent += string(line) + "\n"
	}
	if err := os.WriteFile(filepath.Join(sessDir, "session.cast"), []byte(castContent), 0o640); err != nil {
		t.Fatalf("write session.cast: %v", err)
	}

	tsid := user + "/" + fmt.Sprintf("%s_%s", host, ts)
	return tsid
}

// TestLocalStoreListSessions verifies that ListSessions returns seeded sessions.
func TestLocalStoreListSessions(t *testing.T) {
	s, dir := newLocalStore(t)
	defer s.Close()

	start := time.Date(2026, 4, 8, 9, 0, 0, 0, time.UTC)
	tsid1 := seedSession(t, dir, "alice", "host1", start, "hello")
	tsid2 := seedSession(t, dir, "bob", "host2", start.Add(time.Minute))

	ctx := context.Background()
	records, err := s.ListSessions(ctx)
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("got %d records, want 2", len(records))
	}

	byTSID := make(map[string]store.SessionRecord)
	for _, r := range records {
		byTSID[r.TSID] = r
	}

	r1, ok := byTSID[tsid1]
	if !ok {
		t.Fatalf("session %s not found in list", tsid1)
	}
	if r1.User != "alice" {
		t.Errorf("user: got %q, want %q", r1.User, "alice")
	}
	if r1.Host != "host1" {
		t.Errorf("host: got %q, want %q", r1.Host, "host1")
	}

	if _, ok := byTSID[tsid2]; !ok {
		t.Fatalf("session %s not found in list", tsid2)
	}
}

// TestLocalStoreReadEvents verifies that ReadEvents returns the correct events.
func TestLocalStoreReadEvents(t *testing.T) {
	s, dir := newLocalStore(t)
	defer s.Close()

	start := time.Date(2026, 4, 8, 9, 0, 0, 0, time.UTC)
	tsid := seedSession(t, dir, "dave", "host4", start, "output1", "output2")

	ctx := context.Background()
	events, err := s.ReadEvents(ctx, tsid)
	if err != nil {
		t.Fatalf("ReadEvents: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("got %d events, want 2", len(events))
	}
	if events[0].Kind != "o" {
		t.Errorf("event[0].Kind: got %q, want %q", events[0].Kind, "o")
	}
	if string(events[0].Data) != "output1" {
		t.Errorf("event[0].Data: got %q, want %q", string(events[0].Data), "output1")
	}
}

// TestLocalStoreRiskCache verifies cache hit/miss on same/different hash.
func TestLocalStoreRiskCache(t *testing.T) {
	s, dir := newLocalStore(t)
	defer s.Close()

	start := time.Date(2026, 4, 8, 9, 0, 0, 0, time.UTC)
	tsid := seedSession(t, dir, "eve", "host5", start)

	ctx := context.Background()

	// Cache miss: nothing stored yet.
	if rc, err := s.GetRiskCache(ctx, tsid, "hash1"); err != nil || rc != nil {
		t.Errorf("expected cache miss, got rc=%v err=%v", rc, err)
	}

	// Save a cache entry.
	if err := s.SaveRiskCache(ctx, tsid, "hash1", 75, []string{"reason1"}); err != nil {
		t.Fatalf("SaveRiskCache: %v", err)
	}

	// Cache hit with same hash.
	rc, err := s.GetRiskCache(ctx, tsid, "hash1")
	if err != nil {
		t.Fatalf("GetRiskCache: %v", err)
	}
	if rc == nil {
		t.Fatal("expected cache hit, got nil")
	}
	if rc.Score != 75 {
		t.Errorf("Score: got %d, want 75", rc.Score)
	}
	if len(rc.Reasons) != 1 || rc.Reasons[0] != "reason1" {
		t.Errorf("Reasons: got %v, want [reason1]", rc.Reasons)
	}

	// Cache miss with different hash (stale).
	if rc, err := s.GetRiskCache(ctx, tsid, "hash2"); err != nil || rc != nil {
		t.Errorf("expected stale cache miss, got rc=%v err=%v", rc, err)
	}
}

// TestLocalStoreIsBlocked verifies blocked/allowed user lookups.
func TestLocalStoreIsBlocked(t *testing.T) {
	tmpDir := t.TempDir()
	blockedPath := filepath.Join(tmpDir, "blocked-users.yaml")

	blockedYAML := `block_message: "You are blocked"
users:
  - username: mallory
    hosts: []
    reason: bad actor
  - username: suspicious
    hosts: [host99]
    reason: host-specific block
`
	if err := os.WriteFile(blockedPath, []byte(blockedYAML), 0o640); err != nil {
		t.Fatalf("write blocked-users.yaml: %v", err)
	}

	s, err := store.New(store.Config{
		Backend:          "local",
		LogDir:           tmpDir,
		BlockedUsersPath: blockedPath,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer s.Close()

	ctx := context.Background()

	// mallory is blocked on all hosts.
	blocked, msg, err := s.IsBlocked(ctx, "mallory", "anyhost")
	if err != nil {
		t.Fatalf("IsBlocked: %v", err)
	}
	if !blocked {
		t.Error("mallory should be blocked on anyhost")
	}
	if msg != "You are blocked" {
		t.Errorf("block message: got %q, want %q", msg, "You are blocked")
	}

	// suspicious is blocked only on host99.
	blocked, _, err = s.IsBlocked(ctx, "suspicious", "host99")
	if err != nil {
		t.Fatalf("IsBlocked: %v", err)
	}
	if !blocked {
		t.Error("suspicious should be blocked on host99")
	}

	blocked, _, err = s.IsBlocked(ctx, "suspicious", "otherhost")
	if err != nil {
		t.Fatalf("IsBlocked: %v", err)
	}
	if blocked {
		t.Error("suspicious should NOT be blocked on otherhost")
	}

	// alice is not blocked at all.
	blocked, _, err = s.IsBlocked(ctx, "alice", "host1")
	if err != nil {
		t.Fatalf("IsBlocked: %v", err)
	}
	if blocked {
		t.Error("alice should not be blocked")
	}
}

// TestLocalStorePathConfinement verifies that ReadEvents rejects path-traversal TSIDs.
func TestLocalStorePathConfinement(t *testing.T) {
	s, _ := newLocalStore(t)
	defer s.Close()

	ctx := context.Background()
	_, err := s.ReadEvents(ctx, "../../../etc/passwd")
	if err == nil {
		t.Error("expected error for path-traversal TSID, got nil")
	}
}
