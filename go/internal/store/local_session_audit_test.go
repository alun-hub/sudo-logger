package store_test

// Tests for LocalStore's session audit surface: OpenCast, RecordView/
// ListAccessLog, and the GDPR DeleteSession path.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ── OpenCast ──────────────────────────────────────────────────────────────────

func TestLocalStoreOpenCast(t *testing.T) {
	s, _ := newLocalStore(t)
	defer s.Close()
	ctx := t.Context()

	w, err := s.CreateSession(ctx, testMeta("alice", "host1"), time.Now())
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	tsid := w.TSID()
	w.Close()

	rc, err := s.OpenCast(ctx, tsid)
	if err != nil {
		t.Fatalf("OpenCast: %v", err)
	}
	defer rc.Close()

	data := make([]byte, 4096)
	n, _ := rc.Read(data)
	if n == 0 {
		t.Error("OpenCast returned an empty reader for a real session")
	}
}

func TestLocalStoreOpenCast_MissingSession(t *testing.T) {
	s, _ := newLocalStore(t)
	defer s.Close()

	_, err := s.OpenCast(t.Context(), "nobody/nowhere_20260101-000000")
	if err == nil {
		t.Error("OpenCast should error for a session that does not exist")
	}
}

// ── RecordView / ListAccessLog ───────────────────────────────────────────────

func TestLocalStoreRecordAndListAccessLog(t *testing.T) {
	s, _ := newLocalStore(t)
	defer s.Close()
	ctx := t.Context()

	if err := s.RecordView(ctx, "alice/host1_1", "bob", "/replay/1"); err != nil {
		t.Fatalf("RecordView: %v", err)
	}
	if err := s.RecordView(ctx, "alice/host1_2", "carol", "/replay/2"); err != nil {
		t.Fatalf("RecordView: %v", err)
	}

	all, err := s.ListAccessLog(ctx, "", 10)
	if err != nil {
		t.Fatalf("ListAccessLog: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("ListAccessLog count = %d, want 2", len(all))
	}
	// Newest first.
	if all[0].Viewer != "carol" || all[1].Viewer != "bob" {
		t.Errorf("ListAccessLog order = [%s, %s], want [carol, bob] (newest first)", all[0].Viewer, all[1].Viewer)
	}
}

func TestLocalStoreListAccessLog_FilterByViewer(t *testing.T) {
	s, _ := newLocalStore(t)
	defer s.Close()
	ctx := t.Context()

	s.RecordView(ctx, "a/h_1", "bob", "/replay/1")   //nolint:errcheck
	s.RecordView(ctx, "a/h_2", "carol", "/replay/2") //nolint:errcheck
	s.RecordView(ctx, "a/h_3", "bob", "/replay/3")   //nolint:errcheck

	filtered, err := s.ListAccessLog(ctx, "bob", 10)
	if err != nil {
		t.Fatalf("ListAccessLog: %v", err)
	}
	if len(filtered) != 2 {
		t.Fatalf("filtered ListAccessLog count = %d, want 2", len(filtered))
	}
	for _, e := range filtered {
		if e.Viewer != "bob" {
			t.Errorf("unexpected viewer %q in bob-filtered results", e.Viewer)
		}
	}
}

func TestLocalStoreListAccessLog_RespectsLimit(t *testing.T) {
	s, _ := newLocalStore(t)
	defer s.Close()
	ctx := t.Context()

	for i := 0; i < 5; i++ {
		if err := s.RecordView(ctx, fmt.Sprintf("a/h_%d", i), "bob", "/replay"); err != nil {
			t.Fatalf("RecordView: %v", err)
		}
	}
	limited, err := s.ListAccessLog(ctx, "", 2)
	if err != nil {
		t.Fatalf("ListAccessLog: %v", err)
	}
	if len(limited) != 2 {
		t.Errorf("ListAccessLog with limit=2 returned %d entries", len(limited))
	}
}

// ── DeleteSession (GDPR path) ─────────────────────────────────────────────────

func TestLocalStoreDeleteSession(t *testing.T) {
	s, dir := newLocalStore(t)
	defer s.Close()
	ctx := t.Context()

	w, err := s.CreateSession(ctx, testMeta("alice", "host1"), time.Now())
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	tsid := w.TSID()
	w.Close()

	// A freshly created session was never marked active, so it's already
	// eligible for deletion without needing an explicit MarkDone call.
	if err := s.DeleteSession(ctx, tsid, "GDPR request", "admin"); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, tsid)); !os.IsNotExist(err) {
		t.Error("session directory should be removed after DeleteSession")
	}

	// A deletion audit entry must be appended to .deletion-log.jsonl.
	logData, err := os.ReadFile(filepath.Join(dir, ".deletion-log.jsonl"))
	if err != nil {
		t.Fatalf("read deletion log: %v", err)
	}
	logStr := string(logData)
	if !strings.Contains(logStr, tsid) || !strings.Contains(logStr, "GDPR request") || !strings.Contains(logStr, "admin") {
		t.Errorf("deletion log entry missing expected fields: %s", logStr)
	}
}

func TestLocalStoreDeleteSession_RefusesActiveSession(t *testing.T) {
	s, _ := newLocalStore(t)
	defer s.Close()
	ctx := t.Context()

	w, err := s.CreateSession(ctx, testMeta("alice", "host1"), time.Now())
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	tsid := w.TSID()
	if err := w.MarkActive(); err != nil {
		t.Fatalf("MarkActive: %v", err)
	}
	defer w.Close()

	if err := s.DeleteSession(ctx, tsid, "attempted deletion", "attacker"); err == nil {
		t.Error("DeleteSession should refuse to delete a still-active session")
	}
}

func TestLocalStoreDeleteSession_MissingSession(t *testing.T) {
	s, _ := newLocalStore(t)
	defer s.Close()

	if err := s.DeleteSession(t.Context(), "nobody/nowhere_20260101-000000", "x", "admin"); err == nil {
		t.Error("DeleteSession should error for a session that does not exist")
	}
}

func TestLocalStoreDeleteSession_RejectsTraversalTSID(t *testing.T) {
	s, _ := newLocalStore(t)
	defer s.Close()

	if err := s.DeleteSession(t.Context(), "../../etc/passwd", "x", "admin"); err == nil {
		t.Error("DeleteSession should reject a TSID that attempts to escape LogDir")
	}
}
