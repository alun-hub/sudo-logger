package store_test

import (
	"context"
	"testing"
	"time"

	"sudo-logger/internal/store"
)

func newApprovalStore(t *testing.T) (*store.LocalStore, string) {
	t.Helper()
	s, dir := newLocalStore(t)
	// Close before TempDir cleanup; sleep briefly so async save goroutines drain.
	t.Cleanup(func() {
		s.Close()
		time.Sleep(150 * time.Millisecond)
	})
	return s, dir
}

func TestApproval_CreateListDelete(t *testing.T) {
	ls, _ := newApprovalStore(t)
	ctx := context.Background()

	req := store.ApprovalRequest{
		ID:        "req-1",
		User:      "alice",
		Host:      "prod-01",
		Command:   "systemctl restart nginx",
		ExpiresAt: time.Now().Add(time.Hour),
	}

	if err := ls.CreateApprovalRequest(ctx, req); err != nil {
		t.Fatalf("CreateApprovalRequest: %v", err)
	}

	reqs, err := ls.ListApprovalRequests(ctx)
	if err != nil {
		t.Fatalf("ListApprovalRequests: %v", err)
	}
	if len(reqs) != 1 || reqs[0].ID != "req-1" {
		t.Errorf("expected 1 request ID=req-1, got %v", reqs)
	}

	deleted, err := ls.DeleteApprovalRequest(ctx, "req-1")
	if err != nil || deleted == nil || deleted.ID != "req-1" {
		t.Errorf("DeleteApprovalRequest: got %v, err %v", deleted, err)
	}

	reqs, _ = ls.ListApprovalRequests(ctx)
	if len(reqs) != 0 {
		t.Errorf("expected 0 requests after delete, got %d", len(reqs))
	}
}

func TestApproval_ExpiredRequestNotListed(t *testing.T) {
	ls, _ := newApprovalStore(t)
	ctx := context.Background()

	req := store.ApprovalRequest{
		ID:        "expired-1",
		User:      "bob",
		ExpiresAt: time.Now().Add(-time.Minute),
	}
	ls.CreateApprovalRequest(ctx, req)

	reqs, _ := ls.ListApprovalRequests(ctx)
	if len(reqs) != 0 {
		t.Errorf("expired request should not be listed, got %d", len(reqs))
	}
}

func TestApproval_DeleteNonExistent(t *testing.T) {
	ls, _ := newApprovalStore(t)
	ctx := context.Background()

	deleted, err := ls.DeleteApprovalRequest(ctx, "does-not-exist")
	if err != nil {
		t.Errorf("expected nil error for missing ID, got %v", err)
	}
	if deleted != nil {
		t.Errorf("expected nil for missing ID, got %v", deleted)
	}
}

func TestApprovalWindow_CreateAndHas(t *testing.T) {
	ls, _ := newApprovalStore(t)
	ctx := context.Background()

	_, has, _ := ls.HasApprovalWindow(ctx, "alice", "prod-01")
	if has {
		t.Error("expected no window before creation")
	}

	expires := time.Now().Add(time.Hour)
	if err := ls.CreateApprovalWindow(ctx, "alice", "prod-01", "admin", expires); err != nil {
		t.Fatalf("CreateApprovalWindow: %v", err)
	}

	got, has, err := ls.HasApprovalWindow(ctx, "alice", "prod-01")
	if err != nil || !has {
		t.Errorf("HasApprovalWindow: has=%v err=%v", has, err)
	}
	if got.Unix() != expires.Unix() {
		t.Errorf("window expiry: got %v, want %v", got, expires)
	}

	_, has, _ = ls.HasApprovalWindow(ctx, "alice", "other-host")
	if has {
		t.Error("expected no window for different host")
	}
}

func TestApprovalWindow_Replace(t *testing.T) {
	ls, _ := newApprovalStore(t)
	ctx := context.Background()

	t1 := time.Now().Add(time.Hour)
	t2 := time.Now().Add(2 * time.Hour)
	ls.CreateApprovalWindow(ctx, "alice", "host1", "admin1", t1)
	ls.CreateApprovalWindow(ctx, "alice", "host1", "admin2", t2)

	got, _, _ := ls.HasApprovalWindow(ctx, "alice", "host1")
	if got.Unix() != t2.Unix() {
		t.Errorf("window not replaced: got %v, want %v", got, t2)
	}
}

func TestApprovalWindow_ExpiredNotFound(t *testing.T) {
	ls, _ := newApprovalStore(t)
	ctx := context.Background()

	past := time.Now().Add(-time.Minute)
	ls.CreateApprovalWindow(ctx, "alice", "host1", "admin", past)

	_, has, _ := ls.HasApprovalWindow(ctx, "alice", "host1")
	if has {
		t.Error("expired window should not be found")
	}
}

func TestApproval_PersistRoundTrip(t *testing.T) {
	dir := t.TempDir()

	open := func() *store.LocalStore {
		s, err := store.New(testStoreConfig(dir))
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		return s.(*store.LocalStore)
	}

	ctx := context.Background()
	s1 := open()
	req := store.ApprovalRequest{
		ID:        "persist-1",
		User:      "carol",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	s1.CreateApprovalRequest(ctx, req)
	time.Sleep(100 * time.Millisecond) // let async saveApprovalStore finish
	s1.Close()

	s2 := open()
	defer s2.Close()
	reqs, err := s2.ListApprovalRequests(ctx)
	if err != nil {
		t.Fatalf("ListApprovalRequests after reload: %v", err)
	}
	if len(reqs) == 0 {
		t.Fatal("expected persisted request to survive reload, got 0")
	}
	if reqs[0].ID != "persist-1" {
		t.Errorf("expected ID=persist-1, got %q", reqs[0].ID)
	}
}
