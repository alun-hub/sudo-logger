package iolog

// Internal tests for Writer.Close's failure paths. They live in package iolog
// (rather than iolog_test) because injecting a write failure means swapping the
// Writer's unexported file handle.

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// failingWriter returns a Writer whose buffered data cannot be flushed: the
// writable handle the constructor opened is replaced with a read-only one to
// the same file. Because that handle is a real open descriptor, the caller can
// afterwards ask whether Close actually released it — a second Close on an
// already-closed *os.File reports os.ErrClosed.
func failingWriter(t *testing.T, sessionID string) (*Writer, *os.File) {
	t.Helper()
	w, err := NewWriter(t.TempDir(), SessionMeta{
		SessionID: sessionID, User: "alice", Host: "host1",
	}, time.Now())
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	if err := w.castF.Close(); err != nil {
		t.Fatalf("closing the original handle: %v", err)
	}

	ro, err := os.Open(filepath.Join(w.Dir(), "session.cast"))
	if err != nil {
		t.Fatalf("reopening read-only: %v", err)
	}
	w.castF = ro
	w.castBuf = bufio.NewWriter(ro)
	if _, err := w.castBuf.WriteString("pending bytes that cannot be flushed\n"); err != nil {
		t.Fatalf("buffering: %v", err)
	}
	return w, ro
}

// TestClose_ReleasesDescriptorWhenFlushFails covers the disk-full path. Close
// used to return the moment Flush or Sync failed, leaving session.cast open —
// one leaked descriptor per failed session, on exactly the volume the agent
// keeps opening new sessions on.
func TestClose_ReleasesDescriptorWhenFlushFails(t *testing.T) {
	w, ro := failingWriter(t, "sess-close-leak")

	if err := w.Close(); err == nil {
		t.Error("Close reported success even though the flush could not succeed")
	}
	if err := ro.Close(); !errors.Is(err, os.ErrClosed) {
		t.Errorf("descriptor leaked: second Close returned %v, want os.ErrClosed", err)
	}
}

// TestClose_ReportsFlushErrorNotCloseError pins the error precedence. A
// truncated recording is what the caller must act on, so a failure from
// closing the descriptor afterwards must not replace it.
func TestClose_ReportsFlushErrorNotCloseError(t *testing.T) {
	w, _ := failingWriter(t, "sess-close-precedence")

	// os.ErrClosed is what closing the (already closed) stand-in handle
	// reports; getting it back would mean the flush failure was overwritten.
	if err := w.Close(); errors.Is(err, os.ErrClosed) {
		t.Errorf("close error shadowed the flush error: %v", err)
	}
}

// TestClose_SucceedsAndClosesOnHappyPath guards the ordinary case: the fix
// must not leave the descriptor open, or closed twice, when nothing fails.
func TestClose_SucceedsAndClosesOnHappyPath(t *testing.T) {
	w, err := NewWriter(t.TempDir(), SessionMeta{
		SessionID: "sess-close-ok", User: "alice", Host: "host1",
	}, time.Now())
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	if err := w.WriteOutput([]byte("hello\r\n"), time.Now().UnixNano()); err != nil {
		t.Fatalf("WriteOutput: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := w.castF.Close(); !errors.Is(err, os.ErrClosed) {
		t.Errorf("descriptor not closed on the happy path: %v", err)
	}
}
