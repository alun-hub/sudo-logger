package main

import (
	"testing"
	"time"
)

// newTestPendingExec builds a pendingSudoExec with a long-lived timer so
// confirmPlugin's timer.Stop() call is always operating on a real timer
// (never nil), without the 30s alert actually firing during the test.
func newTestPendingExec(pid uint32, age time.Duration) *pendingSudoExec {
	e := &pendingSudoExec{
		pid:      pid,
		comm:     "sudo",
		wallTime: time.Now().Add(-age),
	}
	e.timer = time.AfterFunc(time.Hour, func() {})
	return e
}

// TestConfirmPlugin_MatchesByPidNotFIFO is the regression test for the
// divergence-detection bypass: confirmPlugin must confirm the entry whose
// pid matches the plugin's reported SessionStart.Pid, not just dequeue the
// FIFO-oldest pending entry. Before the fix, an attacker who bypassed the
// plugin for one sudo invocation (pid 100, oldest) could have that bypass
// silently "confirmed away" by a second, unrelated, properly-logged sudo
// invocation (pid 200) from the same user within maxExecveAge.
func TestConfirmPlugin_MatchesByPidNotFIFO(t *testing.T) {
	d := newDivergenceTracker("myhost", nil)
	key := "alice|myhost"

	older := newTestPendingExec(100, 5*time.Second) // the "bypassed" invocation
	newer := newTestPendingExec(200, 1*time.Second)  // the unrelated, legitimate one
	d.pending[key] = []*pendingSudoExec{older, newer}

	// The plugin reports SESSION_START for pid 200 (the newer, legitimate
	// invocation) -- it must NOT confirm/cancel pid 100's entry.
	if !d.confirmPlugin("alice", "myhost", 200) {
		t.Fatal("confirmPlugin(pid=200) = false, want true (matching entry exists)")
	}

	d.mu.Lock()
	remaining := d.pending[key]
	d.mu.Unlock()

	if len(remaining) != 1 || remaining[0].pid != 100 {
		t.Fatalf("after confirming pid=200, pending queue = %v, want exactly pid=100 still pending", remaining)
	}
	if older.cancelled {
		t.Error("pid=100's entry must NOT be cancelled -- it was never confirmed")
	}
	if !newer.cancelled {
		t.Error("pid=200's entry should be marked cancelled after being confirmed")
	}

	// The still-pending pid=100 entry must still be confirmable on its own
	// (e.g. if it really was an unwitnessed/bypassed invocation, eBPF's own
	// 30s alert timer -- not confirmPlugin -- is what should eventually fire
	// for it; here we just confirm it's not lost or corrupted).
	if !d.confirmPlugin("alice", "myhost", 100) {
		t.Fatal("confirmPlugin(pid=100) = false, want true (still pending, now confirmable)")
	}

	older.timer.Stop()
	newer.timer.Stop()
}

// TestConfirmPlugin_NoMatchLeavesQueueIntact covers the "unwitnessed" path:
// a pid with no matching eBPF entry must return false without disturbing
// other pending (possibly-still-legitimate) entries for the same user@host.
func TestConfirmPlugin_NoMatchLeavesQueueIntact(t *testing.T) {
	d := newDivergenceTracker("myhost", nil)
	key := "bob|myhost"

	e := newTestPendingExec(300, 1*time.Second)
	d.pending[key] = []*pendingSudoExec{e}

	if d.confirmPlugin("bob", "myhost", 999) {
		t.Fatal("confirmPlugin(pid=999) = true, want false (no matching entry)")
	}

	d.mu.Lock()
	remaining := d.pending[key]
	d.mu.Unlock()
	if len(remaining) != 1 || remaining[0].pid != 300 {
		t.Fatalf("unrelated pending entry must survive a non-matching confirmPlugin call, got %v", remaining)
	}

	e.timer.Stop()
}

// TestConfirmPlugin_StaleEntriesDiscarded confirms entries older than
// maxExecveAge are dropped even when their pid would otherwise match, and
// don't leak into a later match attempt.
func TestConfirmPlugin_StaleEntriesDiscarded(t *testing.T) {
	d := newDivergenceTracker("myhost", nil)
	key := "carol|myhost"

	stale := newTestPendingExec(400, maxExecveAge+5*time.Second)
	d.pending[key] = []*pendingSudoExec{stale}

	if d.confirmPlugin("carol", "myhost", 400) {
		t.Fatal("confirmPlugin matched a stale (>maxExecveAge) entry, want false")
	}

	d.mu.Lock()
	_, exists := d.pending[key]
	d.mu.Unlock()
	if exists {
		t.Error("stale entry's key should be removed from pending entirely")
	}
}
