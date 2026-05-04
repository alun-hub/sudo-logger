package main

import (
	"fmt"
	"log"
	"os/user"
	"sync"
	"time"
)

// divergenceTracker matches eBPF sudo execve events against plugin SESSION_START
// messages to detect cases where sudo ran but the plugin did not log it.
//
// The BPF execve hook already filters out execve events from within tracked
// cgroup scopes, so each sudo invocation produces exactly one event here.
// No grace window or duplicate suppression is needed.
type divergenceTracker struct {
	mu       sync.Mutex
	hostname string
	// pending maps "user|host" to an ordered list of pending sudo execve events.
	// Multiple concurrent sudo invocations by the same user produce multiple entries.
	pending map[string][]*pendingSudoExec
	alertFn func(user, host, comm string, ts time.Time)
}

type pendingSudoExec struct {
	pid      uint32 // PID of the process that called execve
	comm     string // "sudo" or "pkexec"
	wallTime time.Time
	timer    *time.Timer
	// cancelled is set under mu by confirmPlugin before it releases the lock.
	// The timer callback checks this under mu to prevent a false alert when
	// time.Timer.Stop() returns false (timer already fired but callback hasn't
	// acquired mu yet).
	cancelled bool
}

func newDivergenceTracker(hostname string, alertFn func(user, host, comm string, ts time.Time)) *divergenceTracker {
	return &divergenceTracker{
		hostname: hostname,
		pending:  make(map[string][]*pendingSudoExec),
		alertFn:  alertFn,
	}
}

// registerEBPF is called when the eBPF execve hook sees a sudo or pkexec invocation.
// The BPF program already filters out execve events from within tracked cgroup
// scopes, so each sudo invocation produces exactly one event here.
func (d *divergenceTracker) registerEBPF(uid uint32, pid uint32, comm string) {
	username, err := lookupUsername(uid)
	if err != nil {
		debugLog("divergence: uid %d lookup: %v", uid, err)
		return
	}

	now := time.Now()
	key := username + "|" + d.hostname

	entry := &pendingSudoExec{
		pid:      pid,
		comm:     comm,
		wallTime: now,
	}

	// Start the 30-second timer. If no plugin SESSION_START arrives, alert.
	// The callback acquires mu before checking entry.cancelled so that it
	// cannot fire an alert for a session that confirmPlugin has already matched
	// (timer.Stop returns false if the timer fired before Stop was called, but
	// the callback may not have acquired mu yet — the cancelled flag bridges
	// this gap).
	entry.timer = time.AfterFunc(30*time.Second, func() {
		d.mu.Lock()
		if entry.cancelled {
			d.mu.Unlock()
			return
		}
		d.removeEntryLocked(key, entry)
		d.mu.Unlock()
		log.Printf("DIVERGENCE ALERT: %s ran %q on %s but plugin did not log it (no SESSION_START within 30s)",
			username, comm, d.hostname)
		if d.alertFn != nil {
			d.alertFn(username, d.hostname, comm, now)
		}
	})

	d.mu.Lock()
	if len(d.pending[key]) >= maxExecvePerUser {
		d.mu.Unlock()
		entry.timer.Stop()
		log.Printf("divergence: pending queue full for %s — dropping execve pid=%d comm=%s", username, pid, comm)
		return
	}
	d.pending[key] = append(d.pending[key], entry)
	d.mu.Unlock()

	debugLog("divergence: registered %s execve pid=%d by uid=%d user=%s", comm, pid, uid, username)
}

// maxExecveAge is the maximum age of a pending execve entry that can be matched
// against a plugin SESSION_START.  Entries older than this are from sudo
// invocations that never received a SESSION_START (e.g. killed before the
// plugin could respond) and must not pollute future matches.
const maxExecveAge = 10 * time.Second

// maxExecvePerUser caps the per-user pending queue to prevent OOM when a user
// issues many rapid sudo calls that never produce a plugin SESSION_START.
const maxExecvePerUser = 100

// confirmPlugin is called when the plugin delivers a SESSION_START for user+host.
// Returns true if a matching eBPF execve was found (confirmed), false if the
// plugin session has no eBPF witness (unwitnessed — eBPF may be down).
func (d *divergenceTracker) confirmPlugin(username, host string) bool {
	key := username + "|" + host
	now := time.Now()

	d.mu.Lock()
	queue := d.pending[key]

	// Discard stale entries (from sudo invocations that were killed before the
	// plugin responded).  Keep only entries newer than maxExecveAge.
	var fresh []*pendingSudoExec
	for _, e := range queue {
		if now.Sub(e.wallTime) <= maxExecveAge {
			fresh = append(fresh, e)
		} else {
			e.cancelled = true // prevent alert if timer fires during/after Stop
			e.timer.Stop()
			debugLog("divergence: discarding stale execve pid=%d age=%v", e.pid, now.Sub(e.wallTime))
		}
	}

	if len(fresh) == 0 {
		delete(d.pending, key)
		d.mu.Unlock()
		return false // no matching eBPF execve seen — eBPF may be disabled
	}

	// Dequeue the oldest fresh entry (FIFO — concurrent sudo invocations by the
	// same user are matched in the order they arrived).
	entry := fresh[0]
	// Set cancelled under the lock so that a concurrently-firing timer callback
	// that has not yet acquired mu will see it and skip the alert.
	entry.cancelled = true
	if len(fresh) == 1 {
		delete(d.pending, key)
	} else {
		d.pending[key] = fresh[1:]
	}
	d.mu.Unlock()

	entry.timer.Stop() // best-effort; cancelled flag handles the race if Stop returns false

	debugLog("divergence: confirmed plugin SESSION_START for %s@%s pid=%d (latency %v)",
		username, host, entry.pid, time.Since(entry.wallTime))
	return true
}

// removeEntryLocked removes target from the pending queue for key.
// Caller must hold d.mu.
func (d *divergenceTracker) removeEntryLocked(key string, target *pendingSudoExec) {
	queue := d.pending[key]
	for i, e := range queue {
		if e == target {
			d.pending[key] = append(queue[:i], queue[i+1:]...)
			break
		}
	}
	if len(d.pending[key]) == 0 {
		delete(d.pending, key)
	}
}

// lookupUsername resolves a numeric UID to a username.
func lookupUsername(uid uint32) (string, error) {
	u, err := user.LookupId(fmt.Sprintf("%d", uid))
	if err != nil {
		return fmt.Sprintf("uid%d", uid), err
	}
	return u.Username, nil
}
