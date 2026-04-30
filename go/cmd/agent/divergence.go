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
// Granularity is per-sudo-invocation, not per TTY session, to avoid false
// positives from normal TTY activity (vim, git, make) that generates eBPF I/O
// without any sudo involvement.
type divergenceTracker struct {
	mu       sync.Mutex
	hostname string
	// pending maps "user|host" to an ordered list of pending sudo execve events.
	// Multiple concurrent sudo invocations by the same user produce multiple entries.
	pending map[string][]*pendingSudoExec
	// lastConfirmed records the PID of the most recently confirmed sudo invocation
	// for a given "user|host" key.  Used to suppress the second execve that sudo
	// fires for the same invocation (sudo fires sys_enter_execve twice: once when
	// the shell exec's sudo, and once when sudo exec's the target command — both
	// events share the same PID because exec does not change PID).
	lastConfirmed map[string]confirmedPID
	alertFn       func(user, host, comm string, ts time.Time)
}

type confirmedPID struct {
	pid uint32
	at  time.Time
}

type pendingSudoExec struct {
	pid      uint32 // PID of the process that called execve
	comm     string // "sudo" or "pkexec"
	wallTime time.Time
	timer    *time.Timer
}

func newDivergenceTracker(hostname string, alertFn func(user, host, comm string, ts time.Time)) *divergenceTracker {
	return &divergenceTracker{
		hostname:      hostname,
		pending:       make(map[string][]*pendingSudoExec),
		lastConfirmed: make(map[string]confirmedPID),
		alertFn:       alertFn,
	}
}

// registerEBPF is called when the eBPF execve hook sees a sudo or pkexec invocation.
// uid is the numeric UID of the invoking user; pid is the PID of the execve caller.
func (d *divergenceTracker) registerEBPF(uid uint32, pid uint32, comm string) {
	username, err := lookupUsername(uid)
	if err != nil {
		debugLog("divergence: uid %d lookup: %v", uid, err)
		return
	}

	now := time.Now()
	key := username + "|" + d.hostname

	// Suppress the second execve that sudo fires for the same invocation.
	// sudo exec's itself (PID X → sudo), then exec's the target command (PID X
	// → target), so both events share the same PID.  If we already confirmed
	// a session for this PID, the second event is a duplicate — skip it.
	d.mu.Lock()
	if c, ok := d.lastConfirmed[key]; ok && c.pid == pid {
		d.mu.Unlock()
		debugLog("divergence: suppressed duplicate execve pid=%d for %s (same sudo invocation)", pid, username)
		return
	}
	d.mu.Unlock()

	entry := &pendingSudoExec{
		pid:      pid,
		comm:     comm,
		wallTime: now,
	}

	// Start the 30-second timer. If no plugin SESSION_START arrives, alert.
	entry.timer = time.AfterFunc(30*time.Second, func() {
		log.Printf("DIVERGENCE ALERT: %s ran %q on %s but plugin did not log it (no SESSION_START within 30s)",
			username, comm, d.hostname)
		if d.alertFn != nil {
			d.alertFn(username, d.hostname, comm, now)
		}
		d.removeEntry(key, entry)
	})

	d.mu.Lock()
	d.pending[key] = append(d.pending[key], entry)
	d.mu.Unlock()

	debugLog("divergence: registered %s execve pid=%d by uid=%d user=%s", comm, pid, uid, username)
}

// confirmPlugin is called when the plugin delivers a SESSION_START for user+host.
// Returns true if a matching eBPF execve was found (confirmed), false if the
// plugin session has no eBPF witness (unwitnessed — eBPF may be down).
func (d *divergenceTracker) confirmPlugin(username, host string) bool {
	key := username + "|" + host
	now := time.Now()

	d.mu.Lock()
	queue := d.pending[key]
	if len(queue) == 0 {
		d.mu.Unlock()
		return false // no matching eBPF execve seen — eBPF may be disabled
	}
	// Dequeue the oldest pending entry (FIFO — sudo invocations are ordered).
	entry := queue[0]
	remaining := queue[1:]

	// A single sudo invocation fires execve twice (once for itself, once for the
	// target command).  Both events share the same PID.  Drain any subsequent
	// entries in the queue that share the same PID — they are part of the same
	// invocation and should not trigger a separate divergence alert.
	var keep []*pendingSudoExec
	for _, e := range remaining {
		if e.pid == entry.pid {
			e.timer.Stop()
		} else {
			keep = append(keep, e)
		}
	}
	if len(keep) == 0 {
		delete(d.pending, key)
	} else {
		d.pending[key] = keep
	}

	// Record the confirmed PID so that any late-arriving duplicate execve with
	// the same PID is suppressed in registerEBPF.
	d.lastConfirmed[key] = confirmedPID{pid: entry.pid, at: now}
	d.mu.Unlock()

	entry.timer.Stop()

	debugLog("divergence: confirmed plugin SESSION_START for %s@%s pid=%d (latency %v)",
		username, host, entry.pid, time.Since(entry.wallTime))
	return true
}

func (d *divergenceTracker) removeEntry(key string, target *pendingSudoExec) {
	d.mu.Lock()
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
	d.mu.Unlock()
}

// lookupUsername resolves a numeric UID to a username.
func lookupUsername(uid uint32) (string, error) {
	u, err := user.LookupId(fmt.Sprintf("%d", uid))
	if err != nil {
		return fmt.Sprintf("uid%d", uid), err
	}
	return u.Username, nil
}
