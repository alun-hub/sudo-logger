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
	pending       map[string][]*pendingSudoExec
	// lastConfirmed records when the most recent plugin SESSION_START was confirmed
	// for a given "user|host" key.  Used to suppress duplicate execve events that
	// arrive after confirmPlugin returns (sudo fires 2 execve calls per invocation).
	lastConfirmed map[string]time.Time
	alertFn       func(user, host, comm string, ts time.Time)
}

type pendingSudoExec struct {
	comm     string // "sudo" or "pkexec"
	wallTime time.Time
	timer    *time.Timer
}

func newDivergenceTracker(hostname string, alertFn func(user, host, comm string, ts time.Time)) *divergenceTracker {
	return &divergenceTracker{
		hostname:      hostname,
		pending:       make(map[string][]*pendingSudoExec),
		lastConfirmed: make(map[string]time.Time),
		alertFn:       alertFn,
	}
}

// registerEBPF is called when the eBPF execve hook sees a sudo or pkexec invocation.
// uid is the numeric UID of the invoking user; cgroupID is the parent cgroup.
func (d *divergenceTracker) registerEBPF(uid uint32, comm string) {
	username, err := lookupUsername(uid)
	if err != nil {
		debugLog("divergence: uid %d lookup: %v", uid, err)
		return
	}

	now := time.Now()
	key := username + "|" + d.hostname

	// Suppress duplicate execve events that arrive after confirmPlugin has already
	// run.  sudo fires sys_enter_execve twice per invocation (once for itself, once
	// when exec'ing the target command); the second event arrives ~1 s after the
	// first has already been confirmed by the plugin SESSION_START.
	d.mu.Lock()
	if t, ok := d.lastConfirmed[key]; ok && now.Sub(t) < 5*time.Second {
		d.mu.Unlock()
		debugLog("divergence: suppressed duplicate execve for %s within grace window", username)
		return
	}
	d.mu.Unlock()

	entry := &pendingSudoExec{
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

	debugLog("divergence: registered %s execve by uid=%d user=%s", comm, uid, username)
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

	// A single sudo invocation can produce multiple execve events (sudo execs
	// itself for pty handling, then execs the target command).  Drain any
	// subsequent entries registered within 5 s — they are part of the same
	// invocation and should not trigger a separate divergence alert.
	var keep []*pendingSudoExec
	for _, e := range remaining {
		if now.Sub(e.wallTime) < 5*time.Second {
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
	d.mu.Unlock()

	entry.timer.Stop()
	// Record confirmation time so that late-arriving duplicate execve events
	// from the same sudo invocation are suppressed in registerEBPF.
	d.mu.Lock()
	d.lastConfirmed[key] = now
	d.mu.Unlock()

	debugLog("divergence: confirmed plugin SESSION_START for %s@%s (latency %v)",
		username, host, time.Since(entry.wallTime))
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
