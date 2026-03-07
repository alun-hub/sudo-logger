// cgroup.go — per-session cgroup management for sudo-shipper.
//
// When the shipper service runs with Delegate=yes in its systemd unit it owns
// a cgroup subtree.  For each sudo session the shipper creates a sub-cgroup,
// moves the sudo process into it before sending SESSION_READY, and then
// freeze/thaws that sub-cgroup when the log server becomes unreachable or
// recovers.
//
// Because fork(2) inherits cgroup membership, all child processes — including
// GUI programs (gvim, okular, …) that double-fork and re-parent to
// init/systemd — remain in the session cgroup and are frozen atomically.
// Re-parenting in the process tree never changes cgroup membership.
//
// Graceful degradation: if cgroupBase is empty (cgroup v2 unavailable or
// Delegate=yes not set), newCgroupSession returns nil and all methods on a
// nil *cgroupSession are no-ops.
package main

import (
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// cgroupBase is the cgroup v2 directory delegated to this service process.
// Populated once in init(); empty when cgroups are unavailable.
var cgroupBase string

func init() {
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return
	}
	// cgroup v2 unified hierarchy produces a single line: "0::<path>"
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "0::") {
			rel := strings.TrimSpace(strings.TrimPrefix(line, "0::"))
			base := "/sys/fs/cgroup" + rel
			if _, err := os.Stat(base); err == nil {
				cgroupBase = base
				log.Printf("cgroup: delegated subtree at %s", base)
			}
			return
		}
	}
}

// cgroupSession is the cgroup created for a single sudo session.
type cgroupSession struct {
	path   string
	mu     sync.Mutex
	frozen bool
}

// newCgroupSession creates a sub-cgroup under cgroupBase named after sessionID
// and moves sudoPid into it so that all subsequent forks (including GUI
// programs that later detach) inherit the cgroup membership.
// Returns nil when cgroup delegation is unavailable.
func newCgroupSession(sessionID string, sudoPid int) *cgroupSession {
	if cgroupBase == "" || sudoPid <= 0 {
		return nil
	}
	path := filepath.Join(cgroupBase, sessionID)
	if err := os.Mkdir(path, 0755); err != nil {
		log.Printf("cgroup: mkdir %s: %v", path, err)
		return nil
	}
	if err := os.WriteFile(
		filepath.Join(path, "cgroup.procs"),
		[]byte(strconv.Itoa(sudoPid)+"\n"),
		0644,
	); err != nil {
		log.Printf("cgroup: move sudo pid %d: %v", sudoPid, err)
		// Keep the cgroup even on failure — the directory exists and the
		// freeze file is still functional for any PIDs that do land here.
	}
	log.Printf("cgroup: session %s created, sudo pid %d", filepath.Base(path), sudoPid)
	return &cgroupSession{path: path}
}

// freeze suspends all processes in the session cgroup (idempotent).
func (cg *cgroupSession) freeze() {
	if cg == nil {
		return
	}
	cg.mu.Lock()
	defer cg.mu.Unlock()
	if cg.frozen {
		return
	}
	if err := os.WriteFile(
		filepath.Join(cg.path, "cgroup.freeze"), []byte("1\n"), 0644,
	); err != nil {
		log.Printf("cgroup freeze: %v", err)
		return
	}
	cg.frozen = true
	log.Printf("cgroup %s: frozen", filepath.Base(cg.path))
}

// unfreeze resumes all processes in the session cgroup (idempotent).
func (cg *cgroupSession) unfreeze() {
	if cg == nil {
		return
	}
	cg.mu.Lock()
	defer cg.mu.Unlock()
	if !cg.frozen {
		return
	}
	if err := os.WriteFile(
		filepath.Join(cg.path, "cgroup.freeze"), []byte("0\n"), 0644,
	); err != nil {
		log.Printf("cgroup unfreeze: %v", err)
		return
	}
	cg.frozen = false
	log.Printf("cgroup %s: unfrozen", filepath.Base(cg.path))
}

// remove unfreezes the cgroup, migrates any remaining processes (e.g. a
// detached gvim window) to the parent cgroup, then removes the directory.
// Safe to call on a nil receiver.
func (cg *cgroupSession) remove() {
	if cg == nil {
		return
	}
	// Must unfreeze before migrating — frozen cgroups block process moves.
	_ = os.WriteFile(filepath.Join(cg.path, "cgroup.freeze"), []byte("0\n"), 0644)

	// Drain remaining processes to the parent cgroup so rmdir succeeds.
	parentProcs := filepath.Join(filepath.Dir(cg.path), "cgroup.procs")
	if data, err := os.ReadFile(filepath.Join(cg.path, "cgroup.procs")); err == nil {
		for _, pid := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			if pid != "" {
				_ = os.WriteFile(parentProcs, []byte(pid+"\n"), 0644)
			}
		}
	}
	if err := os.Remove(cg.path); err != nil {
		log.Printf("cgroup remove %s: %v", cg.path, err)
	} else {
		log.Printf("cgroup %s: removed", filepath.Base(cg.path))
	}
}
