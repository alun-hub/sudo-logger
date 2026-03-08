// cgroup.go — per-session cgroup management for sudo-shipper.
//
// Creates a sub-cgroup per sudo session and moves the sudo process into it
// before SESSION_READY so that all forked children inherit the cgroup.
//
// Design: freeze only children, not sudo
// ──────────────────────────────────────
// If sudo itself is in the frozen cgroup it can never send SESSION_END, so
// the shipper goroutine blocks forever in ReadHeader.  To avoid this, the
// background tracker moves sudo's PID back to the parent cgroup as soon as
// it detects the first child process (bash, gvim-launcher, …).  After that:
//   • Terminal programs (bash, vi, …) — frozen via cgroup.freeze.
//   • GUI programs (gvim, okular, …) — typically moved by GNOME/systemd to
//     an app-*.scope cgroup before our tracker sees them.  Detected as
//     "escaped" and frozen via SIGSTOP/SIGCONT instead.
//
// The tracker polls /proc/<pid>/task/<pid>/children every 10 ms and also
// re-checks every known PID's cgroup membership so late GNOME migrations are
// caught even if the PID was initially seen inside our cgroup.
//
// Graceful degradation: nil receiver is safe on all exported methods.
package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

var (
	cgroupBase  string
	shipperPgid int // our own process group — never signal this
)

func init() {
	shipperPgid = syscall.Getpgrp() // always exclude our own process group
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return
	}
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

// signalGroup sends sig to the entire process group of pid.
// This ensures that bash and any subprocess it is currently running are both
// reached.  Falls back to signalling pid directly if pgid lookup fails or if
// the pgid belongs to the shipper itself.
func signalGroup(pid int, sig syscall.Signal) {
	if pgid, err := syscall.Getpgid(pid); err == nil && pgid > 1 && pgid != shipperPgid {
		syscall.Kill(-pgid, sig)
	} else {
		syscall.Kill(pid, sig)
	}
}

type cgroupSession struct {
	path    string
	sudoPid int
	cgName  string // basename of path, used in /proc/PID/cgroup checks

	mu     sync.Mutex
	frozen bool

	escapedMu sync.Mutex
	escaped   map[int]struct{} // non-cgroup PIDs frozen via SIGSTOP

	stopTrack chan struct{}
	trackDone chan struct{}
}

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
	}
	log.Printf("cgroup: session %s created, sudo pid %d", filepath.Base(path), sudoPid)
	cg := &cgroupSession{
		path:      path,
		sudoPid:   sudoPid,
		cgName:    filepath.Base(path),
		escaped:   make(map[int]struct{}),
		stopTrack: make(chan struct{}),
		trackDone: make(chan struct{}),
	}
	go cg.trackDescendants()
	return cg
}

// procChildren returns the direct child PIDs of pid via the kernel's
// /proc/PID/task/PID/children interface (fast, no scanning of all /proc).
func procChildren(pid int) []int {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/task/%d/children", pid, pid))
	if err != nil {
		return nil
	}
	var out []int
	for _, s := range strings.Fields(string(data)) {
		if n, err := strconv.Atoi(s); err == nil {
			out = append(out, n)
		}
	}
	return out
}

// inOurCgroup reports whether pid's current cgroup is our session cgroup.
func (cg *cgroupSession) inOurCgroup(pid int) bool {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return false
	}
	return strings.Contains(string(data), cg.cgName)
}

// moveSudoOut moves sudo's PID to the parent cgroup so that cgroup.freeze
// only affects child processes (bash, gvim, …), not sudo itself.
// Called once, the first time a child process is detected in our cgroup.
func (cg *cgroupSession) moveSudoOut() {
	parentProcs := filepath.Join(filepath.Dir(cg.path), "cgroup.procs")
	if err := os.WriteFile(parentProcs, []byte(strconv.Itoa(cg.sudoPid)+"\n"), 0644); err != nil {
		log.Printf("cgroup %s: move sudo out: %v", cg.cgName, err)
		return
	}
	log.Printf("cgroup %s: sudo pid %d moved to parent cgroup (child detected)", cg.cgName, cg.sudoPid)
}

// trackDescendants runs as a goroutine for the lifetime of the session.
// Every 10 ms it:
//  1. Discovers new child PIDs via /proc/PID/task/PID/children.
//  2. Removes dead PIDs from the tracking set.
//  3. Moves sudo to the parent cgroup once a child appears.
//  4. Re-checks every tracked (non-sudo) PID's cgroup membership so that
//     late GNOME/systemd migrations are caught and tracked via SIGSTOP.
func (cg *cgroupSession) trackDescendants() {
	defer close(cg.trackDone)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	seen := map[int]struct{}{cg.sudoPid: {}}
	sudoMoved := false

	for {
		select {
		case <-cg.stopTrack:
			return
		case <-ticker.C:
			// ── 1. Discover new children ─────────────────────────────────
			var newPIDs []int
			for pid := range seen {
				for _, child := range procChildren(pid) {
					if _, already := seen[child]; !already {
						seen[child] = struct{}{}
						newPIDs = append(newPIDs, child)
					}
				}
			}
			_ = newPIDs // discovered; they'll be handled in step 4 below

			// ── 2. Remove dead PIDs ───────────────────────────────────────
			for pid := range seen {
				if _, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); err != nil {
					delete(seen, pid)
				}
			}

			// ── 3. Move sudo out once we have any child process ───────────
			if !sudoMoved && len(seen) > 1 {
				cg.moveSudoOut()
				sudoMoved = true
			}

			// ── 4. Re-check cgroup membership for all tracked non-sudo PIDs
			cg.mu.Lock()
			isFrozen := cg.frozen
			cg.mu.Unlock()

			for pid := range seen {
				if pid == cg.sudoPid {
					continue
				}
				cg.escapedMu.Lock()
				_, alreadyEscaped := cg.escaped[pid]
				cg.escapedMu.Unlock()
				if alreadyEscaped {
					continue
				}
				if cg.inOurCgroup(pid) {
					continue // in our cgroup → handled by cgroup.freeze
				}
				// Not in our cgroup.  Verify it is still alive before
				// classifying as escaped: short-lived subprocesses (rpm, ls,
				// …) often exit between procChildren() and the cgroup check,
				// causing inOurCgroup to return false on a non-existent PID.
				if _, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); err != nil {
					delete(seen, pid) // exited normally, forget it
					continue
				}
				// Still alive but not in our cgroup: genuinely escaped.
				cg.escapedMu.Lock()
				if _, already := cg.escaped[pid]; !already {
					cg.escaped[pid] = struct{}{}
					log.Printf("cgroup %s: pid %d escaped to foreign cgroup, tracking via SIGSTOP",
						cg.cgName, pid)
					if isFrozen {
						signalGroup(pid, syscall.SIGSTOP)
					}
				}
				cg.escapedMu.Unlock()
			}
		}
	}
}

// stopTracking stops the tracking goroutine and waits for it to exit.
// Safe to call multiple times and on a nil receiver.
func (cg *cgroupSession) stopTracking() {
	if cg == nil {
		return
	}
	select {
	case <-cg.stopTrack:
	default:
		close(cg.stopTrack)
	}
	<-cg.trackDone
}

// hasPids reports whether any processes remain in the session cgroup.
func (cg *cgroupSession) hasPids() bool {
	if cg == nil {
		return false
	}
	data, err := os.ReadFile(filepath.Join(cg.path, "cgroup.procs"))
	if err != nil {
		log.Printf("cgroup %s: hasPids read error: %v", cg.cgName, err)
		return false
	}
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		log.Printf("cgroup %s: no processes remain", cg.cgName)
		return false
	}
	log.Printf("cgroup %s: processes remain: %s", cg.cgName,
		strings.ReplaceAll(trimmed, "\n", ","))
	return true
}

// hasEscapedRunning reports whether any escaped PIDs are still running.
// Removes dead PIDs from the escaped set as a side-effect.
func (cg *cgroupSession) hasEscapedRunning() bool {
	if cg == nil {
		return false
	}
	cg.escapedMu.Lock()
	defer cg.escapedMu.Unlock()
	running := false
	for pid := range cg.escaped {
		if _, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); err == nil {
			running = true
		} else {
			delete(cg.escaped, pid)
		}
	}
	return running
}

// freeze suspends all processes in the session cgroup and SIGSTOPs escaped PIDs.
func (cg *cgroupSession) freeze() {
	if cg == nil {
		return
	}
	cg.mu.Lock()
	if !cg.frozen {
		if err := os.WriteFile(
			filepath.Join(cg.path, "cgroup.freeze"), []byte("1\n"), 0644,
		); err != nil {
			log.Printf("cgroup freeze: %v", err)
		} else {
			cg.frozen = true
			log.Printf("cgroup %s: frozen", cg.cgName)
		}
	}
	cg.mu.Unlock()
	cg.escapedMu.Lock()
	for pid := range cg.escaped {
		signalGroup(pid, syscall.SIGSTOP)
	}
	cg.escapedMu.Unlock()
}

// unfreeze resumes all processes in the session cgroup and SIGCONTs escaped PIDs.
func (cg *cgroupSession) unfreeze() {
	if cg == nil {
		return
	}
	cg.mu.Lock()
	if cg.frozen {
		if err := os.WriteFile(
			filepath.Join(cg.path, "cgroup.freeze"), []byte("0\n"), 0644,
		); err != nil {
			log.Printf("cgroup unfreeze: %v", err)
		} else {
			cg.frozen = false
			log.Printf("cgroup %s: unfrozen", cg.cgName)
		}
	}
	cg.mu.Unlock()
	cg.escapedMu.Lock()
	for pid := range cg.escaped {
		signalGroup(pid, syscall.SIGCONT)
	}
	cg.escapedMu.Unlock()
}

// remove unfreezes the cgroup, resumes escaped PIDs, migrates remaining
// processes to the parent cgroup, and removes the directory.
func (cg *cgroupSession) remove() {
	if cg == nil {
		return
	}
	_ = os.WriteFile(filepath.Join(cg.path, "cgroup.freeze"), []byte("0\n"), 0644)
	cg.escapedMu.Lock()
	for pid := range cg.escaped {
		signalGroup(pid, syscall.SIGCONT)
	}
	cg.escapedMu.Unlock()
	parentProcs := filepath.Join(filepath.Dir(cg.path), "cgroup.procs")
	if data, err := os.ReadFile(filepath.Join(cg.path, "cgroup.procs")); err == nil {
		for _, pid := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			if pid != "" {
				_ = os.WriteFile(parentProcs, []byte(pid+"\n"), 0644)
			}
		}
	}
	if err := os.Remove(cg.path); err != nil {
		log.Printf("cgroup remove %s: %v", cg.cgName, err)
	} else {
		log.Printf("cgroup %s: removed", cg.cgName)
	}
}
