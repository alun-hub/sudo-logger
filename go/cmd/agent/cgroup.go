// cgroup.go — per-session cgroup management for sudo-logger-agent.
package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"sudo-logger/internal/protocol"
)

var validCgroupName = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,255}$`)

var cgroupBase string

func init() {
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
				debugLog("cgroup: delegated subtree at %s", base)
			}
			return
		}
	}
}

type cgroupSession struct {
	path      string
	sudoPid   int
	cgName    string
	cgroupID  uint64 // cgroup v2 ID (= inode of cgroup dir), used for sandbox scoping

	mu          sync.Mutex
	frozen      bool
	readyToFork bool // Set to true when plugin sends SESSION_READY

	// terminating is set once a watcher (TTL/freeze-timeout expiry) has
	// decided to end the session and called unfreeze() to let its signal
	// land. It permanently disarms freeze(): without it, a late markDead()
	// (server conn tearing down as part of the same shutdown) or lingerCgroup
	// (still seeing the not-yet-dead pid) can refreeze the cgroup after the
	// signal was sent but before the process acted on it, and nothing is left
	// running to ever thaw it again — the process hangs frozen forever.
	terminating atomic.Bool

	serverW *protocol.Writer // Used to send sandbox/divergence alerts

	// escaped maps a tracked escaped pid to its process-group id (0 = no
	// valid pgid was obtainable, so freeze()/unfreeze()/remove() must not
	// attempt to signal it). Keyed by pid so hasEscapedRunning can still
	// probe each one individually via /proc.
	escapedMu sync.Mutex
	escaped   map[int]int

	stopTrack  chan struct{}
	trackDone  chan struct{}
	removeOnce sync.Once
}

func newCgroupSession(sessionID string, sudoPid int) *cgroupSession {
	if cgroupBase == "" || sudoPid <= 0 {
		return nil
	}
	if !validCgroupName.MatchString(sessionID) {
		log.Printf("cgroup: invalid session ID %q — skipping cgroup creation", sessionID)
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
		debugLog("cgroup: move sudo pid %d: %v", sudoPid, err)
	}
	// Confirm sudo's actual cgroup after the write attempt.
	if data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", sudoPid)); err == nil {
		debugLog("cgroup: sudo %d cgroup after move: %s", sudoPid, strings.TrimSpace(string(data)))
	}
	debugLog("cgroup: session %s created, sudo pid %d", filepath.Base(path), sudoPid)
	cg := &cgroupSession{
		path:      path,
		sudoPid:   sudoPid,
		cgName:    filepath.Base(path),
		escaped:   make(map[int]int),
		stopTrack: make(chan struct{}),
		trackDone: make(chan struct{}),
	}

	// The cgroup v2 ID equals the inode number of the cgroup directory —
	// this is what bpf_get_current_cgroup_id() returns in BPF programs.
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err == nil {
		cg.cgroupID = st.Ino
		sandboxSys.registerCgroup(cg.cgroupID)
	} else {
		log.Printf("cgroup: stat %s for sandbox: %v", path, err)
	}

	go cg.trackDescendants()
	return cg
}

func (cg *cgroupSession) SetReady() {
	if cg == nil {
		return
	}
	cg.mu.Lock()
	cg.readyToFork = true
	cg.mu.Unlock()
	debugLog("cgroup %s: session ready (sudo may now fork)", cg.cgName)
}

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

func isShell(pid int) bool {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return false
	}
	switch strings.TrimSpace(string(data)) {
	case "bash", "sh", "zsh", "fish", "ksh", "tcsh", "dash", "csh":
		return true
	}
	return false
}

func hasControllingTTY(pid int) bool {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false
	}
	s := string(data)
	idx := strings.LastIndex(s, ")")
	if idx < 0 {
		return false
	}
	fields := strings.Fields(s[idx+1:])
	if len(fields) < 5 {
		return false
	}
	ttyNr, err := strconv.Atoi(fields[4])
	return err == nil && ttyNr != 0
}

func (cg *cgroupSession) inOurCgroup(pid int) bool {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return false
	}
	return strings.Contains(string(data), cg.cgName)
}

// cgroupInodeOf returns the inode of pid's cgroup v2 directory.
// This matches what bpf_get_current_cgroup_id() returns for the same process.
func cgroupInodeOf(pid int) uint64 {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		debugLog("sandbox: cgroupInodeOf(%d): read cgroup: %v", pid, err)
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "0::") {
			rel := strings.TrimSpace(strings.TrimPrefix(line, "0::"))
			path := "/sys/fs/cgroup" + rel
			var st syscall.Stat_t
			if err := syscall.Stat(path, &st); err != nil {
				debugLog("sandbox: cgroupInodeOf(%d): stat %q: %v", pid, path, err)
				return 0
			}
			return st.Ino
		}
	}
	debugLog("sandbox: cgroupInodeOf(%d): no '0::' line in %q", pid, strings.TrimSpace(string(data)))
	return 0
}

func (cg *cgroupSession) moveSudoOut() {
	parentProcs := filepath.Join(filepath.Dir(cg.path), "cgroup.procs")
	if err := os.WriteFile(parentProcs, []byte(strconv.Itoa(cg.sudoPid)+"\n"), 0644); err != nil {
		log.Printf("cgroup %s: move sudo out: %v", cg.cgName, err)
		return
	}
	debugLog("cgroup %s: sudo pid %d moved to parent cgroup (child detected)", cg.cgName, cg.sudoPid)
}

func (cg *cgroupSession) trackDescendants() {
	defer close(cg.trackDone)
	// 500 ms is a 10x reduction from the original 50 ms while still providing
	// sub-second response for moveSudoOut and escaped-cgroup detection.
	// Real-time fork notification via eBPF (sandbox.bpf.c sched_process_fork)
	// would eliminate polling entirely but requires a dedicated ring-buffer
	// channel back to Go — deferred as a follow-up.
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	seen := map[int]struct{}{cg.sudoPid: {}}
	sudoMoved := false

	for {
		select {
		case <-cg.stopTrack:
			return
		case <-ticker.C:
			for pid := range seen {
				for _, child := range procChildren(pid) {
					if _, already := seen[child]; !already {
						seen[child] = struct{}{}
					}
				}
			}
			for pid := range seen {
				if _, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); err != nil {
					delete(seen, pid)
				}
			}
			if !sudoMoved && len(seen) > 1 {
				cg.mu.Lock()
				ready := cg.readyToFork
				cg.mu.Unlock()
				if ready {
					children := make([]int, 0, len(seen)-1)
					for pid := range seen {
						if pid != cg.sudoPid {
							children = append(children, pid)
						}
					}
					debugLog("cgroup %s: moveSudoOut triggered by children %v", cg.cgName, children)
					cg.moveSudoOut()
					sudoMoved = true
				}
			}
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
					continue
				}
				if _, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); err != nil {
					delete(seen, pid)
					continue
				}
				if cgData, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid)); err == nil {
					debugLog("cgroup %s: pid %d escaped, actual cgroup: %s", cg.cgName, pid, strings.TrimSpace(string(cgData)))
				}
				if hasControllingTTY(pid) && isShell(pid) {
					if err := os.WriteFile(
						filepath.Join(cg.path, "cgroup.procs"),
						[]byte(strconv.Itoa(pid)+"\n"),
						0644,
					); err == nil {
						debugLog("cgroup %s: pid %d escaped (shell), reclaimed", cg.cgName, pid)
					} else {
						sandboxSys.registerAuxCgroup(cgroupInodeOf(pid), cg)
						cg.escapedMu.Lock()
						if _, already := cg.escaped[pid]; !already {
							cg.escaped[pid] = 0 // shell case: never signal-stopped, only tracked
						}
						cg.escapedMu.Unlock()
					}
					continue
				}
				pgid, pgidErr := syscall.Getpgid(pid)
				hasTTY := hasControllingTTY(pid)
				if hasTTY || (pgidErr == nil && pgid != pid) {
					if err := os.WriteFile(
						filepath.Join(cg.path, "cgroup.procs"),
						[]byte(strconv.Itoa(pid)+"\n"),
						0644,
					); err == nil {
						debugLog("cgroup %s: pid %d escaped, reclaimed (hasTTY=%v)", cg.cgName, pid, hasTTY)
						continue
					}
				}
				sandboxSys.registerAuxCgroup(cgroupInodeOf(pid), cg)
				// Track the whole process group, not just this pid: SIGSTOP
				// to a lone member of a group (e.g. one side of a pipeline)
				// can deadlock the other side instead of cleanly pausing
				// it. kill(-pgid, sig) is standard job-control semantics
				// (the same primitive a shell's Ctrl-Z uses) and is safe to
				// call redundantly if another tracked pid shares the same
				// pgid -- signaling an already-stopped group is a no-op.
				var trackPgid int
				if pgidErr == nil {
					trackPgid = pgid
				}
				cg.escapedMu.Lock()
				if _, already := cg.escaped[pid]; !already {
					cg.escaped[pid] = trackPgid
					debugLog("cgroup %s: pid %d escaped, tracked (pgid=%d)", cg.cgName, pid, trackPgid)
					cg.mu.Lock()
					isFrozen := cg.frozen
					cg.mu.Unlock()
					if isFrozen && trackPgid > 0 {
						syscall.Kill(-trackPgid, syscall.SIGSTOP)
					}
				}
				cg.escapedMu.Unlock()
			}
		}
	}
}

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

// backgroundComms are process names that must not gate session end.
// GUI apps (e.g. gvim) may start a private dbus-daemon that outlives the
// main application but has no relevance to the user's session activity.
var backgroundComms = map[string]bool{
	"dbus-daemon": true,
	"dbus-launch": true,
}

func (cg *cgroupSession) hasPids() bool {
	if cg == nil {
		return false
	}
	data, err := os.ReadFile(filepath.Join(cg.path, "cgroup.procs"))
	if err != nil {
		if os.IsNotExist(err) {
			return false
		}
		log.Printf("cgroup %s: hasPids read error: %v (retaining)", cg.cgName, err)
		return true
	}
	for _, pidStr := range strings.Fields(string(data)) {
		pid, err := strconv.Atoi(pidStr)
		if err != nil {
			continue
		}
		comm, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
		if err != nil {
			// Process may have just exited; treat as gone.
			continue
		}
		if !backgroundComms[strings.TrimSpace(string(comm))] {
			return true
		}
	}
	return false
}

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

// markTerminating permanently disarms freeze() for this cgroup — called by a
// watcher (TTL/freeze-timeout expiry) right before it unfreezes and signals
// the session, so a late markDead() or lingerCgroup tick can't refreeze it
// out from under the pending signal.
func (cg *cgroupSession) markTerminating() {
	if cg == nil {
		return
	}
	cg.terminating.Store(true)
}

func (cg *cgroupSession) freeze() {
	if cg == nil || cg.terminating.Load() {
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
			debugLog("cgroup %s: frozen", cg.cgName)
		}
	}
	cg.mu.Unlock()
	cg.escapedMu.Lock()
	for _, pgid := range cg.escaped {
		if pgid > 0 {
			syscall.Kill(-pgid, syscall.SIGSTOP)
		}
	}
	cg.escapedMu.Unlock()
}

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
			debugLog("cgroup %s: unfrozen", cg.cgName)
		}
	}
	cg.mu.Unlock()
	cg.escapedMu.Lock()
	for _, pgid := range cg.escaped {
		if pgid > 0 {
			syscall.Kill(-pgid, syscall.SIGCONT)
		}
	}
	cg.escapedMu.Unlock()
}

func (cg *cgroupSession) remove() {
	if cg == nil {
		return
	}
	cg.removeOnce.Do(func() {
		_ = os.WriteFile(filepath.Join(cg.path, "cgroup.freeze"), []byte("0\n"), 0644)
		cg.escapedMu.Lock()
		for _, pgid := range cg.escaped {
			if pgid > 0 {
				syscall.Kill(-pgid, syscall.SIGCONT)
			}
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
		sandboxSys.unregisterCgroup(cg.cgroupID)
		sandboxSys.unregisterAuxCgroups(cg)
		if err := os.Remove(cg.path); err != nil {
			log.Printf("cgroup remove %s: %v", cg.cgName, err)
		} else {
			debugLog("cgroup %s: removed", cg.cgName)
		}
	})
}
