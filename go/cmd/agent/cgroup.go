// cgroup.go — per-session cgroup management for sudo-logger-agent.
// Identical logic to sudo-shipper/cgroup.go; moved here as part of the merge.
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
	"syscall"
	"time"
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
	path    string
	sudoPid int
	cgName  string

	mu     sync.Mutex
	frozen bool

	escapedMu sync.Mutex
	escaped   map[int]bool

	stopTrack chan struct{}
	trackDone chan struct{}
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
		log.Printf("cgroup: move sudo pid %d: %v", sudoPid, err)
	}
	debugLog("cgroup: session %s created, sudo pid %d", filepath.Base(path), sudoPid)
	cg := &cgroupSession{
		path:      path,
		sudoPid:   sudoPid,
		cgName:    filepath.Base(path),
		escaped:   make(map[int]bool),
		stopTrack: make(chan struct{}),
		trackDone: make(chan struct{}),
	}
	go cg.trackDescendants()
	return cg
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
	ticker := time.NewTicker(50 * time.Millisecond)
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
				cg.moveSudoOut()
				sudoMoved = true
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
				if hasControllingTTY(pid) && isShell(pid) {
					if err := os.WriteFile(
						filepath.Join(cg.path, "cgroup.procs"),
						[]byte(strconv.Itoa(pid)+"\n"),
						0644,
					); err == nil {
						debugLog("cgroup %s: pid %d escaped (shell), reclaimed", cg.cgName, pid)
					} else {
						cg.escapedMu.Lock()
						if _, already := cg.escaped[pid]; !already {
							cg.escaped[pid] = false
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
				shouldSIGSTOP := pgidErr == nil && pgid == pid
				cg.escapedMu.Lock()
				if _, already := cg.escaped[pid]; !already {
					cg.escaped[pid] = shouldSIGSTOP
					debugLog("cgroup %s: pid %d escaped, tracked (sigstop=%v)", cg.cgName, pid, shouldSIGSTOP)
					cg.mu.Lock()
					isFrozen := cg.frozen
					cg.mu.Unlock()
					if isFrozen && shouldSIGSTOP {
						syscall.Kill(pid, syscall.SIGSTOP)
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

func (cg *cgroupSession) hasPids() bool {
	if cg == nil {
		return false
	}
	data, err := os.ReadFile(filepath.Join(cg.path, "cgroup.procs"))
	if err != nil {
		log.Printf("cgroup %s: hasPids read error: %v", cg.cgName, err)
		return false
	}
	return strings.TrimSpace(string(data)) != ""
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
			debugLog("cgroup %s: frozen", cg.cgName)
		}
	}
	cg.mu.Unlock()
	cg.escapedMu.Lock()
	for pid, shouldStop := range cg.escaped {
		if shouldStop {
			syscall.Kill(pid, syscall.SIGSTOP)
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
	for pid, shouldStop := range cg.escaped {
		if shouldStop {
			syscall.Kill(pid, syscall.SIGCONT)
		}
	}
	cg.escapedMu.Unlock()
}

func (cg *cgroupSession) remove() {
	if cg == nil {
		return
	}
	_ = os.WriteFile(filepath.Join(cg.path, "cgroup.freeze"), []byte("0\n"), 0644)
	cg.escapedMu.Lock()
	for pid, shouldStop := range cg.escaped {
		if shouldStop {
			syscall.Kill(pid, syscall.SIGCONT)
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
	if err := os.Remove(cg.path); err != nil {
		log.Printf("cgroup remove %s: %v", cg.cgName, err)
	} else {
		debugLog("cgroup %s: removed", cg.cgName)
	}
}
