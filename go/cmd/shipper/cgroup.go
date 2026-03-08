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
//     If systemd moves them to a different cgroup they are NOT SIGSTOP'd:
//     they have a controlling TTY and the plugin's log_ttyin already blocks
//     all keyboard input, so a soft freeze is sufficient.  SIGSTOP would
//     trigger job control and move the session to the background.
//   • GUI programs (gvim, okular, …) — typically moved by GNOME/systemd to
//     an app-*.scope cgroup before our tracker sees them.  They have no
//     controlling TTY, so they are hard-frozen via SIGSTOP/SIGCONT.
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
	cgName  string // basename of path, used in /proc/PID/cgroup checks

	mu     sync.Mutex
	frozen bool

	escapedMu sync.Mutex
	escaped   map[int]bool // escaped PIDs; true = freeze via SIGSTOP, false = tracked only (no SIGSTOP)

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

// isShell reports whether pid is an interactive shell process.
// Used to distinguish shells (reclaim into session cgroup, never SIGSTOP)
// from GUI apps that happen to inherit a controlling terminal from sudo.
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

// hasControllingTTY reports whether pid has a controlling terminal.
// Used to protect interactive shells (bash, zsh, …) from SIGSTOP: stopping
// a shell that holds the terminal foreground triggers job control and moves
// the session to the background.
func hasControllingTTY(pid int) bool {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false
	}
	// /proc/PID/stat: "pid (comm) state ppid pgrp session tty_nr ..."
	// comm may contain spaces; find the last ')' to skip it safely.
	s := string(data)
	idx := strings.LastIndex(s, ")")
	if idx < 0 {
		return false
	}
	fields := strings.Fields(s[idx+1:])
	// After comm: [0]=state [1]=ppid [2]=pgrp [3]=session [4]=tty_nr
	if len(fields) < 5 {
		return false
	}
	ttyNr, err := strconv.Atoi(fields[4])
	return err == nil && ttyNr != 0
}

// displaySocketInodes returns the kernel inode numbers of all X11 and Wayland
// display server sockets currently listed in /proc/net/unix.  Called once per
// tracker tick so the result can be reused for every PID check in that tick.
func displaySocketInodes() map[uint64]bool {
	result := make(map[uint64]bool)
	data, err := os.ReadFile("/proc/net/unix")
	if err != nil {
		return result
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		// Format: Num RefCount Protocol Flags Type St Inode Path
		if len(fields) < 8 {
			continue
		}
		path := fields[7]
		if strings.Contains(path, "/.X11-unix/") || strings.Contains(path, "/wayland-") {
			if inode, err := strconv.ParseUint(fields[6], 10, 64); err == nil {
				result[inode] = true
			}
		}
	}
	return result
}

// isGUIApp reports whether pid has an open connection to an X11 or Wayland
// display server.  Such processes must not be frozen via cgroup.freeze or
// SIGSTOP: they cannot respond to compositor pings while frozen, so the
// compositor (GNOME/mutter) eventually sends SIGTERM, killing the app on
// unfreeze.  Detection via display socket is more reliable than TTY presence
// because GUI apps may inherit a controlling terminal from their parent shell.
func isGUIApp(pid int, displayInodes map[uint64]bool) bool {
	if len(displayInodes) == 0 {
		return false
	}
	fds, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
	if err != nil {
		return false
	}
	for _, fd := range fds {
		target, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, fd.Name()))
		if err != nil || !strings.HasPrefix(target, "socket:[") {
			continue
		}
		inodeStr := strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")
		inode, err := strconv.ParseUint(inodeStr, 10, 64)
		if err != nil {
			continue
		}
		if displayInodes[inode] {
			return true
		}
	}
	return false
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
	debugLog("cgroup %s: sudo pid %d moved to parent cgroup (child detected)", cg.cgName, cg.sudoPid)
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
			// GUI apps are detected by their open connection to an X11 or
			// Wayland display socket (more reliable than checking TTY: GUI
			// apps inherit the parent shell's controlling terminal, so
			// hasControllingTTY returns true even for gvim, okular, etc.).
			// GUI apps found here are moved immediately to the parent cgroup
			// so they are never subject to cgroup.freeze.  Freezing a GUI
			// app prevents it from responding to compositor pings → GNOME
			// queues SIGTERM → app dies on unfreeze.
			parentProcs := filepath.Join(filepath.Dir(cg.path), "cgroup.procs")
			displayInodes := displaySocketInodes()
			for pid := range seen {
				for _, child := range procChildren(pid) {
					if _, already := seen[child]; !already {
						if isGUIApp(child, displayInodes) {
							// GUI app: push to parent cgroup, don't track.
							if err := os.WriteFile(parentProcs,
								[]byte(strconv.Itoa(child)+"\n"), 0644); err == nil {
								debugLog("cgroup %s: pid %d new GUI child (display conn), moved to parent cgroup",
									cg.cgName, child)
							} else {
								debugLog("cgroup %s: pid %d new GUI child (display conn), move to parent failed: %v",
									cg.cgName, child, err)
							}
							continue // do not add to seen
						}
						seen[child] = struct{}{}
					}
				}
			}

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
					// Process is in our cgroup.  If it has since opened a
					// display connection it is a GUI app that must not be
					// frozen — move it to the parent cgroup now.
					if isGUIApp(pid, displayInodes) {
						if err := os.WriteFile(parentProcs,
							[]byte(strconv.Itoa(pid)+"\n"), 0644); err == nil {
							debugLog("cgroup %s: pid %d detected as GUI (display conn), moved to parent cgroup",
								cg.cgName, pid)
							delete(seen, pid)
						}
					}
					continue // handled by cgroup.freeze (or just moved out)
				}
				// Not in our cgroup.  Verify it is still alive before
				// classifying as escaped: short-lived subprocesses (rpm, ls,
				// …) often exit between procChildren() and the cgroup check,
				// causing inOurCgroup to return false on a non-existent PID.
				if _, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); err != nil {
					delete(seen, pid) // exited normally, forget it
					continue
				}
				// Still alive but not in our cgroup: escaped (GNOME/systemd
				// moved it to a different cgroup).
				//
				// TTY process (interactive shell, e.g. bash): reclaim into the
				// session cgroup so cgroup.freeze covers it.  SIGSTOP is not an
				// option (triggers job control and moves the session to the
				// background).  If reclaim fails, add to escaped with
				// shouldSIGSTOP=false so we stop re-processing it every tick
				// without sending any signals.
				//
				// Non-TTY process (GUI app, e.g. gvim after setsid): freeze via
				// SIGSTOP.  The compositor shows a "not responding" dialog but
				// will NOT auto-kill; on unfreeze we send SIGCONT and the app
				// resumes.  Do NOT reclaim: cgroup.freeze prevents X11/Wayland
				// ping responses → compositor queues SIGTERM → app dies.
				if hasControllingTTY(pid) && isShell(pid) {
					// Interactive shell (bash, zsh, …): reclaim into the
					// session cgroup so cgroup.freeze covers it.  SIGSTOP
					// is not an option (triggers job control).
					if err := os.WriteFile(
						filepath.Join(cg.path, "cgroup.procs"),
						[]byte(strconv.Itoa(pid)+"\n"),
						0644,
					); err == nil {
						debugLog("cgroup %s: pid %d escaped (shell), reclaimed into session cgroup",
							cg.cgName, pid)
					} else {
						// Reclaim failed — track in escaped (no SIGSTOP) to
						// stop the re-processing spam loop.
						cg.escapedMu.Lock()
						if _, already := cg.escaped[pid]; !already {
							cg.escaped[pid] = false // track, no SIGSTOP
							debugLog("cgroup %s: pid %d escaped (shell), reclaim failed: %v — not freezing",
								cg.cgName, pid, err)
						}
						cg.escapedMu.Unlock()
					}
					continue
				}
				// Non-shell process (GUI app such as gvim, helper, etc.).
				// If it has its own process group (pgid == pid, set by setsid)
				// it is safe to SIGSTOP just this PID without touching bash.
				// If it shares a process group with bash, skip: signalling the
				// group would trigger job control.
				pgid, pgidErr := syscall.Getpgid(pid)
				if pgidErr == nil && pgid == pid {
					// Own process group — safe to signal only this PID.
					cg.escapedMu.Lock()
					if _, already := cg.escaped[pid]; !already {
						cg.escaped[pid] = true
						debugLog("cgroup %s: pid %d escaped (own pgid), frozen via SIGSTOP",
							cg.cgName, pid)
						cg.mu.Lock()
						isFrozen := cg.frozen
						cg.mu.Unlock()
						if isFrozen {
							syscall.Kill(pid, syscall.SIGSTOP)
						}
					}
					cg.escapedMu.Unlock()
				} else {
					// Shares process group with bash — skip to avoid job control.
					delete(seen, pid)
					debugLog("cgroup %s: pid %d escaped (shared pgid), dropped from tracking",
						cg.cgName, pid)
				}
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
		debugLog("cgroup %s: no processes remain", cg.cgName)
		return false
	}
	debugLog("cgroup %s: processes remain: %s", cg.cgName,
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

// remove unfreezes the cgroup, resumes escaped PIDs, migrates remaining
// processes to the parent cgroup, and removes the directory.
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
