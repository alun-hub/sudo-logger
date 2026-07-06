package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"sudo-logger/internal/iolog"
)

func (s *ebpfSubsystem) drainRetryQueue() {
	s.retryMu.Lock()
	if len(s.retryQ) == 0 {
		s.retryMu.Unlock()
		return
	}
	queue := s.retryQ
	s.retryQ = nil
	s.retryMu.Unlock()

	cutoff := time.Now().Add(-maxPendingAge)
	var remaining []*ebpfSession

	for i, sess := range queue {
		if sess.ts.Before(cutoff) {
			log.Printf("ebpf: dropping expired pkexec event: id=%s age=%v",
				sess.id, time.Since(sess.ts).Round(time.Second))
			continue
		}
		if err := sess.connect(s.cfg.Server, s.tlsCfg, verifyKey); err != nil {
			log.Printf("ebpf: pkexec retry failed (%d events remain queued): %v", len(queue)-i, err)
			remaining = append(remaining, queue[i:]...)
			break
		}
		sess.close(0)
	}

	if len(remaining) > 0 {
		s.retryMu.Lock()
		s.retryQ = append(remaining, s.retryQ...)
		if len(s.retryQ) > maxPendingQ {
			dropped := len(s.retryQ) - maxPendingQ
			log.Printf("ebpf: pkexec retry queue overflow, dropping %d oldest events", dropped)
			s.retryQ = s.retryQ[dropped:]
		}
		s.retryMu.Unlock()
	}
}

// ── pkexec session handling ───────────────────────────────────────────────────

// handlePkexecExec is called when the eBPF execve hook sees a pkexec invocation.
// Unlike sudo, pkexec uses polkit and never triggers the sudo plugin, so there
// is no SESSION_START from the plugin side.  We create a separate session record
// with source="ebpf-pkexec".
//
// We wait up to 2 seconds for a new cgroup scope to appear (created by
// systemd/polkit for the target command).  If one appears, we track its I/O.
// If not, we emit an instant event (has_io=false) — typical for background
// services like packagekitd.

func (s *ebpfSubsystem) handlePkexecExec(ev execEvent, invokingUID uint32) {
	username, err := lookupUsername(invokingUID)
	if err != nil {
		username = fmt.Sprintf("uid%d", invokingUID)
	}
	// Extract target command from the exec path captured at BPF tracepoint time.
	// This avoids the race where the process dies before Go reads /proc/<pid>/cmdline.
	target := strings.TrimRight(string(ev.Target[:]), "\x00")
	pkexecCmd := filepath.Base(target)
	if pkexecCmd == "" || pkexecCmd == "." {
		pkexecCmd = "pkexec"
	}

	// Read pkexec's current cgroup path NOW — polkit may have already moved it
	// into a new session scope (e.g. user-0.slice/session-N.scope) before this
	// goroutine runs.
	currentCgroupPath := readProcCgroupPath(ev.Pid, s.cgroupRoot)
	currentCgroupID, _ := cgroupInode(currentCgroupPath)

	// Look up the parent eBPF session from the calling process's cgroup.
	s.mu.Lock()
	parentSess := s.sessions[ev.CgroupID]
	s.mu.Unlock()
	parentSessID := ""
	if parentSess != nil {
		parentSessID = parentSess.id
	}

	sessID := generatePkexecSessionID(s.hostname, username)
	log.Printf("ebpf: pkexec by user=%s cmd=%s parent=%s cgroup=%d", username, pkexecCmd, parentSessID, currentCgroupID)

	// Fast path: pkexec has already moved to a new cgroup (polkit-assigned
	// session scope).  Register it immediately — don't wait the full 2 s,
	// since the command may finish before the timer fires.
	var scopePath string
	usingInvokingCgroup := false
	if currentCgroupID != 0 && currentCgroupID != ev.CgroupID {
		s.mu.Lock()
		_, alreadyTracked := s.sessions[currentCgroupID]
		s.mu.Unlock()
		if !alreadyTracked {
			scopePath = currentCgroupPath
			usingInvokingCgroup = true
			log.Printf("ebpf: pkexec fast-path: using cgroup %s", filepath.Base(currentCgroupPath))
		}
	}

	if scopePath == "" {
		// Register a waiter so watch() can notify us when a scope appears.
		waiter := &pkexecWaiter{
			invokingUID: invokingUID,
			ts:          time.Now(),
			ch:          make(chan string, 1),
		}
		s.pkexecMu.Lock()
		s.pendingPkexec = append(s.pendingPkexec, waiter)
		s.pkexecMu.Unlock()

		// Block until scope appears or 2s timeout.
		select {
		case scopePath = <-waiter.ch:
		case <-time.After(2 * time.Second):
		}

		s.pkexecMu.Lock()
		for i, w := range s.pendingPkexec {
			if w == waiter {
				s.pendingPkexec = append(s.pendingPkexec[:i], s.pendingPkexec[i+1:]...)
				break
			}
		}
		s.pkexecMu.Unlock()

		// Fallback: polkit ran the command in the caller's cgroup (no new scope
		// appeared at all).  Register the original invoking cgroup if untracked.
		if scopePath == "" && currentCgroupPath != "" && currentCgroupID == ev.CgroupID {
			s.mu.Lock()
			_, alreadyTracked := s.sessions[ev.CgroupID]
			s.mu.Unlock()
			if !alreadyTracked {
				scopePath = currentCgroupPath
				usingInvokingCgroup = true
			}
		}
	}

	// Stat the scope before creating the session so hasIO reflects actual
	// availability.  Short-lived polkit scopes (background jobs, firewall helpers)
	// may vanish before we reach this point; in that case we emit a no-io event
	// rather than a session with hasIO=true but empty content.
	var cgroupID uint64
	if scopePath != "" {
		id, serr := cgroupInode(scopePath)
		if serr != nil {
			debugLog("ebpf: pkexec scope %s gone: %v — recording as event", filepath.Base(scopePath), serr)
			scopePath = ""
		} else {
			cgroupID = id
		}
	}

	hasIO := scopePath != ""
	sess := &ebpfSession{
		id:       sessID,
		user:     username,
		host:     s.hostname,
		command:  pkexecCmd,
		source:   "ebpf-pkexec",
		parentID: parentSessID,
		hasIO:    hasIO,
		ts:       time.Now(),
		redactor: iolog.MustNewRedactor(getEffectiveMaskPatterns()),
	}

	if err := sess.connect(s.cfg.Server, s.tlsCfg, verifyKey); err != nil {
		if !hasIO {
			// No I/O to lose — queue for retry when server comes back.
			s.retryMu.Lock()
			if len(s.retryQ) < maxPendingQ {
				s.retryQ = append(s.retryQ, sess)
				log.Printf("ebpf: pkexec [%s]: queued for retry (%d in queue): %v", sessID, len(s.retryQ), err)
			} else {
				log.Printf("ebpf: pkexec [%s]: dropped (retry queue full): %v", sessID, err)
			}
			s.retryMu.Unlock()
		} else {
			// Known limitation: interactive pkexec sessions (hasIO=true) cannot
			// be buffered when the log server is unreachable.  Buffering would
			// require writing I/O chunks to a local file and replaying them on
			// reconnect — the cgroup scope is gone by the time the server comes
			// back, so we cannot re-register it in the BPF map after the fact.
			log.Printf("ebpf: pkexec [%s]: connect: %v (interactive session lost — server unreachable)", sessID, err)
		}
		return
	}

	if !hasIO {
		// Background pkexec (e.g. packagekitd, firewall helpers) — no I/O to capture.
		sess.close(0)
		log.Printf("ebpf: pkexec event recorded: %s user=%s (no scope)", sessID, username)
		return
	}

	sess.cgroupID = cgroupID

	var key [64]byte
	copy(key[:], sessID)
	if err := s.objs.TrackedCgroups.Put(cgroupID, key); err != nil {
		log.Printf("ebpf: pkexec trackCgroup %s: %v", filepath.Base(scopePath), err)
		sess.close(0)
		return
	}

	s.mu.Lock()
	s.sessions[cgroupID] = sess
	if !usingInvokingCgroup {
		// Register the reverse mapping so sessionEnded() can find this session
		// by scopePath even after the scope directory has been deleted.
		s.scopeToCgroup[scopePath] = cgroupID
	}
	s.mu.Unlock()

	if usingInvokingCgroup {
		// Session ends when pkexec (ev.Pid) exits — no inotify signal for this cgroup.
		log.Printf("ebpf: pkexec session started: %s user=%s cgroup=%s (invoking cgroup)",
			sessID, username, filepath.Base(scopePath))
		go func() {
			waitForPID(s.ctx, ev.Pid)
			s.mu.Lock()
			if s.sessions[cgroupID] == sess {
				delete(s.sessions, cgroupID)
			}
			s.mu.Unlock()
			_ = s.objs.TrackedCgroups.Delete(cgroupID)
			sess.close(0)
			log.Printf("ebpf: pkexec session ended: %s user=%s", sessID, username)
		}()
	} else {
		log.Printf("ebpf: pkexec session started: %s user=%s scope=%s", sessID, username, filepath.Base(scopePath))
		// Session ends when the scope disappears via inotify → sessionEnded().
	}
}

// resolvePkexecScope notifies the oldest pending pkexec waiter that a new
// cgroup scope appeared.  Called by watch() when a non-session *.scope is
// created within the user cgroup hierarchy.
func (s *ebpfSubsystem) resolvePkexecScope(scopePath string) {
	s.pkexecMu.Lock()
	defer s.pkexecMu.Unlock()

	// Prune stale entries and notify the oldest fresh one.
	var keep []*pkexecWaiter
	notified := false
	for _, w := range s.pendingPkexec {
		if time.Since(w.ts) > 5*time.Second {
			continue // drop stale waiter
		}
		if !notified {
			select {
			case w.ch <- scopePath:
			default:
			}
			notified = true
			continue
		}
		keep = append(keep, w)
	}
	s.pendingPkexec = keep
}

func generatePkexecSessionID(hostname, username string) string {
	ts := strconv.FormatInt(time.Now().UnixNano(), 10)
	safe := func(s string) string {
		var b strings.Builder
		for _, c := range s {
			if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
				(c >= '0' && c <= '9') || c == '-' || c == '_' {
				b.WriteRune(c)
			} else {
				b.WriteRune('_')
			}
		}
		return b.String()
	}
	id := fmt.Sprintf("pkexec.%s.%s.%s", safe(hostname), safe(username), ts)
	if len(id) > 200 {
		id = id[:200]
	}
	return id
}

// ── Cgroup / session lifecycle ────────────────────────────────────────────────


type sessionMeta struct {
	user   string
	remote string
	shell  string
	stype  string
}

func loginctlSession(num string) (sessionMeta, error) {
	props := []string{"Name", "RemoteHost", "Type"}
	args := []string{"show-session", "--value", "--property=" + strings.Join(props, ","), num}
	out, err := exec.Command("loginctl", args...).Output()
	if err != nil {
		return sessionMeta{}, fmt.Errorf("loginctl show-session %s: %w", num, err)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	// Pad with empty strings — system/seat sessions may return fewer properties.
	for len(lines) < len(props) {
		lines = append(lines, "")
	}
	meta := sessionMeta{
		user:   lines[0],
		remote: lines[1],
		stype:  lines[2],
	}
	if shell, err := userShell(meta.user); err == nil {
		meta.shell = shell
	} else {
		meta.shell = "/bin/bash"
	}
	return meta, nil
}

func userShell(username string) (string, error) {
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return "", err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), ":")
		if len(fields) >= 7 && fields[0] == username {
			return fields[6], nil
		}
	}
	return "", fmt.Errorf("user %q not found", username)
}
