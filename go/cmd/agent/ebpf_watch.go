package main

import (
	"bytes"
	"context"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"sudo-logger/internal/iolog"
)

func (s *ebpfSubsystem) watch(ctx context.Context) {
	userSlice := filepath.Join(s.cgroupRoot, "user.slice")

	ifd, err := syscall.InotifyInit1(syscall.IN_CLOEXEC)
	if err != nil {
		log.Printf("ebpf: inotify_init: %v", err)
		return
	}
	var closeIfd sync.Once
	closeInotify := func() { closeIfd.Do(func() { syscall.Close(ifd) }) }
	defer closeInotify()

	wdToDir := map[int32]string{}
	var wdMu sync.Mutex

	addWatch := func(path string) {
		wd, err := syscall.InotifyAddWatch(ifd, path, syscall.IN_CREATE|syscall.IN_DELETE|syscall.IN_ONLYDIR)
		if err != nil {
			return
		}
		wdMu.Lock()
		wdToDir[int32(wd)] = path
		wdMu.Unlock()
	}

	addWatch(userSlice)
	entries, _ := os.ReadDir(userSlice)
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), "user-") {
			userDir := filepath.Join(userSlice, e.Name())
			addWatch(userDir)
			s.scanExistingSessions(userDir)
		}
	}

	// Cancel inotify read when ctx is done.
	go func() {
		<-ctx.Done()
		closeInotify()
	}()

	buf := make([]byte, 4096)
	for {
		n, err := syscall.Read(ifd, buf)
		if err != nil || n == 0 {
			return
		}
		offset := 0
		for offset < n {
			if offset+syscall.SizeofInotifyEvent > n {
				break
			}
			ev := (*syscall.InotifyEvent)(unsafe.Pointer(&buf[offset]))
			nameLen := int(ev.Len)
			nameBytes := buf[offset+syscall.SizeofInotifyEvent : offset+syscall.SizeofInotifyEvent+nameLen]
			name := string(bytes.TrimRight(nameBytes, "\x00"))
			offset += syscall.SizeofInotifyEvent + nameLen

			wdMu.Lock()
			dir := wdToDir[ev.Wd]
			wdMu.Unlock()
			if dir == "" {
				continue
			}

			fullPath := filepath.Join(dir, name)

			if dir == userSlice && ev.Mask&syscall.IN_CREATE != 0 &&
				strings.HasPrefix(name, "user-") {
				addWatch(fullPath)
				continue
			}

			if strings.HasSuffix(name, ".scope") {
				if ev.Mask&syscall.IN_CREATE != 0 {
					if strings.HasPrefix(name, "session-") {
						time.AfterFunc(50*time.Millisecond, func() {
							s.sessionStarted(fullPath, name)
						})
					} else {
						// Non-session scope — could be a pkexec transient scope.
						time.AfterFunc(50*time.Millisecond, func() {
							s.resolvePkexecScope(fullPath)
						})
					}
				} else if ev.Mask&syscall.IN_DELETE != 0 {
					s.sessionEnded(fullPath)
				}
			}
		}
	}
}

func (s *ebpfSubsystem) scanExistingSessions(userDir string) {
	entries, err := os.ReadDir(userDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), "session-") &&
			strings.HasSuffix(e.Name(), ".scope") {
			s.sessionStarted(filepath.Join(userDir, e.Name()), e.Name())
		}
	}
}

func (s *ebpfSubsystem) sessionStarted(scopePath, scopeName string) {
	num := strings.TrimPrefix(strings.TrimSuffix(scopeName, ".scope"), "session-")

	// Query loginctl before statting the scope so that polkit/pkexec PAM
	// sessions with short-lived scopes (< 50 ms) can still be routed to a
	// pending pkexec waiter even after the scope directory has vanished.
	meta, lerr := loginctlSession(num)
	if lerr == nil && meta.stype == "" {
		// Empty session type = polkit/pkexec PAM session for root.
		// Route to pkexec waiter even if the scope has already been removed.
		debugLog("ebpf: sessionStarted: routing session %s (type=%q) to pkexec waiter", num, meta.stype)
		s.resolvePkexecScope(scopePath)
		return
	}

	cgroupID, err := cgroupInode(scopePath)
	if err != nil {
		// Scope removed before the 50 ms delay elapsed — normal for short-lived scopes.
		debugLog("ebpf: sessionStarted: stat %s: %v", scopePath, err)
		return
	}

	if lerr != nil {
		debugLog("ebpf: sessionStarted: loginctl session %s: %v", num, lerr)
		return
	}
	// Only record interactive terminal sessions.  Seat, greeter, x11, wayland
	// and other non-TTY session types are skipped silently.
	if meta.stype != "tty" && meta.stype != "unspecified" {
		debugLog("ebpf: sessionStarted: skipping session %s (type=%q)", num, meta.stype)
		return
	}

	sess := &ebpfSession{
		id:       generateEBPFSessionID(s.hostname, meta.user, num),
		user:     meta.user,
		host:     s.hostname,
		remote:   meta.remote,
		command:  meta.shell,
		cgroupID: cgroupID,
		redactor: iolog.MustNewRedactor(getEffectiveMaskPatterns()),
	}

	if err := sess.connect(s.cfg.Server, s.tlsCfg, verifyKey); err != nil {
		log.Printf("ebpf: sessionStarted [%s]: connect: %v", sess.id, err)
		return
	}

	var key [64]byte
	copy(key[:], sess.id)
	if err := s.objs.TrackedCgroups.Put(cgroupID, key); err != nil {
		log.Printf("ebpf: sessionStarted [%s]: bpf map put: %v", sess.id, err)
		sess.close(0)
		return
	}

	s.mu.Lock()
	s.sessions[cgroupID] = sess
	s.scopeToCgroup[scopePath] = cgroupID
	s.mu.Unlock()

	log.Printf("ebpf: session started: %s user=%s remote=%s", sess.id, sess.user, sess.remote)
}

func (s *ebpfSubsystem) sessionEnded(scopePath string) {
	s.mu.Lock()
	// Try reverse map first — the scope directory may already be deleted when
	// inotify fires IN_DELETE, making cgroupInode fail with ENOENT.
	cgroupID, mapped := s.scopeToCgroup[scopePath]
	if mapped {
		delete(s.scopeToCgroup, scopePath)
	} else {
		// Fallback: scope still exists (called very quickly after deletion).
		var err error
		cgroupID, err = cgroupInode(scopePath)
		if err != nil {
			s.mu.Unlock()
			return
		}
	}
	sess, ok := s.sessions[cgroupID]
	if ok {
		delete(s.sessions, cgroupID)
	}
	s.mu.Unlock()
	if !ok {
		return
	}
	_ = s.objs.TrackedCgroups.Delete(cgroupID)
	sess.close(0)
	log.Printf("ebpf: session ended: %s", sess.id)
}

// trackSudoPID inserts sudoPid into the BPF tracked_sudo_pids map.
// The execve hook checks parent and grandparent PIDs against this map to
// suppress the child execve that sudo fires when running the target command.
// Must be called before SESSION_READY is sent so the PID is in the map by
// the time sudo forks and the child calls execve.
