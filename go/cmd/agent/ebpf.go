package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"sudo-logger/internal/protocol"
)

// ── Ring buffer event types ───────────────────────────────────────────────────

const (
	eventTypeIO   = uint8(1)
	eventTypeExec = uint8(2)
	eventTypeExit = uint8(3)
)

// ioEvent mirrors struct io_event in bpf/recorder.c.
// Layout: event_type(1) stream(1) pad(2) data_len(4) cgroup_id(8) timestamp_ns(8) data(4096)
type ioEvent struct {
	EventType   uint8
	Stream      uint8
	Pad         [2]uint8
	DataLen     uint32
	CgroupID    uint64
	TimestampNS uint64
	Data        [4096]byte
}

// execEvent mirrors struct exec_event in bpf/recorder.c.
// Layout: event_type(1) comm(15) pid(4) uid(4) cgroup_id(8) timestamp_ns(8)
type execEvent struct {
	EventType   uint8
	Comm        [15]byte
	Pid         uint32
	Uid         uint32
	CgroupID    uint64
	TimestampNS uint64
}

// exitEvent mirrors struct exit_event in bpf/recorder.c.
// Layout: event_type(1) pad(3) exit_code(4) cgroup_id(8) timestamp_ns(8)
type exitEvent struct {
	EventType   uint8
	Pad         [3]byte
	ExitCode    uint32
	CgroupID    uint64
	TimestampNS uint64
}

// ── eBPF subsystem ────────────────────────────────────────────────────────────

// pkexecWaiter is registered by handlePkexecExec so that the watch() goroutine
// can notify it when a new cgroup scope appears (pkexec's transient scope).
type pkexecWaiter struct {
	invokingUID uint32
	ts          time.Time
	ch          chan string // receives scope cgroup path, or "" on timeout
}

type ebpfSubsystem struct {
	cfg        agentConfig
	tlsCfg     *tls.Config
	hostname   string
	divergence *divergenceTracker
	cgroupRoot string

	objs    *RecorderObjects
	rd      *ringbuf.Reader
	links   []link.Link

	mu           sync.Mutex
	sessions     map[uint64]*ebpfSession
	droppedTotal atomic.Uint64

	pkexecMu      sync.Mutex
	pendingPkexec []*pkexecWaiter
}

func newEBPFSubsystem(cfg agentConfig, tlsCfg *tls.Config, hostname string, div *divergenceTracker) *ebpfSubsystem {
	return &ebpfSubsystem{
		cfg:        cfg,
		tlsCfg:     tlsCfg,
		hostname:   hostname,
		divergence: div,
		cgroupRoot: "/sys/fs/cgroup",
		sessions:   make(map[uint64]*ebpfSession),
	}
}

// start loads the BPF objects, attaches tracepoints, and begins the watch loop.
// Returns an error if eBPF is unavailable; caller falls back to plugin-only mode.
func (s *ebpfSubsystem) start(ctx context.Context) error {
	objs := &RecorderObjects{}
	if err := LoadRecorderObjects(objs, nil); err != nil {
		return fmt.Errorf("load eBPF objects: %w", err)
	}
	s.objs = objs

	// Attach all three tracepoints.
	tpWrite, err := link.Tracepoint("syscalls", "sys_enter_write", objs.RecordWrite, nil)
	if err != nil {
		objs.Close()
		return fmt.Errorf("attach sys_enter_write: %w", err)
	}
	tpExecve, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.TraceExecve, nil)
	if err != nil {
		tpWrite.Close()
		objs.Close()
		return fmt.Errorf("attach sys_enter_execve: %w", err)
	}
	tpExit, err := link.Tracepoint("sched", "sched_process_exit", objs.RecordExit, nil)
	if err != nil {
		tpExecve.Close()
		tpWrite.Close()
		objs.Close()
		return fmt.Errorf("attach sched_process_exit: %w", err)
	}
	s.links = []link.Link{tpWrite, tpExecve, tpExit}

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		for _, l := range s.links {
			l.Close()
		}
		objs.Close()
		return fmt.Errorf("ringbuf reader: %w", err)
	}
	s.rd = rd

	log.Printf("ebpf: tracepoints attached (sys_enter_write, sys_enter_execve, sched_process_exit)")

	// Goroutine: watch cgroup hierarchy for login sessions.
	go s.watch(ctx)

	// Goroutine: read events from the ring buffer.
	go s.readLoop(ctx)

	// Goroutine: log dropped events periodically.
	go s.logDropped(ctx)

	return nil
}

func (s *ebpfSubsystem) stop() {
	if s.rd != nil {
		s.rd.Close()
	}
	for _, l := range s.links {
		l.Close()
	}
	if s.objs != nil {
		s.objs.Close()
	}
	s.mu.Lock()
	sessions := make([]*ebpfSession, 0, len(s.sessions))
	for id, sess := range s.sessions {
		sessions = append(sessions, sess)
		_ = s.objs.TrackedCgroups.Delete(id)
	}
	s.sessions = make(map[uint64]*ebpfSession)
	s.mu.Unlock()
	for _, sess := range sessions {
		sess.close(0)
	}
}

func (s *ebpfSubsystem) readLoop(ctx context.Context) {
	for {
		rec, err := s.rd.Read()
		if err != nil {
			return
		}

		if len(rec.RawSample) == 0 {
			continue
		}
		eventType := rec.RawSample[0]

		switch eventType {
		case eventTypeIO:
			s.handleIO(rec.RawSample)
		case eventTypeExec:
			s.handleExecve(rec.RawSample)
		case eventTypeExit:
			// Exit events are informational; session lifecycle is managed by inotify.
		default:
			debugLog("ebpf: unknown event type %d", eventType)
		}

		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}

func (s *ebpfSubsystem) handleIO(raw []byte) {
	if len(raw) < int(unsafe.Sizeof(ioEvent{})) {
		return
	}
	var ev ioEvent
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &ev); err != nil {
		return
	}
	s.mu.Lock()
	sess, ok := s.sessions[ev.CgroupID]
	s.mu.Unlock()
	if !ok {
		return
	}
	data := ev.Data[:ev.DataLen]
	sess.sendChunk(int64(ev.TimestampNS), ev.Stream, data)
}

func (s *ebpfSubsystem) handleExecve(raw []byte) {
	if len(raw) < int(unsafe.Sizeof(execEvent{})) {
		return
	}
	var ev execEvent
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &ev); err != nil {
		return
	}
	comm := strings.TrimRight(string(ev.Comm[:]), "\x00")

	// ev.Uid is always 0 because sudo calls setuid(0) before exec'ing the target
	// command.  The invoking user's uid lives in the parent process (the shell).
	invokingUID := parentRealUID(ev.Pid)
	debugLog("ebpf: execve hook: comm=%s pid=%d sudo_uid=%d invoking_uid=%d cgroup=%d", comm, ev.Pid, ev.Uid, invokingUID, ev.CgroupID)

	if comm == "pkexec" {
		// pkexec uses polkit — the sudo plugin is never involved, so divergence
		// tracking does not apply.  Handle it separately.
		go s.handlePkexecExec(ev, invokingUID)
		return
	}
	s.divergence.registerEBPF(invokingUID, ev.Pid, comm)
}

// parentRealUID returns the real uid of the parent of pid by reading
// /proc/<pid>/status (PPid line) and then /proc/<ppid>/status (Uid line).
// Falls back to 0 on any read error (treated as root — still safe for alerting).
func parentRealUID(pid uint32) uint32 {
	readStatus := func(p uint32) map[string]string {
		data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", p))
		if err != nil {
			return nil
		}
		m := make(map[string]string)
		for _, line := range strings.SplitAfter(string(data), "\n") {
			if i := strings.IndexByte(line, ':'); i > 0 {
				m[strings.TrimSpace(line[:i])] = strings.TrimSpace(line[i+1:])
			}
		}
		return m
	}

	st := readStatus(pid)
	if st == nil {
		return 0
	}
	var ppid uint32
	fmt.Sscanf(st["PPid"], "%d", &ppid)
	if ppid == 0 {
		return 0
	}
	pst := readStatus(ppid)
	if pst == nil {
		return 0
	}
	// Uid field: "real  effective  saved  fs" — we want real uid (first value).
	var uid uint32
	fmt.Sscanf(pst["Uid"], "%d", &uid)
	return uid
}

func (s *ebpfSubsystem) logDropped(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	var lastTotal uint64
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			total := s.droppedTotal.Load()
			if total > lastTotal {
				log.Printf("ebpf: ring buffer overflow — %d events dropped total", total)
				lastTotal = total
			}
		}
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
	log.Printf("ebpf: pkexec by user=%s parent=%s cgroup=%d", username, parentSessID, currentCgroupID)

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

	hasIO := scopePath != ""
	sess := &ebpfSession{
		id:       sessID,
		user:     username,
		host:     s.hostname,
		command:  "pkexec",
		source:   "ebpf-pkexec",
		parentID: parentSessID,
		hasIO:    hasIO,
	}

	if err := sess.connect(s.cfg.Server, s.tlsCfg, nil); err != nil {
		log.Printf("ebpf: pkexec [%s]: connect: %v", sessID, err)
		return
	}

	if !hasIO {
		// Background pkexec (e.g. packagekitd) — no I/O to capture.
		sess.close(0)
		log.Printf("ebpf: pkexec event recorded: %s user=%s (no scope)", sessID, username)
		return
	}

	// Scope or invoking cgroup found — register in tracked_cgroups for PTY I/O.
	cgroupID, err := cgroupInode(scopePath)
	if err != nil {
		log.Printf("ebpf: pkexec scope stat %s: %v", scopePath, err)
		sess.close(0)
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
	s.mu.Unlock()

	if usingInvokingCgroup {
		// Session ends when pkexec (ev.Pid) exits — no inotify signal for this cgroup.
		log.Printf("ebpf: pkexec session started: %s user=%s cgroup=%s (invoking cgroup)",
			sessID, username, filepath.Base(scopePath))
		go func() {
			waitForPID(ev.Pid)
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

	for i, w := range s.pendingPkexec {
		if time.Since(w.ts) > 5*time.Second {
			continue
		}
		// Notify the oldest waiter within the time window.
		s.pendingPkexec = append(s.pendingPkexec[:i], s.pendingPkexec[i+1:]...)
		select {
		case w.ch <- scopePath:
		default:
		}
		return
	}
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

func (s *ebpfSubsystem) watch(ctx context.Context) {
	userSlice := filepath.Join(s.cgroupRoot, "user.slice")

	ifd, err := syscall.InotifyInit1(syscall.IN_CLOEXEC)
	if err != nil {
		log.Printf("ebpf: inotify_init: %v", err)
		return
	}
	defer syscall.Close(ifd)

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
		syscall.Close(ifd)
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
						time.AfterFunc(200*time.Millisecond, func() {
							s.sessionStarted(fullPath, name)
						})
					} else {
						// Non-session scope — could be a pkexec transient scope.
						time.AfterFunc(100*time.Millisecond, func() {
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
	cgroupID, err := cgroupInode(scopePath)
	if err != nil {
		// Scope may have been removed before the 200 ms delay elapsed — normal.
		debugLog("ebpf: sessionStarted: stat %s: %v", scopePath, err)
		return
	}

	meta, err := loginctlSession(num)
	if err != nil {
		debugLog("ebpf: sessionStarted: loginctl session %s: %v", num, err)
		return
	}
	// An empty session type means a polkit/pkexec-created PAM session for root.
	// Route it to any pending pkexec waiter rather than tracking it as a TTY session.
	if meta.stype == "" {
		debugLog("ebpf: sessionStarted: routing session %s (type=%q) to pkexec waiter", num, meta.stype)
		s.resolvePkexecScope(scopePath)
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
	}

	if err := sess.connect(s.cfg.Server, s.tlsCfg, nil); err != nil {
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
	s.mu.Unlock()

	log.Printf("ebpf: session started: %s user=%s remote=%s", sess.id, sess.user, sess.remote)
}

func (s *ebpfSubsystem) sessionEnded(scopePath string) {
	cgroupID, err := cgroupInode(scopePath)
	if err != nil {
		return
	}
	s.mu.Lock()
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
func (s *ebpfSubsystem) trackSudoPID(sudoPid uint32, sessionID string) {
	marker := uint8(1)
	if err := s.objs.TrackedSudoPids.Put(sudoPid, marker); err != nil {
		log.Printf("ebpf: trackSudoPID pid=%d session=%s: %v", sudoPid, sessionID, err)
	} else {
		log.Printf("ebpf: trackSudoPID: added pid=%d for session %s", sudoPid, sessionID)
	}
}

// untrackSudoPID removes sudoPid from the BPF tracked_sudo_pids map when the
// plugin session ends.
func (s *ebpfSubsystem) untrackSudoPID(sudoPid uint32) {
	if err := s.objs.TrackedSudoPids.Delete(sudoPid); err == nil {
		log.Printf("ebpf: untrackSudoPID: removed pid=%d", sudoPid)
	}
}

// trackPluginCgroup adds the cgroup at cgroupPath to the BPF tracked_cgroups
// map so that PTY I/O events from plugin sessions are captured.
func (s *ebpfSubsystem) trackPluginCgroup(cgroupPath, sessionID string) {
	id, err := cgroupInode(cgroupPath)
	if err != nil {
		log.Printf("ebpf: trackPluginCgroup %s: stat error: %v", cgroupPath, err)
		return
	}
	var key [64]byte
	copy(key[:], sessionID)
	if err := s.objs.TrackedCgroups.Put(id, key); err != nil {
		log.Printf("ebpf: trackPluginCgroup put %s inode=%d: %v", cgroupPath, id, err)
	} else {
		log.Printf("ebpf: trackPluginCgroup: added inode=%d for session %s", id, sessionID)
	}
}

// untrackPluginCgroup removes the cgroup from the BPF tracked_cgroups map
// when the plugin session ends.
func (s *ebpfSubsystem) untrackPluginCgroup(cgroupPath string) {
	id, err := cgroupInode(cgroupPath)
	if err != nil {
		return
	}
	if err := s.objs.TrackedCgroups.Delete(id); err == nil {
		log.Printf("ebpf: untrackPluginCgroup: removed inode=%d", id)
	}
}

// ── ebpfSession ───────────────────────────────────────────────────────────────

type ebpfSession struct {
	id       string
	user     string
	host     string
	remote   string
	command  string
	cgroupID uint64
	source   string // "ebpf-tty" or "ebpf-pkexec"
	parentID string // parent session ID (pkexec only)
	hasIO    bool   // false = no TTY data expected (background pkexec)

	mu     sync.Mutex
	conn   net.Conn
	bw     *bufio.Writer
	seq    uint64
	done   bool
	cancel context.CancelFunc
}

func (s *ebpfSession) connect(addr string, tlsCfg *tls.Config, verifyKey []byte) error {
	rawTCP, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("dial %s: %w", addr, err)
	}
	tc := rawTCP.(*net.TCPConn)
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(1 * time.Second)

	cfg := tlsCfg.Clone()
	if cfg.ServerName == "" {
		if host, _, err := net.SplitHostPort(addr); err == nil {
			cfg.ServerName = host
		}
	}
	tlsConn := tls.Client(rawTCP, cfg)
	if err := tlsConn.Handshake(); err != nil {
		rawTCP.Close()
		return fmt.Errorf("TLS handshake: %w", err)
	}

	s.conn = tlsConn
	s.bw = bufio.NewWriterSize(tlsConn, 64*1024)

	src := s.source
	if src == "" {
		src = "ebpf-tty"
	}
	start := protocol.SessionStart{
		SessionID:       s.id,
		User:            s.user,
		Host:            s.host,
		Command:         s.command,
		Ts:              time.Now().Unix(),
		Pid:             os.Getpid(),
		Source:          src,
		ParentSessionID: s.parentID,
		HasIO:           s.hasIO,
	}
	payload, _ := json.Marshal(start)
	if err := protocol.WriteMessage(s.bw, protocol.MsgSessionStart, payload); err != nil {
		tlsConn.Close()
		return fmt.Errorf("send session start: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel

	go s.heartbeat(ctx)
	go s.drainACKs(ctx, verifyKey)

	return nil
}

func (s *ebpfSession) sendChunk(tsNS int64, stream uint8, data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done || s.conn == nil {
		return
	}
	s.seq++
	payload := encodeEBPFChunk(s.seq, tsNS, stream, data)
	if err := protocol.WriteMessage(s.bw, protocol.MsgChunk, payload); err != nil {
		log.Printf("ebpf [%s]: send chunk: %v", s.id, err)
		s.done = true
		if s.cancel != nil {
			s.cancel()
		}
	}
}

func (s *ebpfSession) close(exitCode int32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done || s.conn == nil {
		return
	}
	s.done = true
	if s.cancel != nil {
		s.cancel()
	}
	payload := encodeEBPFSessionEnd(s.seq, exitCode)
	_ = protocol.WriteMessage(s.bw, protocol.MsgSessionEnd, payload)
	s.conn.Close()
}

func (s *ebpfSession) heartbeat(ctx context.Context) {
	ticker := time.NewTicker(400 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		s.mu.Lock()
		if s.done {
			s.mu.Unlock()
			return
		}
		_ = protocol.WriteMessage(s.bw, protocol.MsgHeartbeat, nil)
		s.mu.Unlock()
	}
}

func (s *ebpfSession) drainACKs(ctx context.Context, verifyKey []byte) {
	s.mu.Lock()
	conn := s.conn
	s.mu.Unlock()
	if conn == nil {
		return
	}
	br := bufio.NewReader(conn)
	lastACK := time.Now()

	for {
		// Check context before blocking on read.
		select {
		case <-ctx.Done():
			return
		default:
		}

		msgType, payloadLen, err := protocol.ReadHeader(br)
		if err != nil {
			return
		}
		if _, err := protocol.ReadPayload(br, payloadLen); err != nil {
			return
		}

		switch msgType {
		case protocol.MsgAck, protocol.MsgHeartbeatAck:
			lastACK = time.Now()
		}

		if time.Since(lastACK) > 5*time.Second {
			log.Printf("ebpf [%s]: no ACK from server for >5s", s.id)
			lastACK = time.Now()
		}
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// readProcCgroupPath returns the absolute cgroup v2 path for pid, or "" on error.
// Must be called while the process is still alive.
func readProcCgroupPath(pid uint32, cgroupRoot string) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "0::") {
			rel := strings.TrimSpace(strings.TrimPrefix(line, "0::"))
			if rel == "" || rel == "/" {
				return ""
			}
			return filepath.Join(cgroupRoot, rel)
		}
	}
	return ""
}

// waitForPID blocks until /proc/<pid> disappears (process has exited).
func waitForPID(pid uint32) {
	for {
		if _, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); os.IsNotExist(err) {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func cgroupInode(path string) (uint64, error) {
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return 0, err
	}
	return st.Ino, nil
}

type sessionMeta struct {
	user   string
	remote string
	shell  string
	stype  string
}

func loginctlSession(num string) (sessionMeta, error) {
	props := []string{"Name", "RemoteHost", "Type", "Class"}
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

func generateEBPFSessionID(hostname, username, sessionNum string) string {
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
	id := fmt.Sprintf("ebpf.%s.%s.%s.%s", safe(hostname), safe(username), sessionNum, ts)
	if len(id) > 200 {
		id = id[:200]
	}
	return id
}

func encodeEBPFChunk(seq uint64, tsNS int64, stream uint8, data []byte) []byte {
	buf := make([]byte, 21+len(data))
	binary.BigEndian.PutUint64(buf[0:], seq)
	binary.BigEndian.PutUint64(buf[8:], uint64(tsNS))
	buf[16] = stream
	binary.BigEndian.PutUint32(buf[17:], uint32(len(data)))
	copy(buf[21:], data)
	return buf
}

func encodeEBPFSessionEnd(finalSeq uint64, exitCode int32) []byte {
	buf := make([]byte, 12)
	binary.BigEndian.PutUint64(buf[0:], finalSeq)
	binary.BigEndian.PutUint32(buf[8:], uint32(exitCode))
	return buf
}
