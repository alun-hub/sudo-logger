package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// ── Ring buffer event types ───────────────────────────────────────────────────

const (
	eventTypeIO   = uint8(1)
	eventTypeExec = uint8(2)
	eventTypeExit = uint8(3)

	maxPendingAge  = 10 * time.Minute
	maxPendingQ    = 200
	retryInterval  = 30 * time.Second
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
// Layout: event_type(1) comm(15) pid(4) uid(4) cgroup_id(8) timestamp_ns(8) target(64)
type execEvent struct {
	EventType   uint8
	Comm        [15]byte
	Pid         uint32
	Uid         uint32
	CgroupID    uint64
	TimestampNS uint64
	Target      [64]byte // path passed to execve, captured at tracepoint time
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
	ctx        context.Context

	objs    *RecorderObjects
	rd      *ringbuf.Reader
	links   []link.Link

	mu            sync.Mutex
	sessions      map[uint64]*ebpfSession
	scopeToCgroup map[string]uint64 // scopePath → cgroupID, for sessionEnded after scope is deleted
	droppedTotal  atomic.Uint64

	pkexecMu      sync.Mutex
	pendingPkexec []*pkexecWaiter

	retryMu sync.Mutex
	retryQ  []*ebpfSession // hasIO=false sessions waiting for server reconnect
}

func newEBPFSubsystem(cfg agentConfig, tlsCfg *tls.Config, hostname string, div *divergenceTracker) *ebpfSubsystem {
	return &ebpfSubsystem{
		cfg:           cfg,
		tlsCfg:        tlsCfg,
		hostname:      hostname,
		divergence:    div,
		cgroupRoot:    "/sys/fs/cgroup",
		sessions:      make(map[uint64]*ebpfSession),
		scopeToCgroup: make(map[string]uint64),
	}
}

// start loads the BPF objects, attaches tracepoints, and begins the watch loop.
// Returns an error if eBPF is unavailable; caller falls back to plugin-only mode.
func (s *ebpfSubsystem) start(ctx context.Context) error {
	s.ctx = ctx
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

	// Goroutine: retry queued hasIO=false pkexec sessions when server reconnects.
	go s.retryLoop(ctx)

	// Goroutine: evict sessions that never generated a sched_process_exit event.
	go s.sweepStaleSessions(ctx)

	return nil
}

func (s *ebpfSubsystem) stop() {
	if s.rd != nil {
		s.rd.Close()
	}
	for _, l := range s.links {
		l.Close()
	}
	// Delete BPF map entries BEFORE closing BPF objects to avoid use-after-close.
	s.mu.Lock()
	sessions := make([]*ebpfSession, 0, len(s.sessions))
	for id, sess := range s.sessions {
		sessions = append(sessions, sess)
		if s.objs != nil {
			_ = s.objs.TrackedCgroups.Delete(id)
		}
	}
	s.sessions = make(map[uint64]*ebpfSession)
	s.scopeToCgroup = make(map[string]uint64)
	s.mu.Unlock()
	if s.objs != nil {
		s.objs.Close()
	}
	// sess.close() only tears down the session's TLS connection to the
	// server, not any BPF object — so its ordering relative to
	// s.objs.Close() above is not safety-critical either way.
	for _, sess := range sessions {
		sess.close(0)
	}
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

func (s *ebpfSubsystem) retryLoop(ctx context.Context) {
	ticker := time.NewTicker(retryInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.drainRetryQueue()
		}
	}
}

const sessionMaxAge = 24 * time.Hour

// sweepStaleSessions evicts sessions that have been connected longer than
// sessionMaxAge.  This guards against sessions that never generate a
// sched_process_exit event (e.g. zombie processes), which would otherwise
// hold open TLS connections indefinitely.
func (s *ebpfSubsystem) sweepStaleSessions(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		cutoff := time.Now().Add(-sessionMaxAge)
		s.mu.Lock()
		var stale []*ebpfSession
		for id, sess := range s.sessions {
			if !sess.connectedAt.IsZero() && sess.connectedAt.Before(cutoff) {
				stale = append(stale, sess)
				delete(s.sessions, id)
				_ = s.objs.TrackedCgroups.Delete(id)
			}
		}
		for path, id := range s.scopeToCgroup {
			if _, ok := s.sessions[id]; !ok {
				delete(s.scopeToCgroup, path)
			}
		}
		s.mu.Unlock()
		for _, sess := range stale {
			log.Printf("ebpf: evicting stale session %s (connected %v ago)", sess.id, time.Since(sess.connectedAt).Round(time.Minute))
			sess.close(0)
		}
	}
}

func (s *ebpfSubsystem) trackSudoPID(sudoPid uint32, sessionID string) {
	marker := uint8(1)
	if err := s.objs.TrackedSudoPids.Put(sudoPid, marker); err != nil {
		debugLog("ebpf: trackSudoPID pid=%d session=%s: %v", sudoPid, sessionID, err)
	} else {
		debugLog("ebpf: trackSudoPID: added pid=%d for session %s", sudoPid, sessionID)
	}
}

// untrackSudoPID removes sudoPid from the BPF tracked_sudo_pids map when the
// plugin session ends.
func (s *ebpfSubsystem) untrackSudoPID(sudoPid uint32) {
	if err := s.objs.TrackedSudoPids.Delete(sudoPid); err == nil {
		debugLog("ebpf: untrackSudoPID: removed pid=%d", sudoPid)
	}
}

// trackPluginCgroup adds the cgroup at cgroupPath to the BPF tracked_cgroups
// map so that PTY I/O events from plugin sessions are captured.
func (s *ebpfSubsystem) trackPluginCgroup(cgroupPath, sessionID string) {
	id, err := cgroupInode(cgroupPath)
	if err != nil {
		debugLog("ebpf: trackPluginCgroup %s: stat error: %v", cgroupPath, err)
		return
	}
	var key [64]byte
	copy(key[:], sessionID)
	if err := s.objs.TrackedCgroups.Put(id, key); err != nil {
		debugLog("ebpf: trackPluginCgroup put %s inode=%d: %v", cgroupPath, id, err)
	} else {
		debugLog("ebpf: trackPluginCgroup: added inode=%d for session %s", id, sessionID)
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
		debugLog("ebpf: untrackPluginCgroup: removed inode=%d", id)
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

// waitForPID blocks until /proc/<pid> disappears or ctx is cancelled.
func waitForPID(ctx context.Context, pid uint32) {
	for {
		if _, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); os.IsNotExist(err) {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func cgroupInode(path string) (uint64, error) {
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return 0, err
	}
	return st.Ino, nil
}
