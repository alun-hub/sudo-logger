package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"time"
	"unsafe"
)

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

		// Belt-and-suspenders: the loop actually exits via s.rd.Close()
		// unblocking the Read() above (which returns an error), not via this
		// check — ctx cancellation alone won't interrupt a blocked Read().
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
	if ev.DataLen > uint32(len(ev.Data)) {
		ev.DataLen = uint32(len(ev.Data))
	}
	data := ev.Data[:ev.DataLen]
	// Use Go reception time rather than BPF ktime (CLOCK_MONOTONIC).
	// bpf_ktime_get_ns() excludes suspend time but /proc/uptime includes it,
	// causing all event timestamps to be before startTime after suspend/resume
	// (elapsed clamped to 0 → all output shown at once in replay).
	// Ring-buffer events are processed sequentially, so reception time is a
	// faithful relative timestamp for interactive sessions.
	sess.sendChunk(time.Now().UnixNano(), ev.Stream, data)
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
// TOCTOU note: pid/ppid may have exited and been reused between the BPF
// event firing and this read, which could misattribute the alert to the
// wrong (recycled) PID's parent. Low risk in practice and no worse than the
// existing error fallback, since PID reuse is rare within the resolution
// window and misattribution here only affects an informational alert, not
// an enforcement decision.
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
