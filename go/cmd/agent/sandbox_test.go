package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"sudo-logger/internal/protocol"
)

// captureLog redirects the standard logger's output for the duration of fn
// and returns everything written to it.
func captureLog(fn func()) string {
	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(orig)
	fn()
	return buf.String()
}

func TestSandbox_ReportViolation(t *testing.T) {
	// Mock activeCgs
	origActiveCgs := activeCgs
	defer func() {
		activeCgs = origActiveCgs
	}()

	// Use net.Pipe to mock the server connection
	serverSide, agentSide := net.Pipe()
	defer serverSide.Close()
	defer agentSide.Close()

	bw := bufio.NewWriter(agentSide)
	var mu sync.Mutex
	sw := protocol.NewWriter(bw, &mu)

	cg := &cgroupSession{
		cgroupID: 12345,
		cgName:   "test-session-sandbox",
		serverW:  sw,
	}
	activeCgs = []*cgroupSession{cg}

	s := &sandboxSubsystem{}

	// Prepare to receive the alert on the server side
	alertChan := make(chan protocol.SandboxAlert, 1)
	go func() {
		r := bufio.NewReader(serverSide)
		mType, plen, err := protocol.ReadHeader(r)
		if err != nil {
			return
		}
		payload, _ := protocol.ReadPayload(r, plen)
		if mType == protocol.MsgSandboxAlert {
			var alert protocol.SandboxAlert
			json.Unmarshal(payload, &alert)
			alertChan <- alert
		}
	}()

	s.reportViolation(12345, 9999, alertFileOpen, "test-proc", 0, 0, 0, "", 0)

	select {
	case alert := <-alertChan:
		if alert.SessionID != "test-session-sandbox" {
			t.Errorf("Expected SessionID %q, got %q", "test-session-sandbox", alert.SessionID)
		}
		if alert.Comm != "test-proc" {
			t.Errorf("Expected Comm %q, got %q", "test-proc", alert.Comm)
		}
		if alert.Type != alertFileOpen {
			t.Errorf("Expected Type %d, got %d", alertFileOpen, alert.Type)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Timeout waiting for sandbox alert")
	}
}

func TestSandbox_RetryViolation(t *testing.T) {
	// Test that retryViolation checks auxCgroupMap
	origActiveCgs := activeCgs
	defer func() {
		activeCgs = origActiveCgs
		auxCgroupMu.Lock()
		auxCgroupMap = make(map[uint64]*cgroupSession)
		auxCgroupMu.Unlock()
	}()

	activeCgs = nil // No active sessions initially

	serverSide, agentSide := net.Pipe()
	defer serverSide.Close()
	defer agentSide.Close()
	bw := bufio.NewWriter(agentSide)
	var mu sync.Mutex
	sw := protocol.NewWriter(bw, &mu)

	cg := &cgroupSession{
		cgroupID: 555,
		cgName:   "aux-session",
		serverW:  sw,
	}

	// Register in aux map
	auxCgroupMu.Lock()
	auxCgroupMap[555] = cg
	auxCgroupMu.Unlock()

	s := &sandboxSubsystem{}
	alert := protocol.SandboxAlert{
		Pid:  8888,
		Comm: "escaped-proc",
		Type: alertProcessKill,
	}

	alertChan := make(chan protocol.SandboxAlert, 1)
	go func() {
		r := bufio.NewReader(serverSide)
		// We expect one message
		mType, plen, err := protocol.ReadHeader(r)
		if err != nil {
			if err != io.EOF {
				t.Errorf("ReadHeader error: %v", err)
			}
			return
		}
		payload, _ := protocol.ReadPayload(r, plen)
		if mType == protocol.MsgSandboxAlert {
			var a protocol.SandboxAlert
			json.Unmarshal(payload, &a)
			alertChan <- a
		}
	}()

	// Trigger retry (which happens after 150ms)
	go s.retryViolation(555, alert, 0)

	select {
	case received := <-alertChan:
		if received.SessionID != "aux-session" {
			t.Errorf("Expected SessionID %q, got %q", "aux-session", received.SessionID)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Timeout waiting for retry sandbox alert")
	}
}

func TestLogSandboxWeakening(t *testing.T) {
	allOn := resolvedFeatures{
		DenyNetlink: true, DenyMount: true, DenyPtrace: true,
		DenyCapAuditControl: true, DenyCapNetAdmin: true, DenyCapSysModule: true,
		DenyCapMacAdmin: true, DenyCapSysRawio: true, DenyCapSysBoot: true,
		DenySystemdIPC: true,
	}

	t.Run("no change logs nothing", func(t *testing.T) {
		out := captureLog(func() {
			logSandboxWeakening(allOn, allOn, 0, 0, 0, 0, 0)
		})
		if out != "" {
			t.Errorf("expected no log output, got: %q", out)
		}
	})

	t.Run("additions only logs nothing", func(t *testing.T) {
		// Same features, and only new inodes/procs added (no obsolete/removed
		// entries) must not be flagged as weakening.
		out := captureLog(func() {
			logSandboxWeakening(allOn, allOn, 0, 0, 0, 0, 0)
		})
		if out != "" {
			t.Errorf("expected no log output for additions-only reload, got: %q", out)
		}
	})

	t.Run("feature disabled is flagged", func(t *testing.T) {
		weakened := allOn
		weakened.DenyPtrace = false
		out := captureLog(func() {
			logSandboxWeakening(allOn, weakened, 0, 0, 0, 0, 0)
		})
		if !strings.Contains(out, "SECURITY WARNING") || !strings.Contains(out, "deny_ptrace disabled") {
			t.Errorf("expected a deny_ptrace weakening warning, got: %q", out)
		}
	})

	t.Run("feature enabled (strengthening) is not flagged", func(t *testing.T) {
		allOff := resolvedFeatures{}
		out := captureLog(func() {
			logSandboxWeakening(allOff, allOn, 0, 0, 0, 0, 0)
		})
		if out != "" {
			t.Errorf("expected no log output when features are only being enabled, got: %q", out)
		}
	})

	t.Run("removed protected inode is flagged", func(t *testing.T) {
		out := captureLog(func() {
			logSandboxWeakening(allOn, allOn, 2, 0, 0, 0, 0)
		})
		if !strings.Contains(out, "SECURITY WARNING") || !strings.Contains(out, "2 protected path(s) no longer protected") {
			t.Errorf("expected a removed-inode weakening warning, got: %q", out)
		}
	})

	t.Run("removed process/ipc/forbidden/noexec entries are each flagged", func(t *testing.T) {
		out := captureLog(func() {
			logSandboxWeakening(allOn, allOn, 0, 1, 1, 1, 1)
		})
		for _, want := range []string{
			"1 protected process(es) no longer protected",
			"1 systemd-ipc socket(s) no longer blocked",
			"1 forbidden-binary rule(s) removed",
			"1 noexec rule(s) removed",
		} {
			if !strings.Contains(out, want) {
				t.Errorf("expected log to contain %q, got: %q", want, out)
			}
		}
	})
}
