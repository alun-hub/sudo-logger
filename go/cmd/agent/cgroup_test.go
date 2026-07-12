package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func newTestCgroupSession(t *testing.T) *cgroupSession {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "cgroup.freeze"), []byte("0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	return &cgroupSession{path: dir}
}

func readFreezeFile(t *testing.T, cg *cgroupSession) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(cg.path, "cgroup.freeze"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestCgroup_MarkTerminatingDisarmsFreeze reproduces the hang seen in
// production: a TTL/freeze-timeout watcher calls unfreeze() then signals the
// session, but a concurrent markDead() (server conn tearing down as part of
// the same shutdown) or a lingerCgroup tick can call freeze() again before
// the signal lands, leaving the cgroup permanently frozen since nothing else
// ever thaws it. markTerminating() must make any later freeze() a no-op.
func TestCgroup_MarkTerminatingDisarmsFreeze(t *testing.T) {
	cg := newTestCgroupSession(t)

	cg.freeze()
	if !cg.frozen || readFreezeFile(t, cg) != "1\n" {
		t.Fatalf("freeze() before termination should still freeze; frozen=%v file=%q", cg.frozen, readFreezeFile(t, cg))
	}

	cg.unfreeze()
	if cg.frozen || readFreezeFile(t, cg) != "0\n" {
		t.Fatalf("unfreeze() should thaw; frozen=%v file=%q", cg.frozen, readFreezeFile(t, cg))
	}

	cg.markTerminating()
	cg.freeze() // simulates a late markDead()/lingerCgroup racing the termination
	if cg.frozen || readFreezeFile(t, cg) != "0\n" {
		t.Fatalf("freeze() after markTerminating() must be a no-op; frozen=%v file=%q", cg.frozen, readFreezeFile(t, cg))
	}
}

// TestCgroup_MarkTerminatingNilSafe ensures the helper matches the nil-safety
// of freeze()/unfreeze() — sc.cg can be nil when cgroups are disabled.
func TestCgroup_MarkTerminatingNilSafe(t *testing.T) {
	var cg *cgroupSession
	cg.markTerminating() // must not panic
}

// procState reads the single-letter process state from /proc/<pid>/status
// (e.g. "S" sleeping, "T" stopped, "R" running).
func procState(t *testing.T, pid int) string {
	t.Helper()
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		t.Fatalf("read /proc/%d/status: %v", pid, err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "State:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				return fields[1]
			}
		}
	}
	t.Fatalf("no State: line in /proc/%d/status", pid)
	return ""
}

func waitForState(t *testing.T, pid int, want string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if procState(t, pid) == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("pid %d did not reach state %q within %v (last state %q)", pid, want, timeout, procState(t, pid))
}

// spawnInGroup starts `sleep 100`, either as a new process-group leader
// (joinPgid == 0) or joining an existing group (joinPgid == that group's
// pgid) -- exactly how a real shell pipeline's two sides share one pgid.
func spawnInGroup(t *testing.T, joinPgid int) *exec.Cmd {
	t.Helper()
	cmd := exec.Command("sleep", "100")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pgid: joinPgid}
	if err := cmd.Start(); err != nil {
		t.Fatalf("spawn sleep: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	return cmd
}

// TestCgroup_FreezeStopsWholeProcessGroup is the regression test for the
// escaped-process SIGSTOP fix: freeze() must signal the tracked process's
// entire process group (kill(-pgid, ...)), not just the individual pid --
// otherwise one side of an escaped pipeline (a pgid member that isn't the
// group leader) is never stopped at all. Uses real spawned processes and
// reads real /proc state, not a mock, to exercise actual kernel signal
// delivery semantics.
func TestCgroup_FreezeStopsWholeProcessGroup(t *testing.T) {
	cg := newTestCgroupSession(t)
	cg.escaped = make(map[int]int)

	leader := spawnInGroup(t, 0)
	leaderPid := leader.Process.Pid
	member := spawnInGroup(t, leaderPid) // joins leader's process group

	waitForState(t, leaderPid, "S", time.Second)
	waitForState(t, member.Process.Pid, "S", time.Second)

	// Only the group LEADER pid is tracked in escaped (matching how
	// trackDescendants registers one entry per escaped pid) -- freeze()
	// must still stop the non-leader member via the shared pgid.
	cg.escaped[leaderPid] = leaderPid // pgid == leaderPid for the group

	cg.freeze()
	waitForState(t, leaderPid, "T", time.Second)
	waitForState(t, member.Process.Pid, "T", time.Second)

	cg.unfreeze()
	waitForState(t, leaderPid, "S", time.Second)
	waitForState(t, member.Process.Pid, "S", time.Second)
}

// TestCgroup_EscapedPidWithNoPgidIsNeverSignaled covers the pgid==0
// sentinel (Getpgid failed, or the shell-reclaim-fallback path in
// trackDescendants) -- freeze() must not call kill(-0, ...), which would
// signal the *caller's own* process group instead of doing nothing.
func TestCgroup_EscapedPidWithNoPgidIsNeverSignaled(t *testing.T) {
	cg := newTestCgroupSession(t)
	cg.escaped = map[int]int{99999999: 0} // fake pid, pgid explicitly 0

	// Must not panic or signal anything real; if this incorrectly called
	// kill(-0, SIGSTOP) it would stop this very test process's group.
	cg.freeze()
	cg.unfreeze()

	if procState(t, os.Getpid()) == "T" {
		t.Fatal("freeze() with pgid=0 signaled the test process's own group")
	}
}
