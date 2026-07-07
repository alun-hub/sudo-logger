package main

import (
	"os"
	"path/filepath"
	"testing"
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
