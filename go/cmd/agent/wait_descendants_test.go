package main

// waitForDescendants replaces a flat 2s sleep at the end of every session. The
// upper bound must not shrink -- cutting it short would tear a session cgroup
// down while a late-forking child is still starting -- but a session that has
// nothing to wait for should not pay it.

import (
	"testing"
	"time"
)

func TestWaitForDescendants_ReturnsAsSoonAsAChildAppears(t *testing.T) {
	cg := &cgroupSession{path: t.TempDir(), escaped: map[int]int{}}
	// An escaped PID counts as a descendant; PID 1 is always running.
	cg.escaped[1] = 1

	start := time.Now()
	waitForDescendants(cg, 2*time.Second, 20*time.Millisecond)
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Errorf("waited %v with a descendant already present; should return promptly", elapsed)
	}
}

func TestWaitForDescendants_WaitsTheFullLimitWhenNothingAppears(t *testing.T) {
	cg := &cgroupSession{path: t.TempDir(), escaped: map[int]int{}}

	const limit = 300 * time.Millisecond
	start := time.Now()
	waitForDescendants(cg, limit, 20*time.Millisecond)
	elapsed := time.Since(start)

	if elapsed < limit {
		t.Errorf("returned after %v, before the %v limit — a late fork could be missed", elapsed, limit)
	}
	if elapsed > limit+250*time.Millisecond {
		t.Errorf("overshot the limit by too much: %v", elapsed)
	}
}

// A nil session (cgroups unavailable) must not panic: hasPids and
// hasEscapedRunning both tolerate a nil receiver, and this is on the path
// every session takes on shutdown.
func TestWaitForDescendants_NilSession(t *testing.T) {
	start := time.Now()
	waitForDescendants(nil, 150*time.Millisecond, 20*time.Millisecond)
	if elapsed := time.Since(start); elapsed < 150*time.Millisecond {
		t.Errorf("nil session returned early after %v", elapsed)
	}
}
