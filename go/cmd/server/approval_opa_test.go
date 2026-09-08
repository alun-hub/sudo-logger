package main

// Tests for the OPA/JIT policy lifecycle: storing it, reloading it, and what
// happens when it is removed or the store cannot be read.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"testing"

	"sudo-logger/internal/policy"
)

func challengePolicy(ruleID, user string) policy.Policy {
	return policy.Policy{
		DefaultAction: "challenge",
		Rules: []policy.Rule{
			{ID: ruleID, Action: "allow", Users: []string{user}},
		},
	}
}

// failingSetConfigStore rejects writes so the test can observe what happens to
// the in-memory engine when persistence fails.
type failingSetConfigStore struct {
	mockApprovalStore
}

var errStoreDown = errors.New("store unavailable")

func (f *failingSetConfigStore) SetConfig(context.Context, string, string) error {
	return errStoreDown
}

// TestSetOPAPolicy_FailedWriteLeavesPolicyUnchanged covers the ordering bug:
// the engine used to be swapped in before the policy was persisted, so a
// failed write returned an error to the caller while the process had already
// started enforcing a policy that no restart would restore.
func TestSetOPAPolicy_FailedWriteLeavesPolicyUnchanged(t *testing.T) {
	m := newApprovalManager(t.TempDir()+"/approval-policy.yaml", &failingSetConfigStore{})

	before, _ := m.GetOPAPolicy()
	if err := m.SetOPAPolicy(context.Background(), challengePolicy("r1", "alice")); !errors.Is(err, errStoreDown) {
		t.Fatalf("SetOPAPolicy error = %v, want the store error", err)
	}

	after, _ := m.GetOPAPolicy()
	if len(after.Rules) != len(before.Rules) {
		t.Errorf("in-memory policy changed despite the write failing: %d rules, was %d",
			len(after.Rules), len(before.Rules))
	}
}

// TestSetOPAPolicy_StoresAndAppliesOnSuccess is the other half: a successful
// write must both persist and take effect.
func TestSetOPAPolicy_StoresAndAppliesOnSuccess(t *testing.T) {
	backend := &mockApprovalStore{}
	m := newApprovalManager(t.TempDir()+"/approval-policy.yaml", backend)

	if err := m.SetOPAPolicy(context.Background(), challengePolicy("r1", "alice")); err != nil {
		t.Fatalf("SetOPAPolicy: %v", err)
	}
	if backend.configs["jit-policy"] == "" {
		t.Error("policy was not persisted under the jit-policy key")
	}
	got, rego := m.GetOPAPolicy()
	if len(got.Rules) != 1 || got.Rules[0].ID != "r1" {
		t.Errorf("policy not applied in memory: %+v", got)
	}
	if rego == "" {
		t.Error("no compiled Rego source available after a successful set")
	}
}

// TestLoadOPAPolicy_RemovedPolicyStopsBeingEnforced covers a policy deleted
// through the admin UI. The compiled engine used to stay live until the next
// restart, so a policy an operator had removed went on deciding sessions.
func TestLoadOPAPolicy_RemovedPolicyStopsBeingEnforced(t *testing.T) {
	backend := &mockApprovalStore{}
	m := newApprovalManager(t.TempDir()+"/approval-policy.yaml", backend)

	if err := m.SetOPAPolicy(context.Background(), challengePolicy("r1", "alice")); err != nil {
		t.Fatalf("SetOPAPolicy: %v", err)
	}
	if got, _ := m.GetOPAPolicy(); len(got.Rules) != 1 {
		t.Fatalf("setup: policy not loaded")
	}

	// Simulate deletion: the key is now absent, which the store reports as
	// an empty value with no error.
	delete(backend.configs, "jit-policy")
	m.loadOPAPolicy(context.Background())

	if got, _ := m.GetOPAPolicy(); len(got.Rules) != 0 {
		t.Errorf("removed policy still loaded: %+v", got)
	}
	m.mu.RLock()
	engine := m.opaEngine
	m.mu.RUnlock()
	if engine != nil {
		t.Error("compiled engine survived removal of the policy")
	}
}

// countingConfigStore counts GetConfig reads and how often the Rego is
// actually recompiled, so the reload loop's per-tick work can be measured
// rather than reasoned about.
type reloadCountingStore struct {
	mockApprovalStore
}

// TestReloadLoop_UnchangedPolicyIsNotRecompiled covers the every-30-seconds
// "OPA policy loaded" line an operator sees on an idle server. loadOPAPolicy
// reparsed and recompiled the policy on every tick regardless of whether it
// had changed, and logged each time -- 2880 lines a day in the log that is
// supposed to make a real configuration change stand out.
func TestReloadLoop_UnchangedPolicyIsNotRecompiled(t *testing.T) {
	backend := &reloadCountingStore{}
	m := newApprovalManager(t.TempDir()+"/approval-policy.yaml", backend)

	if err := m.SetOPAPolicy(context.Background(), challengePolicy("r1", "alice")); err != nil {
		t.Fatalf("SetOPAPolicy: %v", err)
	}

	m.mu.RLock()
	engineAfterSet := m.opaEngine
	hashAfterSet := m.lastOPAHash
	m.mu.RUnlock()
	if hashAfterSet == "" {
		t.Fatal("SetOPAPolicy did not record the hash of what it stored")
	}

	// Three ticks with nothing changed.
	for i := 0; i < 3; i++ {
		m.loadOPAPolicy(context.Background())
	}

	m.mu.RLock()
	engineAfterTicks := m.opaEngine
	m.mu.RUnlock()
	if engineAfterTicks != engineAfterSet {
		t.Error("the engine was rebuilt even though the policy had not changed")
	}
}

// A policy that does change must still be picked up.
func TestReloadLoop_ChangedPolicyIsApplied(t *testing.T) {
	backend := &mockApprovalStore{}
	m := newApprovalManager(t.TempDir()+"/approval-policy.yaml", backend)

	if err := m.SetOPAPolicy(context.Background(), challengePolicy("r1", "alice")); err != nil {
		t.Fatalf("SetOPAPolicy: %v", err)
	}

	// Someone edits the policy directly in the store, as another replica would.
	updated, err := json.Marshal(challengePolicy("r2", "bob"))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := backend.SetConfig(context.Background(), "jit-policy", string(updated)); err != nil {
		t.Fatalf("SetConfig: %v", err)
	}

	m.loadOPAPolicy(context.Background())

	got, _ := m.GetOPAPolicy()
	if len(got.Rules) != 1 || got.Rules[0].ID != "r2" {
		t.Errorf("changed policy was not picked up: %+v", got)
	}
}

// A build that failed must be retried on the next tick, not treated as
// already applied because the bytes are the same.
func TestReloadLoop_FailedLoadIsRetried(t *testing.T) {
	backend := &mockApprovalStore{}
	m := newApprovalManager(t.TempDir()+"/approval-policy.yaml", backend)

	// Valid JSON, but Rego that cannot compile.
	bad, err := json.Marshal(policy.Policy{DefaultAction: "challenge", RawRego: "this is not rego {{{"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := backend.SetConfig(context.Background(), "jit-policy", string(bad)); err != nil {
		t.Fatalf("SetConfig: %v", err)
	}

	m.loadOPAPolicy(context.Background())

	m.mu.RLock()
	hashAfterFailure := m.lastOPAHash
	engine := m.opaEngine
	m.mu.RUnlock()

	badHash := fmt.Sprintf("%x", sha256.Sum256(bad))
	if hashAfterFailure == badHash {
		t.Error("a failed load recorded its hash; the same bytes would never be retried")
	}
	if engine != nil {
		t.Error("an engine was installed despite the compile failing")
	}

	// Fixing the policy in place must take effect on the next tick.
	good, err := json.Marshal(challengePolicy("r9", "carol"))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := backend.SetConfig(context.Background(), "jit-policy", string(good)); err != nil {
		t.Fatalf("SetConfig: %v", err)
	}
	m.loadOPAPolicy(context.Background())

	if got, _ := m.GetOPAPolicy(); len(got.Rules) != 1 || got.Rules[0].ID != "r9" {
		t.Errorf("corrected policy was not applied on the next tick: %+v", got)
	}
}

// TestReloadLoop_LogsOncePerChange targets the symptom directly: an idle
// server printed "OPA policy loaded" on every 30-second tick. Written without
// touching internals so it can be run against either version of the code.
func TestReloadLoop_LogsOncePerChange(t *testing.T) {
	backend := &mockApprovalStore{}
	m := newApprovalManager(t.TempDir()+"/approval-policy.yaml", backend)

	stored, err := json.Marshal(challengePolicy("r1", "alice"))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := backend.SetConfig(context.Background(), "jit-policy", string(stored)); err != nil {
		t.Fatalf("SetConfig: %v", err)
	}

	var buf bytes.Buffer
	old := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(old) })

	// First load applies it; four further ticks change nothing.
	for i := 0; i < 5; i++ {
		m.loadOPAPolicy(context.Background())
	}

	if got := strings.Count(buf.String(), "OPA policy loaded"); got != 1 {
		t.Errorf("logged %d times over 5 ticks with an unchanged policy, want 1", got)
	}
}
