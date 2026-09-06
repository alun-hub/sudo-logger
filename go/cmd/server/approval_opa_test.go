package main

// Tests for the OPA/JIT policy lifecycle: storing it, reloading it, and what
// happens when it is removed or the store cannot be read.

import (
	"context"
	"errors"
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
