package main

// Tests for loadPolicy when there is no approval policy file. The three
// configs it manages live under separate store keys, so the absence of one
// must not stop the others from loading.

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

// TestLoadPolicy_MissingFileStillLoadsRedactor covers a deployment where JIT
// approval is not configured. loadPolicy used to return as soon as the policy
// file was missing, before reaching loadRedactor -- leaving the justification
// redactor nil, so a secret pasted into a justification reached the pending
// request, the log line and the approval webhook unmasked.
func TestLoadPolicy_MissingFileStillLoadsRedactor(t *testing.T) {
	patterns, err := json.Marshal([]string{`SUPERSECRET-[0-9]+`})
	if err != nil {
		t.Fatalf("marshal patterns: %v", err)
	}
	backend := &mockApprovalStore{configs: map[string]string{
		"redaction_config": string(patterns),
		// "approval-policy.yaml" deliberately absent, so loadPolicy falls
		// through to the file path below, which does not exist either.
	}}

	m := newApprovalManager(filepath.Join(t.TempDir(), "approval-policy.yaml"), backend)

	const justification = "deploying with token SUPERSECRET-4242 today"
	if got := m.redactJustification(justification); got == justification {
		t.Errorf("justification not redacted with no policy file present: %q", got)
	}
}

// TestLoadPolicy_MissingFileLeavesApprovalDisabled pins the other half of that
// early return, so widening it later is a deliberate act: with no policy file
// and nothing in the store, JIT approval stays off and sessions are allowed.
func TestLoadPolicy_MissingFileLeavesApprovalDisabled(t *testing.T) {
	m := newApprovalManager(filepath.Join(t.TempDir(), "approval-policy.yaml"),
		&mockApprovalStore{})

	res := m.Check("alice", "host1", "root", "/bin/bash", nil, "")
	if res.Result != ApprovalResultAllow {
		t.Errorf("Check = %v, want ApprovalResultAllow when no policy is configured", res.Result)
	}
}
