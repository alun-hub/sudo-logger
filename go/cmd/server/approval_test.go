package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"sudo-logger/internal/policy"
	"sudo-logger/internal/store"
)

type mockApprovalStore struct {
	store.ApprovalStore
	deletedID string
	configs   map[string]string
}

func (m *mockApprovalStore) DeleteApprovalRequest(ctx context.Context, id string) (*store.ApprovalRequest, error) {
	m.deletedID = id
	if id == "NOTFOUND" {
		return nil, nil
	}
	return &store.ApprovalRequest{ID: id, User: "alice", Host: "host1"}, nil
}

func (m *mockApprovalStore) GetConfig(ctx context.Context, key string) (string, error) {
	if m.configs == nil {
		return "", nil
	}
	return m.configs[key], nil
}

func (m *mockApprovalStore) SetConfig(ctx context.Context, key, value string) error {
	if m.configs == nil {
		m.configs = make(map[string]string)
	}
	m.configs[key] = value
	return nil
}

func (m *mockApprovalStore) HasApprovalWindow(ctx context.Context, user, host string) (time.Time, bool, error) {
	return time.Time{}, false, nil
}

func (m *mockApprovalStore) CreateApprovalRequest(ctx context.Context, req store.ApprovalRequest) error {
	return nil
}

func (m *mockApprovalStore) CreateApprovalWindow(ctx context.Context, user, host, grantedBy string, expiresAt time.Time) error {
	return nil
}

func TestHandleDecisionPathSplitting(t *testing.T) {
	backend := &mockApprovalStore{}
	m := &ApprovalManager{
		backend: backend,
	}

	tests := []struct {
		name           string
		path           string
		expectedStatus int
		expectedID     string
	}{
		{
			name:           "Valid approval",
			path:           "/api/approvals/ABCD/approve",
			expectedStatus: http.StatusNoContent,
			expectedID:     "ABCD",
		},
		{
			name:           "Valid denial",
			path:           "/api/approvals/EFGH/deny",
			expectedStatus: http.StatusNoContent,
			expectedID:     "EFGH",
		},
		{
			name:           "Invalid path - too short",
			path:           "/api/approvals/ABCD",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "Invalid path - too long",
			path:           "/api/approvals/ABCD/approve/extra",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "Unknown action",
			path:           "/api/approvals/ABCD/unknown",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "Not found",
			path:           "/api/approvals/NOTFOUND/approve",
			expectedStatus: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, tt.path, nil)
			w := httptest.NewRecorder()

			m.handleDecision(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, w.Code)
			}
			if tt.expectedID != "" && backend.deletedID != tt.expectedID {
				t.Errorf("expected deleted ID %s, got %s", tt.expectedID, backend.deletedID)
			}
		})
	}
}

func TestApprovalManager_Expiry(t *testing.T) {
	dir := t.TempDir()
	backend, err := store.New(store.Config{
		Backend:            "local",
		LogDir:             dir,
		ApprovalStorePath:  filepath.Join(dir, "approval-store.yaml"),
		ApprovalPolicyPath: filepath.Join(dir, "approval-policy.yaml"),
	})
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	defer backend.Close()

	// Write an approval policy with 100ms pending TTL
	policyYAML := "enabled: true\npending_ttl: 100ms\n"
	backend.SetConfig(context.Background(), "approval-policy.yaml", policyYAML)

	m := newApprovalManager(filepath.Join(dir, "approval-policy.yaml"), backend.(store.ApprovalStore))
	// Give reload loop a moment or just load directly.
	if err := m.loadPolicy(); err != nil {
		t.Fatalf("loadPolicy: %v", err)
	}

	// 1. Initial request with reason
	res1 := m.Check("alice", "host1", "root", "ls", nil, "justification")
	if res1.Result != ApprovalResultPending {
		t.Fatalf("expected ResultPending, got %v", res1.Result)
	}

	// Check it is listed
	pending := m.ListPending()
	if len(pending) != 1 {
		t.Fatalf("expected 1 pending request, got %d", len(pending))
	}

	// Wait for TTL to expire
	time.Sleep(150 * time.Millisecond)

	// Check pending is now empty (expired)
	pending = m.ListPending()
	if len(pending) != 0 {
		t.Errorf("expected 0 pending requests after expiry, got %d", len(pending))
	}
}

func TestApprovalManager_Concurrent(t *testing.T) {
	dir := t.TempDir()
	backend, err := store.New(store.Config{
		Backend:            "local",
		LogDir:             dir,
		ApprovalStorePath:  filepath.Join(dir, "approval-store.yaml"),
		ApprovalPolicyPath: filepath.Join(dir, "approval-policy.yaml"),
	})
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	defer backend.Close()

	policyYAML := "enabled: true\npending_ttl: 10s\n"
	backend.SetConfig(context.Background(), "approval-policy.yaml", policyYAML)

	m := newApprovalManager(filepath.Join(dir, "approval-policy.yaml"), backend.(store.ApprovalStore))
	if err := m.loadPolicy(); err != nil {
		t.Fatalf("loadPolicy: %v", err)
	}

	const workers = 10
	done := make(chan struct{})
	for i := 0; i < workers; i++ {
		go func(id int) {
			user := fmt.Sprintf("user-%d", id)
			m.Check(user, "host1", "root", "ls", nil, "reason")
			done <- struct{}{}
		}(i)
	}

	for i := 0; i < workers; i++ {
		<-done
	}

	pending := m.ListPending()
	if len(pending) != workers {
		t.Errorf("expected %d pending requests, got %d", workers, len(pending))
	}
}

func TestApprovalManager_OPARejection(t *testing.T) {
	backend := &mockApprovalStore{
		configs: make(map[string]string),
	}

	policyYAML := "enabled: true\n"
	backend.SetConfig(context.Background(), "approval-policy.yaml", policyYAML)

	m := newApprovalManager("approval-policy.yaml", backend)
	if err := m.loadPolicy(); err != nil {
		t.Fatalf("loadPolicy: %v", err)
	}

	// Set OPA policy: deny "attacker" user
	opaPolicy := policy.Policy{
		DefaultAction: "allow",
		Rules: []policy.Rule{
			{
				ID:       "deny-attacker",
				Users:    []string{"attacker"},
				Action:   "deny",
				HourFrom: -1,
				HourTo:   -1,
			},
		},
	}
	opaData, _ := json.Marshal(opaPolicy)
	backend.SetConfig(context.Background(), "jit-policy", string(opaData))
	m.loadOPAPolicy(context.Background())

	// Test check for regular user vs attacker
	res1 := m.Check("alice", "host1", "root", "ls", nil, "")
	if res1.Result != ApprovalResultAllow {
		t.Errorf("expected regular user to be allowed, got %v", res1.Result)
	}

	res2 := m.Check("attacker", "host1", "root", "ls", nil, "")
	if res2.Result != ApprovalResultDeny {
		t.Errorf("expected attacker to be denied, got %v", res2.Result)
	}
}
