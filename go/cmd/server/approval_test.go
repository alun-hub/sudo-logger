package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"sudo-logger/internal/store"
)

type mockApprovalStore struct {
	store.ApprovalStore
	deletedID string
}

func (m *mockApprovalStore) DeleteApprovalRequest(ctx context.Context, id string) (*store.ApprovalRequest, error) {
	m.deletedID = id
	if id == "NOTFOUND" {
		return nil, nil
	}
	return &store.ApprovalRequest{ID: id, User: "alice", Host: "host1"}, nil
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
