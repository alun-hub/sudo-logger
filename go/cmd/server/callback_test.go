package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandleCallback(t *testing.T) {
	backend := &mockApprovalStore{}
	m := &ApprovalManager{
		backend: backend,
	}
	secret := "test-secret" // pragma: allowlist secret
	m.policy.Notifications.WebhookSecret = secret // pragma: allowlist secret

	reqID := "ABCD"
	action := "approve"
	token := m.generateActionToken(reqID, action, secret)

	tests := []struct {
		name           string
		payload        map[string]interface{}
		expectedStatus int
		expectedMsg    string
	}{
		{
			name: "Valid approval",
			payload: map[string]interface{}{
				"user_name": "admin",
				"context": map[string]string{
					"request_id": reqID,
					"action":     action,
					"token":      token,
				},
			},
			expectedStatus: http.StatusOK,
			expectedMsg:    "Request ABCD approved by @admin.",
		},
		{
			name: "Valid denial",
			payload: map[string]interface{}{
				"user_name": "admin",
				"context": map[string]string{
					"request_id": "EFGH",
					"action":     "deny",
					"token":      m.generateActionToken("EFGH", "deny", secret),
				},
			},
			expectedStatus: http.StatusOK,
			expectedMsg:    "Request EFGH denied by @admin.",
		},
		{
			name: "Unauthorized - wrong token",
			payload: map[string]interface{}{
				"user_name": "admin",
				"context": map[string]string{
					"request_id": reqID,
					"action":     action,
					"token":      "wrong-token",
				},
			},
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name: "Invalid payload",
			payload: map[string]interface{}{
				"user_name": "admin",
				"context":   "not-a-map",
			},
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(tt.payload)
			req := httptest.NewRequest(http.MethodPost, "/api/approvals/callback", bytes.NewReader(body))
			w := httptest.NewRecorder()

			m.handleCallback(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			if tt.expectedMsg != "" {
				var resp struct {
					Update struct {
						Message string `json:"message"`
					} `json:"update"`
				}
				if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
					t.Fatalf("decode response: %v", err)
				}
				if resp.Update.Message != tt.expectedMsg {
					t.Errorf("expected message %q, got %q", tt.expectedMsg, resp.Update.Message)
				}
			}
		})
	}
}
