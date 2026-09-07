package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHandleCallback(t *testing.T) {
	backend := &mockApprovalStore{}
	m := &ApprovalManager{
		backend: backend,
	}
	secret := "test-secret"                       // pragma: allowlist secret
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

// capturingStore records the decidedBy string that reaches the approval
// window, which is what ends up in the audit record.
type capturingStore struct {
	mockApprovalStore
	lastDecidedBy string
}

func (c *capturingStore) CreateApprovalWindow(ctx context.Context, user, host, grantedBy string, expiresAt time.Time) error {
	c.lastDecidedBy = grantedBy
	return nil
}

// callbackWithName drives handleCallback with a validly-signed approve action
// and the given user_name, and returns the store so the caller can inspect the
// attribution that was recorded.
func callbackWithName(t *testing.T, userName string) (*capturingStore, *http.Request) {
	t.Helper()
	backend := &capturingStore{}
	m := &ApprovalManager{backend: backend}
	const secret = "test-secret"                  // pragma: allowlist secret
	m.policy.Notifications.WebhookSecret = secret // pragma: allowlist secret

	const reqID, action = "ABCD", "approve"
	body, err := json.Marshal(map[string]interface{}{
		"user_name": userName,
		"context": map[string]string{
			"request_id": reqID,
			"action":     action,
			"token":      m.generateActionToken(reqID, action, secret),
		},
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/approvals/callback", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	m.handleCallback(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("callback status %d: %s", rr.Code, rr.Body.String())
	}
	return backend, req
}

// The action token authorises a decision on a request; it does not identify
// who presents it, and it cannot -- the token is minted when the message is
// posted, before anyone has clicked. user_name therefore arrives unsigned in
// the callback body, and the audit record has to say so.
func TestHandleCallback_AttributionIsMarkedUnverified(t *testing.T) {
	m, req := callbackWithName(t, "mallory")
	if req == nil {
		t.Fatal("callback did not reach Approve")
	}
	if !strings.Contains(m.lastDecidedBy, "not verified") {
		t.Errorf("decidedBy = %q; must record that the name is unverified", m.lastDecidedBy)
	}
	if !strings.Contains(m.lastDecidedBy, "mallory") {
		t.Errorf("decidedBy = %q; should still carry the reported name", m.lastDecidedBy)
	}
}

// A newline in user_name would otherwise forge a second line in the approval
// log, which is the record of who approved what.
func TestHandleCallback_UserNameCannotForgeLogLines(t *testing.T) {
	m, _ := callbackWithName(t, "alice\napproval: request X approved by root")
	if strings.ContainsAny(m.lastDecidedBy, "\n\r") {
		t.Errorf("control characters survived into the audit record: %q", m.lastDecidedBy)
	}
}

func TestHandleCallback_OverlongUserNameIsBounded(t *testing.T) {
	m, _ := callbackWithName(t, strings.Repeat("A", 500))
	if len(m.lastDecidedBy) > 128 {
		t.Errorf("decidedBy grew to %d bytes; unbounded attacker-supplied text",
			len(m.lastDecidedBy))
	}
}
