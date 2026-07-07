package main

// Tests for requireStepUp (go/cmd/replay-server/rbac.go).

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"sudo-logger/internal/store"
)

func stepUpGateReq(cookieValue string) *http.Request {
	req := httptest.NewRequest(http.MethodPut, "/api/sudoers/config", nil)
	if cookieValue != "" {
		req.AddCookie(&http.Cookie{Name: "sudo_session", Value: cookieValue})
	}
	return req
}

func TestRequireStepUp_BootstrapMode(t *testing.T) {
	initTestStore(t) // no users at all -> bootstrap mode
	rr := httptest.NewRecorder()
	if !requireStepUp(rr, stepUpGateReq("")) {
		t.Errorf("bootstrap mode should bypass step-up, got %d", rr.Code)
	}
}

func TestRequireStepUp_ProxyMode(t *testing.T) {
	initTestStore(t)
	// A user must exist for isBootstrapMode to be false.
	u := newUserWithPassword(t, "alice", "correct-horse", RoleAdmin)
	if err := sessionStore.UpsertUser(t.Context(), u); err != nil {
		t.Fatalf("UpsertUser: %v", err)
	}
	if err := sessionStore.SetAuthConfig(t.Context(), store.AuthConfig{Source: "proxy"}); err != nil {
		t.Fatalf("SetAuthConfig: %v", err)
	}
	rr := httptest.NewRecorder()
	if !requireStepUp(rr, stepUpGateReq("")) {
		t.Errorf("proxy mode should always no-op past step-up, got %d", rr.Code)
	}
}

func TestRequireStepUp_OpenDeployment(t *testing.T) {
	initTestStore(t)
	// A user exists (so not bootstrap mode) but has no password (so this is
	// an "open deployment" -- no independent credential to re-check).
	if err := sessionStore.UpsertUser(t.Context(), store.User{Username: "alice", Source: "oidc", Role: RoleAdmin}); err != nil {
		t.Fatalf("UpsertUser: %v", err)
	}
	rr := httptest.NewRecorder()
	if !requireStepUp(rr, stepUpGateReq("")) {
		t.Errorf("open deployment (no local passwords) should no-op past step-up, got %d", rr.Code)
	}
}

func TestRequireStepUp_NoSessionCookie(t *testing.T) {
	initTestStore(t)
	u := newUserWithPassword(t, "alice", "correct-horse", RoleAdmin)
	if err := sessionStore.UpsertUser(t.Context(), u); err != nil {
		t.Fatalf("UpsertUser: %v", err)
	}
	rr := httptest.NewRecorder()
	if requireStepUp(rr, stepUpGateReq("")) {
		t.Fatal("missing session cookie should not pass requireStepUp")
	}
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("got %d, want 401", rr.Code)
	}
}

func TestRequireStepUp_NotYetSteppedUp(t *testing.T) {
	initTestStore(t)
	u := newUserWithPassword(t, "alice", "correct-horse", RoleAdmin)
	if err := sessionStore.UpsertUser(t.Context(), u); err != nil {
		t.Fatalf("UpsertUser: %v", err)
	}
	sid := loginSessions.create("alice", RoleAdmin, "")
	defer loginSessions.delete(sid)

	rr := httptest.NewRecorder()
	if requireStepUp(rr, stepUpGateReq(sid)) {
		t.Fatal("a session with no prior step-up should not pass requireStepUp")
	}
	if rr.Code != http.StatusForbidden {
		t.Errorf("got %d, want 403", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "stepup_required") {
		t.Errorf("expected stepup_required in body, got: %s", rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"auth_source":"local"`) {
		t.Errorf("expected auth_source=local in body, got: %s", rr.Body.String())
	}
}

func TestRequireStepUp_ValidAfterMarkStepUp(t *testing.T) {
	initTestStore(t)
	u := newUserWithPassword(t, "alice", "correct-horse", RoleAdmin)
	if err := sessionStore.UpsertUser(t.Context(), u); err != nil {
		t.Fatalf("UpsertUser: %v", err)
	}
	sid := loginSessions.create("alice", RoleAdmin, "")
	defer loginSessions.delete(sid)
	loginSessions.markStepUp(sid)

	rr := httptest.NewRecorder()
	if !requireStepUp(rr, stepUpGateReq(sid)) {
		t.Errorf("a recently step-up-verified session should pass requireStepUp, got %d body=%s", rr.Code, rr.Body.String())
	}
}
