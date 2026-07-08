package main

// Tests for requireStepUp (go/cmd/replay-server/rbac.go).

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"sudo-logger/internal/store"
)

func stepUpGateReq(cookieValue string) *http.Request {
	req := httptest.NewRequest(http.MethodPut, "/api/sudoers/config", nil)
	if cookieValue != "" {
		req.AddCookie(&http.Cookie{Name: "sudo_session", Value: cookieValue})
	}
	return req
}

// ── isAdmin / requireAdmin ─────────────────────────────────────────────────────

func TestIsAdmin(t *testing.T) {
	if !isAdmin(adminReq(http.MethodGet, "/api/users", "")) {
		t.Error("isAdmin(admin request) = false, want true")
	}
	if isAdmin(viewerReq(http.MethodGet, "/api/users", "")) {
		t.Error("isAdmin(viewer request) = true, want false")
	}
}

func TestRequireAdmin(t *testing.T) {
	initTestStore(t)
	u := newUserWithPassword(t, "someone", "Correct-Horse1!", RoleViewer)
	if err := sessionStore.UpsertUser(t.Context(), u); err != nil {
		t.Fatalf("UpsertUser: %v", err)
	}

	rr := httptest.NewRecorder()
	if requireAdmin(rr, viewerReq(http.MethodGet, "/api/users", "")) {
		t.Error("requireAdmin(viewer) = true, want false")
	}
	if rr.Code != http.StatusForbidden {
		t.Errorf("requireAdmin(viewer) status = %d, want 403", rr.Code)
	}

	rr2 := httptest.NewRecorder()
	if !requireAdmin(rr2, adminReq(http.MethodGet, "/api/users", "")) {
		t.Error("requireAdmin(admin) = false, want true")
	}
}

// ── requirePermissionsContained ────────────────────────────────────────────────

func TestRequirePermissionsContained(t *testing.T) {
	initTestStore(t)
	u := newUserWithPassword(t, "someone", "Correct-Horse1!", RoleViewer)
	if err := sessionStore.UpsertUser(t.Context(), u); err != nil {
		t.Fatalf("UpsertUser: %v", err)
	}

	rr := httptest.NewRecorder()
	req := viewerReq(http.MethodPut, "/api/roles/custom", "")
	if requirePermissionsContained(rr, req, []store.Permission{store.PermConfigWrite}) {
		t.Error("requirePermissionsContained should refuse granting a permission the viewer caller lacks")
	}
	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rr.Code)
	}

	rr2 := httptest.NewRecorder()
	req2 := viewerReq(http.MethodPut, "/api/roles/custom", "")
	if !requirePermissionsContained(rr2, req2, []store.Permission{store.PermSessionsListOwn}) {
		t.Error("requirePermissionsContained should allow granting a permission the caller already holds")
	}
}

func TestRequirePermissionsContained_BootstrapModeAlwaysAllows(t *testing.T) {
	initTestStore(t) // zero users -> bootstrap mode
	rr := httptest.NewRecorder()
	req := stepUpGateReq("")
	if !requirePermissionsContained(rr, req, []store.Permission{store.PermConfigWrite}) {
		t.Error("requirePermissionsContained should always allow in bootstrap mode")
	}
}

func TestRequireStepUp_BootstrapMode(t *testing.T) {
	initTestStore(t) // no users at all -> bootstrap mode
	rr := httptest.NewRecorder()
	if !requireStepUp(rr, stepUpGateReq("")) {
		t.Errorf("bootstrap mode should bypass step-up, got %d", rr.Code)
	}
}

// TestIsBootstrapMode_HTPasswdConfiguredIsNotBootstrap reproduces a bug found
// via the system-test suite: a deployment using the legacy -htpasswd flag,
// with zero users created through the newer store-based user system, was
// treated as "bootstrap mode" (no auth required, requests served as admin)
// even though -htpasswd was explicitly configured. ListUsers()==0 there
// means "no modern store user yet", not "no auth configured at all".
func TestIsBootstrapMode_HTPasswdConfiguredIsNotBootstrap(t *testing.T) {
	initTestStore(t) // no store users at all

	old := *flagHTPasswd // pragma: allowlist secret
	*flagHTPasswd = "/tmp/does-not-need-to-exist-for-this-check.htpasswd" // pragma: allowlist secret
	defer func() { *flagHTPasswd = old }() // pragma: allowlist secret

	req := httptest.NewRequest(http.MethodGet, "/api/sessions", nil)
	if isBootstrapMode(req) {
		t.Error("isBootstrapMode must be false when -htpasswd is configured, even with zero store users")
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

func TestRequireStepUp_CustomTTL(t *testing.T) {
	initTestStore(t)
	u := newUserWithPassword(t, "alice", "correct-horse", RoleAdmin)
	if err := sessionStore.UpsertUser(t.Context(), u); err != nil {
		t.Fatalf("UpsertUser: %v", err)
	}
	if err := sessionStore.SetAuthConfig(t.Context(), store.AuthConfig{Source: "local", StepUpTTLMinutes: 1}); err != nil {
		t.Fatalf("SetAuthConfig: %v", err)
	}
	sid := loginSessions.create("alice", RoleAdmin, "")
	defer loginSessions.delete(sid)

	// Backdate the step-up to 2 minutes ago -- within the old 10-minute
	// default, but past a configured 1-minute TTL.
	loginSessions.markStepUp(sid)
	loginSessions.mu.Lock()
	loginSessions.data[sid].stepUpAt = time.Now().Add(-2 * time.Minute)
	loginSessions.mu.Unlock()

	rr := httptest.NewRecorder()
	if requireStepUp(rr, stepUpGateReq(sid)) {
		t.Error("a step-up older than the configured 1-minute TTL should require re-auth again")
	}
	if rr.Code != http.StatusForbidden {
		t.Errorf("got %d, want 403", rr.Code)
	}
}

func TestRequireStepUp_ZeroTTLUsesDefault(t *testing.T) {
	initTestStore(t)
	u := newUserWithPassword(t, "alice", "correct-horse", RoleAdmin)
	if err := sessionStore.UpsertUser(t.Context(), u); err != nil {
		t.Fatalf("UpsertUser: %v", err)
	}
	// StepUpTTLMinutes left at its zero value -- must fall back to the
	// 10-minute default, not treat 0 as "always expired".
	if err := sessionStore.SetAuthConfig(t.Context(), store.AuthConfig{Source: "local"}); err != nil {
		t.Fatalf("SetAuthConfig: %v", err)
	}
	sid := loginSessions.create("alice", RoleAdmin, "")
	defer loginSessions.delete(sid)
	loginSessions.markStepUp(sid)

	rr := httptest.NewRecorder()
	if !requireStepUp(rr, stepUpGateReq(sid)) {
		t.Errorf("zero StepUpTTLMinutes should fall back to the default TTL, got %d body=%s", rr.Code, rr.Body.String())
	}
}
