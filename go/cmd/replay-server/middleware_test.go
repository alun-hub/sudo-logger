package main

// Tests for RBAC/permission enforcement (rbac.go) and request middleware
// (middleware.go).

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"sudo-logger/internal/store"
)

// ── resolveRoleFromGroups ────────────────────────────────────────────────────

func TestResolveRoleFromGroups(t *testing.T) {
	cfg := store.AuthConfig{
		GroupMappings: []store.GroupRoleMapping{
			{Group: "sudo-logger-operators", Role: "operator"},
		},
		AdminGroups: []string{"sudo-logger-admins"},
	}

	if got := resolveRoleFromGroups([]string{"sudo-logger-operators"}, cfg); got != "operator" {
		t.Errorf("group mapping: got %q, want operator", got)
	}
	// GroupMappings take priority over AdminGroups even when both would match.
	both := store.AuthConfig{
		GroupMappings: []store.GroupRoleMapping{{Group: "g1", Role: "operator"}},
		AdminGroups:   []string{"g1"},
	}
	if got := resolveRoleFromGroups([]string{"g1"}, both); got != "operator" {
		t.Errorf("explicit mapping should win over admin-group fallback: got %q", got)
	}
	if got := resolveRoleFromGroups([]string{"sudo-logger-admins"}, cfg); got != RoleAdmin {
		t.Errorf("admin group fallback: got %q, want admin", got)
	}
	if got := resolveRoleFromGroups([]string{"unrelated-group"}, cfg); got != RoleViewer {
		t.Errorf("no match: got %q, want viewer default", got)
	}
	if got := resolveRoleFromGroups(nil, cfg); got != RoleViewer {
		t.Errorf("no groups: got %q, want viewer default", got)
	}
}

// ── sanitizeForLog ───────────────────────────────────────────────────────────

func TestSanitizeForLog(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"/api/sessions", "/api/sessions"},
		{"/api/sessions\nX-Injected: evil", "/api/sessions_X-Injected: evil"},
		{"tab\there", "tab_here"},
		{"del\x7fchar", "del_char"},
	}
	for _, tt := range tests {
		if got := sanitizeForLog(tt.in); got != tt.want {
			t.Errorf("sanitizeForLog(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// ── securityHeadersMiddleware ────────────────────────────────────────────────

func TestSecurityHeadersMiddleware(t *testing.T) {
	h := securityHeadersMiddleware(newOKHandler())
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	want := map[string]string{
		"X-Frame-Options":            "DENY",
		"X-Content-Type-Options":     "nosniff",
		"Referrer-Policy":            "strict-origin-when-cross-origin",
		"Cross-Origin-Opener-Policy": "same-origin",
	}
	for k, v := range want {
		if got := rr.Header().Get(k); got != v {
			t.Errorf("header %s = %q, want %q", k, got, v)
		}
	}
	if rr.Header().Get("Content-Security-Policy") == "" {
		t.Error("Content-Security-Policy header not set")
	}
	if rr.Header().Get("Strict-Transport-Security") != "" {
		t.Error("HSTS should not be set for a plain HTTP request")
	}
}

func TestSecurityHeadersMiddleware_HSTSOverForwardedHTTPS(t *testing.T) {
	h := securityHeadersMiddleware(newOKHandler())
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Header().Get("Strict-Transport-Security") == "" {
		t.Error("HSTS should be set when X-Forwarded-Proto is https")
	}
}

// ── loggingResponseWriter ────────────────────────────────────────────────────

func TestLoggingResponseWriter_CapturesStatus(t *testing.T) {
	rec := httptest.NewRecorder()
	lrw := &loggingResponseWriter{ResponseWriter: rec, status: http.StatusOK}
	lrw.WriteHeader(http.StatusTeapot)

	if lrw.status != http.StatusTeapot {
		t.Errorf("captured status = %d, want %d", lrw.status, http.StatusTeapot)
	}
	if rec.Code != http.StatusTeapot {
		t.Errorf("underlying recorder status = %d, want %d", rec.Code, http.StatusTeapot)
	}
}

// ── require() / the 403 path ─────────────────────────────────────────────────

// TestRequire_ForbiddenWithoutPermission is the first test in the repo that
// exercises require() actually failing closed. Every previously-existing
// handler test runs against a store with zero users, which puts require()
// in "bootstrap mode" (always-allow) — so the 403 branch has never been
// covered. Seed a user first so bootstrap mode is off, then attach a
// low-privilege (viewer) role/permission set to the request context the
// same way accessLogMiddleware does, and confirm a PermConfigWrite-gated
// handler correctly refuses it.
func TestRequire_ForbiddenWithoutPermission(t *testing.T) {
	initTestStore(t)
	u := newUserWithPassword(t, "someone", "Correct-Horse1!", RoleViewer)
	if err := sessionStore.UpsertUser(t.Context(), u); err != nil {
		t.Fatalf("UpsertUser: %v", err)
	}

	req := httptest.NewRequest(http.MethodPut, "/api/retention", strings.NewReader(`{"enabled":true,"days":30}`))
	perms := resolveRolePerms(req, RoleViewer)
	ctx := context.WithValue(req.Context(), ctxRole, RoleViewer)
	ctx = context.WithValue(ctx, ctxPermissions, perms)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handlePutRetention(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("viewer without PermConfigWrite: got %d, want 403; body: %s", rr.Code, rr.Body.String())
	}
}

func TestRequire_AllowedWithPermission(t *testing.T) {
	initTestStore(t)
	u := newUserWithPassword(t, "someone", "Correct-Horse1!", RoleViewer)
	if err := sessionStore.UpsertUser(t.Context(), u); err != nil {
		t.Fatalf("UpsertUser: %v", err)
	}

	req := httptest.NewRequest(http.MethodPut, "/api/retention", strings.NewReader(`{"enabled":true,"days":30}`))
	ctx := context.WithValue(req.Context(), ctxRole, RoleAdmin)
	ctx = context.WithValue(ctx, ctxPermissions, builtinAdminPerms)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handlePutRetention(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("admin with PermConfigWrite: got %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
}

func TestRequire_BootstrapModeAlwaysAllows(t *testing.T) {
	// Zero users in the store → bootstrap mode → require() must pass even
	// with no permissions attached to the context, so the very first admin
	// can configure the system before any user exists.
	initTestStore(t)

	req := httptest.NewRequest(http.MethodPut, "/api/retention", strings.NewReader(`{"enabled":true,"days":30}`))
	rr := httptest.NewRecorder()
	handlePutRetention(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("bootstrap mode: got %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
}

// ── accessLogMiddleware ──────────────────────────────────────────────────────

func TestAccessLogMiddleware_ProxyHeaderWithGroups(t *testing.T) {
	initTestStore(t)
	cfg := store.AuthConfig{
		Source:      "proxy",
		AdminGroups: []string{"admins"},
	}
	cfg.Proxy.UserHeader = "X-Remote-User"
	cfg.Proxy.GroupsHeader = "X-Remote-Groups"
	if err := sessionStore.SetAuthConfig(t.Context(), cfg); err != nil {
		t.Fatalf("SetAuthConfig: %v", err)
	}
	// isBootstrapMode requires zero users AND source local/"" — seed a user
	// so we exercise the proxy-header role resolution instead of the
	// bootstrap-mode force-admin branch.
	u := newUserWithPassword(t, "proxied-user", "Correct-Horse1!", RoleViewer)
	if err := sessionStore.UpsertUser(t.Context(), u); err != nil {
		t.Fatalf("UpsertUser: %v", err)
	}

	var gotRole Role
	var gotViewer string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRole = roleFromContext(r)
		gotViewer = viewerFromContext(r)
		w.WriteHeader(http.StatusOK)
	})
	h := accessLogMiddleware(inner, "")

	req := httptest.NewRequest(http.MethodGet, "/api/sessions", nil)
	req.Header.Set("X-Remote-User", "proxied-user")
	req.Header.Set("X-Remote-Groups", "admins,other")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if gotViewer != "proxied-user" {
		t.Errorf("viewer = %q, want proxied-user", gotViewer)
	}
	if gotRole != RoleAdmin {
		t.Errorf("role = %q, want admin (from AdminGroups fallback)", gotRole)
	}
}

func TestAccessLogMiddleware_LocalSessionCookie(t *testing.T) {
	initTestStore(t)
	u := newUserWithPassword(t, "alice", "Correct-Horse1!", RoleAdmin)
	if err := sessionStore.UpsertUser(t.Context(), u); err != nil {
		t.Fatalf("UpsertUser: %v", err)
	}
	sid := loginSessions.create("alice", RoleAdmin, "")
	t.Cleanup(func() { loginSessions.delete(sid) })

	var gotViewer string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotViewer = viewerFromContext(r)
		w.WriteHeader(http.StatusOK)
	})
	h := accessLogMiddleware(inner, "")

	req := httptest.NewRequest(http.MethodGet, "/api/sessions", nil)
	req.AddCookie(&http.Cookie{Name: "sudo_session", Value: sid})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if gotViewer != "alice" {
		t.Errorf("viewer = %q, want alice", gotViewer)
	}
}

func TestAccessLogMiddleware_BootstrapForcesAdmin(t *testing.T) {
	initTestStore(t) // zero users → bootstrap mode

	var gotRole Role
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRole = roleFromContext(r)
		w.WriteHeader(http.StatusOK)
	})
	h := accessLogMiddleware(inner, "")

	req := httptest.NewRequest(http.MethodGet, "/api/sessions", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if gotRole != RoleAdmin {
		t.Errorf("bootstrap-mode role = %q, want admin", gotRole)
	}
}

// ── basicAuthMiddleware: /login in OIDC mode ────────────────────────────────

func TestBasicAuthMiddleware_LoginRedirectsToOIDCWhenNoSession(t *testing.T) {
	initTestStore(t)
	// Seed a user so isBootstrapMode is false and the OIDC branch is exercised.
	u := newUserWithPassword(t, "alice", "Correct-Horse1!", RoleAdmin)
	if err := sessionStore.UpsertUser(t.Context(), u); err != nil {
		t.Fatalf("UpsertUser: %v", err)
	}
	if err := sessionStore.SetAuthConfig(t.Context(), store.AuthConfig{Source: "oidc"}); err != nil {
		t.Fatalf("SetAuthConfig: %v", err)
	}

	h := basicAuthMiddleware(newOKHandler())
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("GET /login in oidc mode without session: got %d, want 302", rr.Code)
	}
	if loc := rr.Header().Get("Location"); loc != "/api/oidc/login" {
		t.Errorf("Location = %q, want /api/oidc/login", loc)
	}
}

func TestBasicAuthMiddleware_LoginServedDirectlyWithValidOIDCSession(t *testing.T) {
	initTestStore(t)
	u := newUserWithPassword(t, "alice", "Correct-Horse1!", RoleAdmin)
	if err := sessionStore.UpsertUser(t.Context(), u); err != nil {
		t.Fatalf("UpsertUser: %v", err)
	}
	if err := sessionStore.SetAuthConfig(t.Context(), store.AuthConfig{Source: "oidc"}); err != nil {
		t.Fatalf("SetAuthConfig: %v", err)
	}
	sid := loginSessions.create("alice", RoleAdmin, "")
	t.Cleanup(func() { loginSessions.delete(sid) })

	h := basicAuthMiddleware(newOKHandler())
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	req.AddCookie(&http.Cookie{Name: "sudo_session", Value: sid})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("GET /login with a valid oidc session: got %d, want 200 (serve SPA as-is)", rr.Code)
	}
}

func TestBasicAuthMiddleware_LoginPassesThroughInLocalMode(t *testing.T) {
	initTestStore(t)
	u := newUserWithPassword(t, "alice", "Correct-Horse1!", RoleAdmin)
	if err := sessionStore.UpsertUser(t.Context(), u); err != nil {
		t.Fatalf("UpsertUser: %v", err)
	}
	// No AuthConfig source set → defaults to local/"" — must not be redirected.

	h := basicAuthMiddleware(newOKHandler())
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("GET /login in local mode: got %d, want 200 (serve local login page)", rr.Code)
	}
}
