package main

// Tests for oidc.go. isSafeReturnPath covers the open-redirect guard for the
// OIDC step-up "return to where you were" flow. The handler tests below
// exercise the "OIDC not configured" error paths — a real OIDC round trip
// would need a mock identity provider serving discovery/token/JWKS
// endpoints, which is disproportionate for what these tests check (that
// misconfiguration fails safely, not the OIDC protocol itself).

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIsSafeReturnPath(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/config/sandbox", true},
		{"/policy/sudoers", true},
		{"/", true},
		{"", false},
		{"config/sandbox", false},             // missing leading slash
		{"//evil.com", false},                 // protocol-relative
		{"///evil.com", false},                // protocol-relative, extra slash
		{"/\\evil.com", false},                // backslash trick
		{"https://evil.com", false},           // absolute URL
		{"http://evil.com/x", false},          // absolute URL
		{"/redirect?x=http://evil.com", true}, // query string is fine, still same-origin path
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			if got := isSafeReturnPath(c.path); got != c.want {
				t.Errorf("isSafeReturnPath(%q) = %v, want %v", c.path, got, c.want)
			}
		})
	}
}

// ── generateState ────────────────────────────────────────────────────────────

func TestGenerateState(t *testing.T) {
	a := generateState()
	b := generateState()
	if a == "" || b == "" {
		t.Fatal("generateState returned an empty string")
	}
	if a == b {
		t.Error("generateState returned the same value twice in a row")
	}
	if len(a) < 32 {
		t.Errorf("generateState result too short to be a meaningful CSRF token: %q", a)
	}
}

// ── getOIDCConfig / handlers when OIDC is not configured ───────────────────

func TestGetOIDCConfig_NotConfigured(t *testing.T) {
	initTestStore(t) // AuthConfig defaults to Source=="" (not "oidc")
	req := httptest.NewRequest(http.MethodGet, "/api/oidc/login", nil)
	_, provider, verifier, oauthConf, err := getOIDCConfig(t.Context(), req)
	if err == nil {
		t.Fatal("getOIDCConfig should error when OIDC is not configured")
	}
	if provider != nil || verifier != nil || oauthConf != nil {
		t.Error("getOIDCConfig should return nil provider/verifier/config on error")
	}
}

func TestHandleOIDCLogin_NotConfigured(t *testing.T) {
	initTestStore(t)
	rr := httptest.NewRecorder()
	handleOIDCLogin(rr, httptest.NewRequest(http.MethodGet, "/api/oidc/login", nil))
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500, body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandleOIDCCallback_NotConfigured(t *testing.T) {
	initTestStore(t)
	rr := httptest.NewRecorder()
	handleOIDCCallback(rr, httptest.NewRequest(http.MethodGet, "/api/oidc/callback?state=x&code=y", nil))
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500, body=%s", rr.Code, rr.Body.String())
	}
}

// TestHandleOIDCLogout_NotConfigured verifies the fallback branch: when the
// provider can't be reached/configured, handleOIDCLogout still clears the
// local session cookie and redirects home instead of erroring out.
func TestHandleOIDCLogout_NotConfigured(t *testing.T) {
	initTestStore(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/oidc/logout", nil)
	req.AddCookie(&http.Cookie{Name: "sudo_session", Value: "whatever"})
	handleOIDCLogout(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302, body=%s", rr.Code, rr.Body.String())
	}
	if loc := rr.Header().Get("Location"); loc != "/" {
		t.Errorf("Location = %q, want /", loc)
	}
	var clearedSession bool
	for _, c := range rr.Result().Cookies() {
		if c.Name == "sudo_session" && c.MaxAge < 0 {
			clearedSession = true
		}
	}
	if !clearedSession {
		t.Error("handleOIDCLogout should clear the sudo_session cookie even when OIDC is unreachable")
	}
}
