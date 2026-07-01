package main

// Tests for the local-login auth/session lifecycle: validatePassword,
// authenticate, loginSessionStore, handleLocalLogin, handleLogout.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"sudo-logger/internal/store"
)

// ── validatePassword ────────────────────────────────────────────────────────

func TestValidatePassword(t *testing.T) {
	tests := []struct {
		name    string
		pw      string
		wantErr string // substring expected in the error, "" means no error
	}{
		{"too short", "Ab1!", "at least 8 characters"},
		{"no uppercase", "abcdefg1!", "uppercase"},
		{"no lowercase", "ABCDEFG1!", "lowercase"},
		{"no number", "Abcdefgh!", "number"},
		{"no special char", "Abcdefg1", "special character"},
		{"valid password", "Abcdefg1!", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePassword(tt.pw)
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("validatePassword(%q) = %v, want nil", tt.pw, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("validatePassword(%q) = %v, want error containing %q", tt.pw, err, tt.wantErr)
			}
		})
	}
}

// ── authenticate ────────────────────────────────────────────────────────────

func newUserWithPassword(t *testing.T, username, password, role string) store.User {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt.GenerateFromPassword: %v", err)
	}
	return store.User{
		Username:     username,
		PasswordHash: string(hash),
		Role:         role,
		Source:       "local",
	}
}

func TestAuthenticate_ValidCredentials(t *testing.T) {
	initTestStore(t)
	u := newUserWithPassword(t, "alice", "correct-horse", RoleViewer)
	if err := sessionStore.UpsertUser(t.Context(), u); err != nil {
		t.Fatalf("UpsertUser: %v", err)
	}
	if !authenticate(t.Context(), "alice", "correct-horse") {
		t.Error("authenticate should succeed with correct credentials")
	}
}

func TestAuthenticate_WrongPassword(t *testing.T) {
	initTestStore(t)
	u := newUserWithPassword(t, "alice", "correct-horse", RoleViewer)
	if err := sessionStore.UpsertUser(t.Context(), u); err != nil {
		t.Fatalf("UpsertUser: %v", err)
	}
	if authenticate(t.Context(), "alice", "wrong-password") {
		t.Error("authenticate should fail with wrong password")
	}
}

func TestAuthenticate_UnknownUser(t *testing.T) {
	initTestStore(t)
	// Must still run bcrypt against dummyHash (not short-circuit) — this
	// test only asserts the outcome; timing behavior isn't asserted here.
	if authenticate(t.Context(), "nobody", "whatever") {
		t.Error("authenticate should fail for unknown user")
	}
}

func TestAuthenticate_NonLocalSource(t *testing.T) {
	initTestStore(t)
	u := newUserWithPassword(t, "oidc-user", "irrelevant", RoleViewer)
	u.Source = "oidc"
	if err := sessionStore.UpsertUser(t.Context(), u); err != nil {
		t.Fatalf("UpsertUser: %v", err)
	}
	if authenticate(t.Context(), "oidc-user", "irrelevant") {
		t.Error("authenticate should refuse non-local users even with a matching hash")
	}
}

// ── loginSessionStore ───────────────────────────────────────────────────────

func TestLoginSessionStore_CreateLookup(t *testing.T) {
	s := newLoginSessionStore()
	sid := s.create("alice", RoleAdmin, "")
	if sid == "" {
		t.Fatal("create returned empty session id")
	}
	sess := s.lookup(sid)
	if sess == nil {
		t.Fatal("lookup returned nil for a freshly created session")
		return
	}
	if sess.username != "alice" || sess.role != RoleAdmin {
		t.Errorf("lookup returned %+v, want username=alice role=admin", sess)
	}
}

func TestLoginSessionStore_LookupEmptySid(t *testing.T) {
	s := newLoginSessionStore()
	if s.lookup("") != nil {
		t.Error("lookup(\"\") should return nil")
	}
}

func TestLoginSessionStore_LookupUnknownSid(t *testing.T) {
	s := newLoginSessionStore()
	if s.lookup("does-not-exist") != nil {
		t.Error("lookup of unknown sid should return nil")
	}
}

func TestLoginSessionStore_Expiry(t *testing.T) {
	s := newLoginSessionStore()
	sid := s.create("alice", RoleViewer, "")
	// Force expiry by rewriting the stored session directly.
	s.mu.Lock()
	s.data[sid].expiresAt = time.Now().Add(-time.Second)
	s.mu.Unlock()
	if s.lookup(sid) != nil {
		t.Error("lookup should return nil for an expired session")
	}
	// lookup on an expired session should also delete it.
	s.mu.Lock()
	_, stillPresent := s.data[sid]
	s.mu.Unlock()
	if stillPresent {
		t.Error("expired session should be deleted by lookup")
	}
}

func TestLoginSessionStore_Delete(t *testing.T) {
	s := newLoginSessionStore()
	sid := s.create("alice", RoleViewer, "")
	s.delete(sid)
	if s.lookup(sid) != nil {
		t.Error("session should be gone after delete")
	}
	// Deleting again (or an unknown sid) must be a no-op, not a panic.
	s.delete(sid)
	s.delete("never-existed")
}

func TestLoginSessionStore_PurgeExpired(t *testing.T) {
	s := newLoginSessionStore()
	liveSid := s.create("alice", RoleViewer, "")
	expiredSid := s.create("bob", RoleViewer, "")
	s.mu.Lock()
	s.data[expiredSid].expiresAt = time.Now().Add(-time.Second)
	s.mu.Unlock()

	s.purgeExpired()

	s.mu.Lock()
	_, liveOK := s.data[liveSid]
	_, expiredOK := s.data[expiredSid]
	s.mu.Unlock()
	if !liveOK {
		t.Error("purgeExpired removed a non-expired session")
	}
	if expiredOK {
		t.Error("purgeExpired did not remove an expired session")
	}
}

// ── handleLocalLogin ────────────────────────────────────────────────────────

func TestHandleLocalLogin_WrongMethod(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/login", nil)
	rr := httptest.NewRecorder()
	handleLocalLogin(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET login: got %d, want 405", rr.Code)
	}
}

func TestHandleLocalLogin_InvalidJSON(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader("{bad"))
	rr := httptest.NewRecorder()
	handleLocalLogin(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("invalid JSON: got %d, want 400", rr.Code)
	}
}

func TestHandleLocalLogin_BadCredentials(t *testing.T) {
	initTestStore(t)
	body := `{"username":"nobody","password":"whatever"}`
	req := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(body))
	rr := httptest.NewRecorder()
	handleLocalLogin(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("bad credentials: got %d, want 401", rr.Code)
	}
}

func TestHandleLocalLogin_Success(t *testing.T) {
	initTestStore(t)
	u := newUserWithPassword(t, "alice", "correct-horse", RoleAdmin)
	if err := sessionStore.UpsertUser(t.Context(), u); err != nil {
		t.Fatalf("UpsertUser: %v", err)
	}

	body := `{"username":"alice","password":"correct-horse"}`
	req := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(body))
	rr := httptest.NewRecorder()
	handleLocalLogin(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("valid login: got %d, want 204; body: %s", rr.Code, rr.Body.String())
	}

	var cookie *http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == "sudo_session" {
			cookie = c
			break
		}
	}
	if cookie == nil {
		t.Fatal("login response did not set a sudo_session cookie")
		return
	}
	if !cookie.HttpOnly {
		t.Error("sudo_session cookie should be HttpOnly")
	}
	if cookie.SameSite != http.SameSiteLaxMode {
		t.Error("sudo_session cookie should be SameSite=Lax")
	}
	if cookie.Secure {
		t.Error("sudo_session cookie should not be Secure over plain HTTP")
	}
	if cookie.MaxAge != 3600*24 {
		t.Errorf("sudo_session cookie MaxAge = %d, want %d", cookie.MaxAge, 3600*24)
	}
	if loginSessions.lookup(cookie.Value) == nil {
		t.Error("login did not register a server-side session for the issued cookie")
	}
	loginSessions.delete(cookie.Value) // avoid bleeding into other tests
}

func TestHandleLocalLogin_SecureCookieOverForwardedHTTPS(t *testing.T) {
	initTestStore(t)
	u := newUserWithPassword(t, "alice", "correct-horse", RoleAdmin)
	if err := sessionStore.UpsertUser(t.Context(), u); err != nil {
		t.Fatalf("UpsertUser: %v", err)
	}

	body := `{"username":"alice","password":"correct-horse"}`
	req := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(body))
	req.Header.Set("X-Forwarded-Proto", "https")
	rr := httptest.NewRecorder()
	handleLocalLogin(rr, req)

	var cookie *http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == "sudo_session" {
			cookie = c
		}
	}
	if cookie == nil || !cookie.Secure {
		t.Error("sudo_session cookie should be Secure when X-Forwarded-Proto is https")
	}
	if cookie != nil {
		loginSessions.delete(cookie.Value)
	}
}

// ── handleLogout ────────────────────────────────────────────────────────────

func TestHandleLogout_ClearsSessionAndCookie(t *testing.T) {
	initTestStore(t)
	sid := loginSessions.create("alice", RoleViewer, "")

	req := httptest.NewRequest(http.MethodPost, "/api/logout", nil)
	req.AddCookie(&http.Cookie{Name: "sudo_session", Value: sid})
	rr := httptest.NewRecorder()
	handleLogout(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("logout: got %d, want 302", rr.Code)
	}
	if loginSessions.lookup(sid) != nil {
		t.Error("logout should delete the server-side session")
	}

	var cookie *http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == "sudo_session" {
			cookie = c
		}
	}
	if cookie == nil || cookie.MaxAge >= 0 {
		t.Error("logout should clear the sudo_session cookie (MaxAge < 0)")
	}
}

func TestHandleLogout_NoSessionCookie(t *testing.T) {
	initTestStore(t)
	req := httptest.NewRequest(http.MethodPost, "/api/logout", nil)
	rr := httptest.NewRecorder()
	handleLogout(rr, req)
	// Logging out without a session cookie should still redirect cleanly,
	// not error.
	if rr.Code != http.StatusFound {
		t.Errorf("logout without cookie: got %d, want 302", rr.Code)
	}
}
