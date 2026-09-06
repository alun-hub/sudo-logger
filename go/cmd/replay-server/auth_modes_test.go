package main

// Characterization tests for the middleware chain's identity/role resolution.
//
// These lock down what each authentication mode resolves to, so a change to
// basicAuthMiddleware or accessLogMiddleware cannot silently alter who a
// request is taken to be. The chain built here mirrors main.go exactly:
//
//	securityHeaders -> basicAuth -> accessLog -> handler
//
// Only the two inner layers matter for identity, so the test wires those.

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"sudo-logger/internal/store"
)

func basicHeader(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

func proxyAuthConfig(header string) store.AuthConfig {
	var c store.AuthConfig
	c.Source = "proxy"
	c.Proxy.UserHeader = header
	return c
}

// authModeCase is one deployment shape plus the credential a caller presents.
type authModeCase struct {
	name       string
	seed       func(t *testing.T)
	headers    map[string]string
	cookieUser string
	cookieRole Role
	trusted    string // trustedHeader argument to accessLogMiddleware

	wantStatus int
	wantViewer string
	wantRole   Role
	wantConfigWrite bool
}

func TestAuthModes_IdentityAndRole(t *testing.T) {
	cases := []authModeCase{
		{
			name: "bootstrap: no users at all",
			seed: func(t *testing.T) {},
			// Bootstrap intentionally grants admin so the first account can be
			// created; the viewer stays anonymous because nobody has logged in.
			wantStatus: http.StatusOK, wantViewer: "-", wantRole: RoleAdmin, wantConfigWrite: true,
		},
		{
			name: "open deployment: user without password, no credential",
			seed: seedPasswordlessAdmin,
			// No local passwords anywhere -> open deployment, anonymous viewer.
			wantStatus: http.StatusOK, wantViewer: "-", wantRole: RoleViewer, wantConfigWrite: false,
		},
		{
			name: "open deployment: user without password, wrong Basic Auth password",
			seed: seedPasswordlessAdmin,
			headers: map[string]string{"Authorization": basicHeader("alice", "wrong-password")},
			// Must be indistinguishable from the case above: an unverified
			// Authorization header must never confer a name, and with it a role.
			wantStatus: http.StatusOK, wantViewer: "-", wantRole: RoleViewer, wantConfigWrite: false,
		},
		{
			name: "local passwords: correct Basic Auth",
			seed: seedPasswordedAdmin,
			headers: map[string]string{"Authorization": basicHeader("alice", "Correct-Horse1!")},
			wantStatus: http.StatusOK, wantViewer: "alice", wantRole: RoleAdmin, wantConfigWrite: true,
		},
		{
			name: "local passwords: wrong Basic Auth",
			seed: seedPasswordedAdmin,
			headers: map[string]string{"Authorization": basicHeader("alice", "wrong-password")},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "local passwords: session cookie",
			seed: seedPasswordedAdmin,
			cookieUser: "alice", cookieRole: RoleAdmin,
			wantStatus: http.StatusOK, wantViewer: "alice", wantRole: RoleAdmin, wantConfigWrite: true,
		},
		{
			name: "proxy: trusted header present",
			seed: seedProxyAdmin,
			headers: map[string]string{"X-Forwarded-User": "bob"},
			trusted: "X-Forwarded-User",
			wantStatus: http.StatusOK, wantViewer: "bob", wantRole: RoleAdmin, wantConfigWrite: true,
		},
		{
			name: "proxy: trusted header missing fails closed",
			seed: seedProxyAdmin,
			trusted: "X-Forwarded-User",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "oidc: no session cookie",
			seed: func(t *testing.T) {
				seedPasswordedAdmin(t)
				if err := sessionStore.SetAuthConfig(t.Context(), store.AuthConfig{Source: "oidc"}); err != nil {
					t.Fatalf("SetAuthConfig: %v", err)
				}
			},
			wantStatus: http.StatusUnauthorized,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			initTestStore(t)
			tc.seed(t)

			var gotViewer string
			var gotRole Role
			var gotConfigWrite bool
			inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotViewer = viewerFromContext(r)
				gotRole = roleFromContext(r)
				gotConfigWrite = permsFromContext(r)[store.PermConfigWrite]
				w.WriteHeader(http.StatusOK)
			})
			h := basicAuthMiddleware(accessLogMiddleware(inner, tc.trusted))

			req := httptest.NewRequest(http.MethodGet, "/api/sessions", nil)
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			if tc.cookieUser != "" {
				sid := loginSessions.create(tc.cookieUser, tc.cookieRole, "")
				t.Cleanup(func() { loginSessions.delete(sid) })
				req.AddCookie(&http.Cookie{Name: "sudo_session", Value: sid})
			}

			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)

			if rr.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body: %s)", rr.Code, tc.wantStatus, rr.Body.String())
			}
			if tc.wantStatus != http.StatusOK {
				return // blocked before the handler; nothing else to assert
			}
			if gotViewer != tc.wantViewer {
				t.Errorf("viewer = %q, want %q", gotViewer, tc.wantViewer)
			}
			if gotRole != tc.wantRole {
				t.Errorf("role = %q, want %q", gotRole, tc.wantRole)
			}
			if gotConfigWrite != tc.wantConfigWrite {
				t.Errorf("PermConfigWrite = %v, want %v", gotConfigWrite, tc.wantConfigWrite)
			}
		})
	}
}

// seedPasswordlessAdmin reproduces what -admin-users does at startup
// (main.go): an admin account with no password hash at all.
func seedPasswordlessAdmin(t *testing.T) {
	t.Helper()
	err := sessionStore.UpsertUser(t.Context(), store.User{
		Username: "alice", Role: string(RoleAdmin), Source: "local",
	})
	if err != nil {
		t.Fatalf("UpsertUser: %v", err)
	}
}

func seedPasswordedAdmin(t *testing.T) {
	t.Helper()
	if err := sessionStore.UpsertUser(t.Context(), newUserWithPassword(t, "alice", "Correct-Horse1!", RoleAdmin)); err != nil {
		t.Fatalf("UpsertUser: %v", err)
	}
}

func seedProxyAdmin(t *testing.T) {
	t.Helper()
	err := sessionStore.UpsertUser(t.Context(), store.User{
		Username: "bob", Role: string(RoleAdmin), Source: "proxy",
	})
	if err != nil {
		t.Fatalf("UpsertUser: %v", err)
	}
	if err := sessionStore.SetAuthConfig(t.Context(), proxyAuthConfig("X-Forwarded-User")); err != nil {
		t.Fatalf("SetAuthConfig: %v", err)
	}
}

// TestAnonymousViewerGrantsFullReplay documents why an authenticated request
// must never fall back to the anonymous viewer: "-" is not "unknown, deny"
// but "open deployment, allow everything", so losing a caller's identity
// silently grants them every other user's sessions.
func TestAnonymousViewerGrantsFullReplay(t *testing.T) {
	initTestStore(t)
	resetTestCaches(t)

	ownSessionsOnly := map[store.Permission]bool{
		store.PermSessionsListOwn:   true,
		store.PermSessionsReplayOwn: true, // deliberately not ReplayAll
	}
	request := func(viewer string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/api/session/events?tsid=x", nil)
		ctx := context.WithValue(r.Context(), ctxViewer, viewer)
		ctx = context.WithValue(ctx, ctxRole, RoleViewer)
		ctx = context.WithValue(ctx, ctxPermissions, ownSessionsOnly)
		return r.WithContext(ctx)
	}

	if !enforceOwnership(httptest.NewRecorder(), request("-"), "someone-elses-session") {
		t.Error("anonymous viewer should be allowed (open-deployment semantics); " +
			"if this changed, the identity-loss risk it documents changed too")
	}
	if enforceOwnership(httptest.NewRecorder(), request("alice"), "someone-elses-session") {
		t.Error("named viewer without ReplayAll must not reach another user's session")
	}
}
