package main

// The point of authSnapshot is the number of store round trips a single
// request makes, so the test counts them rather than asserting the shape of
// the code.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"sudo-logger/internal/store"
)

// countingStore wraps a real store and counts the two reads the auth path
// makes on every request.
type countingStore struct {
	store.SessionStore
	authConfigReads atomic.Int64
	listUsersReads  atomic.Int64
}

func (c *countingStore) GetAuthConfig(ctx context.Context) (store.AuthConfig, error) {
	c.authConfigReads.Add(1)
	return c.SessionStore.GetAuthConfig(ctx)
}

func (c *countingStore) ListUsers(ctx context.Context) ([]store.User, error) {
	c.listUsersReads.Add(1)
	return c.SessionStore.ListUsers(ctx)
}

func TestAuthSnapshot_OneReadOfEachPerRequest(t *testing.T) {
	initTestStore(t)
	if err := sessionStore.UpsertUser(t.Context(),
		newUserWithPassword(t, "alice", "Correct-Horse1!", RoleAdmin)); err != nil {
		t.Fatalf("UpsertUser: %v", err)
	}

	counting := &countingStore{SessionStore: sessionStore}
	real := sessionStore
	sessionStore = counting
	t.Cleanup(func() { sessionStore = real })

	h := basicAuthMiddleware(identityMiddleware(accessLogMiddleware(newOKHandler()), ""))
	req := httptest.NewRequest(http.MethodGet, "/api/sessions", nil)
	req.SetBasicAuth("alice", "Correct-Horse1!")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status %d, want 200: %s", rr.Code, rr.Body.String())
	}
	if got := counting.authConfigReads.Load(); got != 1 {
		t.Errorf("GetAuthConfig called %d times per request, want 1", got)
	}
	if got := counting.listUsersReads.Load(); got != 1 {
		t.Errorf("ListUsers called %d times per request, want 1", got)
	}
}

// The snapshot must not outlive the request: auth config and users are edited
// through the admin UI and have to take effect on the very next request, or a
// removed user would keep getting in.
func TestAuthSnapshot_DoesNotPersistAcrossRequests(t *testing.T) {
	initTestStore(t)
	counting := &countingStore{SessionStore: sessionStore}
	real := sessionStore
	sessionStore = counting
	t.Cleanup(func() { sessionStore = real })

	h := basicAuthMiddleware(identityMiddleware(accessLogMiddleware(newOKHandler()), ""))
	for i := 0; i < 3; i++ {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/sessions", nil))
	}

	if got := counting.authConfigReads.Load(); got != 3 {
		t.Errorf("GetAuthConfig called %d times over 3 requests, want 3 — "+
			"a snapshot leaked between requests", got)
	}
}
