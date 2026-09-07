package main

// Per-request snapshot of the two store reads the authentication path depends
// on: the auth config and the user list.
//
// Both are consulted repeatedly while a single request is being authenticated:
// basicAuthMiddleware reads the config, asks isBootstrapMode (which reads the
// config and the user list again), and may scan the users once more for local
// passwords; accessLogMiddleware then reads the config and calls
// isBootstrapMode a second time. In distributed mode each of those is a
// database round trip, and every one of them happens before the handler runs.
//
// Taking them once at the start of the request and reading from that is safe
// because nothing depends on either value changing mid-request: every
// isBootstrapMode call site runs before the UpsertUser that could change the
// answer. Caching beyond the request would not be safe -- auth config and
// users are edited through the admin UI and must take effect immediately, or
// a removed user would keep getting in.

import (
	"context"
	"net/http"

	"sudo-logger/internal/store"
)

const ctxAuthSnapshot ctxKey = 4

type authSnapshot struct {
	cfg      store.AuthConfig
	cfgErr   error
	users    []store.User
	usersErr error
}

// newAuthSnapshot performs both reads once.
func newAuthSnapshot(r *http.Request) *authSnapshot {
	s := &authSnapshot{}
	s.cfg, s.cfgErr = sessionStore.GetAuthConfig(r.Context())
	s.users, s.usersErr = sessionStore.ListUsers(r.Context())
	return s
}

// withAuthSnapshot attaches a freshly taken snapshot to r.
func withAuthSnapshot(r *http.Request) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), ctxAuthSnapshot, newAuthSnapshot(r)))
}

// authSnapshotFor returns the snapshot taken for this request, taking one now
// if there is none. The fallback keeps handlers callable on their own, which
// the tests rely on, at the cost of the reads this type exists to avoid.
func authSnapshotFor(r *http.Request) *authSnapshot {
	if s, ok := r.Context().Value(ctxAuthSnapshot).(*authSnapshot); ok && s != nil {
		return s
	}
	return newAuthSnapshot(r)
}

// authConfigFor returns the request's auth config, preserving GetAuthConfig's
// error so callers can keep failing closed on a store outage.
func authConfigFor(r *http.Request) (store.AuthConfig, error) {
	s := authSnapshotFor(r)
	return s.cfg, s.cfgErr
}
