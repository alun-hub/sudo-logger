package main

import (
	"net/http"

	"sudo-logger/internal/store"
)

// Role is the name of a role assigned to a user or derived from group membership.
type Role = string

const (
	RoleViewer = "viewer"
	RoleAdmin  = "admin"
)

// builtinAdminPerms is the fixed permission set for the locked "admin" role.
var builtinAdminPerms = func() map[store.Permission]bool {
	m := make(map[store.Permission]bool, len(store.AllPermissions))
	for _, p := range store.AllPermissions {
		m[p] = true
	}
	return m
}()

// defaultViewerPerms is the permission set seeded for the "viewer" role on first start.
var defaultViewerPerms = []store.Permission{
	store.PermSessionsListOwn,
	store.PermSessionsReplayOwn,
}

const ctxRole ctxKey = 1
const ctxPermissions ctxKey = 2

// roleFromContext returns the role name stored in the request context.
func roleFromContext(r *http.Request) Role {
	if v, ok := r.Context().Value(ctxRole).(Role); ok && v != "" {
		return v
	}
	return RoleViewer
}

// permsFromContext returns the permission set injected by accessLogMiddleware.
func permsFromContext(r *http.Request) map[store.Permission]bool {
	if v, ok := r.Context().Value(ctxPermissions).(map[store.Permission]bool); ok {
		return v
	}
	return map[store.Permission]bool{}
}

// can reports whether the request has the given permission.
func can(r *http.Request, p store.Permission) bool {
	return permsFromContext(r)[p]
}

// require writes 403 and returns false if the request lacks the given permission.
func require(w http.ResponseWriter, r *http.Request, p store.Permission) bool {
	if can(r, p) || isBootstrapMode(r) {
		return true
	}
	http.Error(w, "forbidden: missing permission "+string(p), http.StatusForbidden)
	return false
}

// isAdmin is true when the request has all config-write permissions (admin equivalent).
func isAdmin(r *http.Request) bool {
	return can(r, store.PermConfigWrite)
}

// isBootstrapMode returns true if no users exist in the store, allowing the
// creation of the first admin account via the UI.
func isBootstrapMode(r *http.Request) bool {
	users, err := sessionStore.ListUsers(r.Context())
	return err == nil && len(users) == 0
}

// requireAdmin writes 403 and returns false if the request is not admin.
// Kept for the few paths that require full admin (bootstrap, user management).
func requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	return require(w, r, store.PermConfigWrite)
}

// resolveRolePerms looks up the permission set for a role name.
// The built-in "admin" role is synthesized in-memory; other roles are fetched
// from the store and cached per-request (cheap: one store lookup per request).
func resolveRolePerms(r *http.Request, roleName string) map[store.Permission]bool {
	if roleName == RoleAdmin {
		return builtinAdminPerms
	}
	def, err := sessionStore.GetRole(r.Context(), roleName)
	if err != nil || def.Name == "" {
		// Unknown role → fall back to default viewer permissions (fail-safe).
		m := make(map[store.Permission]bool, len(defaultViewerPerms))
		for _, p := range defaultViewerPerms {
			m[p] = true
		}
		return m
	}
	m := make(map[store.Permission]bool, len(def.Permissions))
	for _, p := range def.Permissions {
		m[p] = true
	}
	return m
}
