package main

import (
	"net/http"
)

// Role represents an access level in the replay UI.
type Role string

const (
	RoleViewer Role = "viewer" // can list and replay own sessions only
	RoleAdmin  Role = "admin"  // can list and replay all sessions, access audit log, perform approvals
)

const ctxRole ctxKey = 1

// roleFromContext returns the role stored in the request context.
// Defaults to RoleViewer if none was set (open/unauthenticated deployments).
func roleFromContext(r *http.Request) Role {
	if v, ok := r.Context().Value(ctxRole).(Role); ok {
		return v
	}
	return RoleViewer
}

// isAdmin reports whether the request carries admin privileges.
func isAdmin(r *http.Request) bool {
	return roleFromContext(r) == RoleAdmin
}

// requireAdmin writes 403 and returns false if the request is not admin.
func requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	if !isAdmin(r) {
		http.Error(w, "forbidden: admin role required", http.StatusForbidden)
		return false
	}
	return true
}
