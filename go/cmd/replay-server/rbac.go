package main

import (
	"encoding/json"
	"net/http"
	"time"

	"sudo-logger/internal/store"
)

// stepUpTTL is how long a step-up re-authentication remains valid before the
// next sensitive action requires it again.
const stepUpTTL = 10 * time.Minute

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

// isBootstrapMode returns true if no users exist in the store and local auth is used,
// allowing the creation of the first admin account via the UI.
func isBootstrapMode(r *http.Request) bool {
	cfg, _ := sessionStore.GetAuthConfig(r.Context())
	if cfg.Source != "local" && cfg.Source != "" {
		return false
	}
	users, err := sessionStore.ListUsers(r.Context())
	return err == nil && len(users) == 0
}

// requireAdmin writes 403 and returns false if the request is not admin.
// Kept for the few paths that require full admin (bootstrap, user management).
func requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	return require(w, r, store.PermConfigWrite)
}

// requireStepUp writes 403 with a {"error":"stepup_required"} body and
// returns false if the caller hasn't recently re-proven their identity for a
// sensitive action (currently: sudoers/sandbox config push, see A-1/A-3 in
// review/14-a1-a3-plan.md §3.4).
//
// Proxy-mode auth is a documented no-op here: replay-server doesn't own the
// authentication decision in that mode (it trusts a header set by an
// upstream reverse proxy/SSO), so there is no independent local factor to
// re-check. Faking one would be security theater, not a real second factor.
// The diff/confirmation dialog (§3.3) is the only friction available for
// proxy-mode deployments.
func requireStepUp(w http.ResponseWriter, r *http.Request) bool {
	if isBootstrapMode(r) {
		return true
	}
	cfg, err := sessionStore.GetAuthConfig(r.Context())
	if err != nil {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return false
	}
	if cfg.Source == "proxy" {
		return true
	}
	if cfg.Source == "" || cfg.Source == "local" {
		// Mirror basicAuthMiddleware's "open deployment" detection: if no
		// local user has a password configured at all, there is no
		// independent credential to re-check, same rationale as proxy mode.
		hasLocalPasswords := *flagHTPasswd != "" // pragma: allowlist secret
		if !hasLocalPasswords {
			users, err := sessionStore.ListUsers(r.Context())
			if err != nil {
				http.Error(w, "service unavailable", http.StatusServiceUnavailable)
				return false
			}
			for _, u := range users {
				if u.PasswordHash != "" { // pragma: allowlist secret
					hasLocalPasswords = true // pragma: allowlist secret
					break
				}
			}
		}
		if !hasLocalPasswords {
			return true
		}
	}
	c, err := r.Cookie("sudo_session")
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	if loginSessions.stepUpValid(c.Value, stepUpTTL) {
		return true
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":       "stepup_required",
		"auth_source": cfg.Source,
	})
	return false
}

// requirePermissionsContained returns false and writes 403 if the caller does
// not hold every permission in perms. Prevents privilege escalation when
// creating/modifying roles or assigning roles to users.
func requirePermissionsContained(w http.ResponseWriter, r *http.Request, perms []store.Permission) bool {
	if isBootstrapMode(r) {
		return true
	}
	callerPerms := permsFromContext(r)
	for _, p := range perms {
		if !callerPerms[p] {
			http.Error(w, "cannot grant permission you do not hold: "+string(p), http.StatusForbidden)
			return false
		}
	}
	return true
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
