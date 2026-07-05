package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"sudo-logger/internal/store"
)

// BlockedUser describes a single blocked user entry in blocked-users.yaml.
type BlockedUser struct {
	Username  string   `yaml:"username"   json:"username"`
	Hosts     []string `yaml:"hosts"      json:"hosts"`
	Reason    string   `yaml:"reason"     json:"reason"`
	BlockedAt int64    `yaml:"blocked_at" json:"blocked_at"`
}

// BlockedUsersConfig is the top-level structure of blocked-users.yaml.
type BlockedUsersConfig struct {
	BlockMessage string        `yaml:"block_message" json:"block_message"`
	Users        []BlockedUser `yaml:"users"         json:"users"`
}

// WhitelistedUser describes a single whitelisted user entry in whitelisted-users.yaml.
type WhitelistedUser struct {
	Username string   `yaml:"username" json:"username"`
	Hosts    []string `yaml:"hosts"    json:"hosts"`
	Reason   string   `yaml:"reason"   json:"reason"`
}

// WhitelistedUsersConfig is the top-level structure of whitelisted-users.yaml.
type WhitelistedUsersConfig struct {
	Users []WhitelistedUser `yaml:"users" json:"users"`
}

// ── Blocked users API ─────────────────────────────────────────────────────────

func handleGetBlockedUsers(w http.ResponseWriter, r *http.Request) {
	if !require(w, r, store.PermConfigRead) {
		return
	}
	policy, err := sessionStore.GetBlockedPolicy(r.Context())
	if err != nil {
		http.Error(w, "read config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	cfg := BlockedUsersConfig{BlockMessage: policy.BlockMessage}
	for _, u := range policy.Users {
		hosts := u.Hosts
		if hosts == nil {
			hosts = []string{}
		}
		cfg.Users = append(cfg.Users, BlockedUser{
			Username:  u.Username,
			Hosts:     hosts,
			Reason:    u.Reason,
			BlockedAt: u.BlockedAt,
		})
	}
	if cfg.Users == nil {
		cfg.Users = []BlockedUser{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"path":   *flagBlockedUsers,
		"config": cfg,
	})
}

func handlePutBlockedUsers(w http.ResponseWriter, r *http.Request) {
	if !require(w, r, store.PermConfigWrite) {
		return
	}
	var body struct {
		Config BlockedUsersConfig `json:"config"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	for i, u := range body.Config.Users {
		if u.Username == "" {
			http.Error(w, fmt.Sprintf("user[%d]: username required", i), http.StatusBadRequest)
			return
		}
	}
	if body.Config.Users == nil {
		body.Config.Users = []BlockedUser{}
	}
	policy := store.BlockedPolicy{BlockMessage: body.Config.BlockMessage}
	for _, u := range body.Config.Users {
		hosts := u.Hosts
		if hosts == nil {
			hosts = []string{}
		}
		policy.Users = append(policy.Users, store.BlockedUserEntry{
			Username:  u.Username,
			Hosts:     hosts,
			Reason:    u.Reason,
			BlockedAt: u.BlockedAt,
		})
	}
	if err := sessionStore.SaveBlockedPolicy(r.Context(), policy); err != nil {
		http.Error(w, "write failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	log.Printf("blocked-users: config updated via GUI (%d blocked users)", len(body.Config.Users))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

func handleGetWhitelistedUsers(w http.ResponseWriter, r *http.Request) {
	if !require(w, r, store.PermConfigRead) {
		return
	}
	policy, err := sessionStore.GetWhitelistPolicy(r.Context())
	if err != nil {
		http.Error(w, "read config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	cfg := WhitelistedUsersConfig{}
	for _, u := range policy.Users {
		hosts := u.Hosts
		if hosts == nil {
			hosts = []string{}
		}
		cfg.Users = append(cfg.Users, WhitelistedUser{
			Username: u.Username,
			Hosts:    hosts,
			Reason:   u.Reason,
		})
	}
	if cfg.Users == nil {
		cfg.Users = []WhitelistedUser{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"path":   *flagWhitelistedUsers,
		"config": cfg,
	})
}

func handlePutWhitelistedUsers(w http.ResponseWriter, r *http.Request) {
	if !require(w, r, store.PermConfigWrite) {
		return
	}
	var body struct {
		Config WhitelistedUsersConfig `json:"config"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	for i, u := range body.Config.Users {
		if u.Username == "" {
			http.Error(w, fmt.Sprintf("user[%d]: username required", i), http.StatusBadRequest)
			return
		}
	}
	if body.Config.Users == nil {
		body.Config.Users = []WhitelistedUser{}
	}
	var policy store.WhitelistPolicy
	for _, u := range body.Config.Users {
		hosts := u.Hosts
		if hosts == nil {
			hosts = []string{}
		}
		policy.Users = append(policy.Users, store.WhitelistedUserEntry{
			Username: u.Username,
			Hosts:    hosts,
			Reason:   u.Reason,
		})
	}
	if err := sessionStore.SaveWhitelistPolicy(r.Context(), policy); err != nil {
		http.Error(w, "write failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	log.Printf("whitelisted-users: config updated via GUI (%d whitelisted users)", len(body.Config.Users))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

func handleGetUsers(w http.ResponseWriter, r *http.Request) {
	if !require(w, r, store.PermUsersRead) {
		return
	}
	users, err := sessionStore.ListUsers(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}

func handlePutUser(w http.ResponseWriter, r *http.Request) {
	log.Printf("PUT /api/users called")
	// Bootstrap exception: allow creating the first user without admin role.
	if !isBootstrapMode(r) && !require(w, r, store.PermUsersWrite) {
		log.Printf("PUT /api/users: require failed (bootstrap=%v)", isBootstrapMode(r))
		return
	}

	var input struct {
		store.User
		Password string `json:"password_hash"` // We use password_hash field name from UI
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		log.Printf("PUT /api/users: decode failed: %v", err)
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	u := input.User
	log.Printf("PUT /api/users: user=%q, role=%s, source=%s, has_pass=%v", u.Username, u.Role, u.Source, input.Password != "")

	if u.Username == "" {
		http.Error(w, "username required", http.StatusBadRequest)
		return
	}

	// Hash password if provided
	if input.Password != "" {
		log.Printf("PUT /api/users: validating password for %q", u.Username)
		if err := validatePassword(input.Password); err != nil {
			log.Printf("PUT /api/users: password validation failed for %q: %v", u.Username, err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		log.Printf("PUT /api/users: hashing password for %q", u.Username)
		hash, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
		if err != nil {
			log.Printf("PUT /api/users: bcrypt failed for %q: %v", u.Username, err)
			http.Error(w, "hash failed", http.StatusInternalServerError)
			return
		}
		u.PasswordHash = string(hash) // pragma: allowlist secret
		log.Printf("PUT /api/users: password hashed successfully for %q", u.Username)
	} else if u.Source == "local" {
		// Keep existing hash if not changing password
		if existing, _ := sessionStore.GetUser(r.Context(), u.Username); existing != nil {
			u.PasswordHash = existing.PasswordHash // pragma: allowlist secret
		}
	}

	if u.Role == "" {
		u.Role = RoleViewer
	}
	if u.Source == "" {
		u.Source = "local"
	}
	if u.CreatedAt.IsZero() {
		u.CreatedAt = time.Now()
	}

	// Prevent privilege escalation: caller cannot assign a role with permissions they lack.
	if !isBootstrapMode(r) {
		targetPerms := resolveRolePerms(r, u.Role)
		callerPerms := permsFromContext(r)
		for p := range targetPerms {
			if !callerPerms[p] {
				http.Error(w, "cannot assign role with permission you do not hold: "+string(p), http.StatusForbidden)
				return
			}
		}
	}

	if err := sessionStore.UpsertUser(r.Context(), u); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Printf("user %q updated (source=%s, role=%s)", u.Username, u.Source, u.Role)
	w.WriteHeader(http.StatusNoContent)
}

func handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	if !require(w, r, store.PermUsersWrite) {
		return
	}
	username := strings.TrimPrefix(r.URL.Path, "/api/users/")
	if username == "" {
		http.Error(w, "username required", http.StatusBadRequest)
		return
	}

	if err := sessionStore.DeleteUser(r.Context(), username); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Printf("user %q deleted", username)
	w.WriteHeader(http.StatusNoContent)
}

func handleGetHosts(w http.ResponseWriter, r *http.Request) {
	if !require(w, r, store.PermSessionsListOwn) {
		return
	}
	all, err := cache.get(r.Context())
	if err != nil {
		http.Error(w, "index error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	seen := make(map[string]struct{})
	for _, s := range all {
		if s.Host != "" {
			seen[s.Host] = struct{}{}
		}
	}
	hosts := make([]string, 0, len(seen))
	for h := range seen {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"hosts": hosts})
}

// handleAccessLog returns the view audit log as JSON, newest entries first.
// Optional query params:
//
//	viewer=alice  — filter to a specific viewer
//	limit=N       — max entries to return (default 200, max 1000)
func handleAccessLog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !require(w, r, store.PermAuditLogRead) {
		return
	}

	filterViewer := r.URL.Query().Get("viewer")
	limit := 200
	if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 && v <= 1000 {
		limit = v
	}

	entries, err := sessionStore.ListAccessLog(r.Context(), filterViewer, limit)
	if err != nil {
		log.Printf("list access log: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(entries); err != nil {
		log.Printf("encode access log: %v", err)
	}
}
