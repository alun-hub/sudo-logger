package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"sort"
	"time"

	"gopkg.in/yaml.v3"
)

// usersConfig mirrors the YAML structure of users.yaml.
type usersConfig struct {
	Users []User `yaml:"users"`
}


func (ls *LocalStore) loadUsers() error {
	data, err := os.ReadFile(ls.cfg.UsersPath)
	if err != nil {
		if os.IsNotExist(err) {
			ls.usersMu.Lock()
			ls.usersCfg = usersConfig{}
			ls.usersMu.Unlock()
			return nil
		}
		return err
	}
	h := sha256.Sum256(data)
	newHash := hex.EncodeToString(h[:])

	var cfg usersConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("parse users: %w", err)
	}
	ls.usersMu.Lock()
	changed := newHash != ls.lastUsersHash
	ls.usersCfg = cfg
	if changed {
		ls.lastUsersHash = newHash
	}
	ls.usersMu.Unlock()
	if changed {
		log.Printf(`{"time":%q,"event":"config_reload","config":"users.yaml","sha256":%q,"entries":%d}`,
			time.Now().UTC().Format(time.RFC3339), newHash, len(cfg.Users))
	}
	return nil
}

func (ls *LocalStore) saveUsers() error {
	ls.usersMu.RLock()
	data, err := yaml.Marshal(ls.usersCfg)
	ls.usersMu.RUnlock()
	if err != nil {
		return fmt.Errorf("marshal users: %w", err)
	}

	// Write to temporary file first to ensure atomic update.
	tmp := ls.cfg.UsersPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("write tmp users: %w", err)
	}
	if err := os.Rename(tmp, ls.cfg.UsersPath); err != nil {
		return fmt.Errorf("rename tmp users: %w", err)
	}

	// Update local cache hash immediately so we don't log a config_reload
	// for our own change in the background goroutine.
	h := sha256.Sum256(data)
	ls.usersMu.Lock()
	ls.lastUsersHash = hex.EncodeToString(h[:])
	ls.usersMu.Unlock()

	return nil
}

// GetUser implements SessionStore.
func (ls *LocalStore) GetUser(_ context.Context, username string) (*User, error) {
	ls.usersMu.RLock()
	defer ls.usersMu.RUnlock()
	for _, u := range ls.usersCfg.Users {
		if u.Username == username {
			cp := u
			return &cp, nil
		}
	}
	return nil, nil
}

// UpsertUser implements SessionStore.
func (ls *LocalStore) UpsertUser(_ context.Context, u User) error {
	ls.usersMu.Lock()
	found := false
	for i, existing := range ls.usersCfg.Users {
		if existing.Username == u.Username {
			if u.CreatedAt.IsZero() {
				u.CreatedAt = existing.CreatedAt
			}
			if u.LastLogin.IsZero() {
				u.LastLogin = existing.LastLogin
			}
			ls.usersCfg.Users[i] = u
			found = true
			break
		}
	}
	if !found {
		if u.CreatedAt.IsZero() {
			u.CreatedAt = time.Now()
		}
		ls.usersCfg.Users = append(ls.usersCfg.Users, u)
	}
	ls.usersMu.Unlock()
	return ls.saveUsers()
}

// ListUsers implements SessionStore.
func (ls *LocalStore) ListUsers(_ context.Context) ([]User, error) {
	ls.usersMu.RLock()
	defer ls.usersMu.RUnlock()
	users := make([]User, len(ls.usersCfg.Users))
	copy(users, ls.usersCfg.Users)
	sort.Slice(users, func(i, j int) bool { return users[i].Username < users[j].Username })
	return users, nil
}

// DeleteUser implements SessionStore.
func (ls *LocalStore) DeleteUser(_ context.Context, username string) error {
	ls.usersMu.Lock()
	newUsers := make([]User, 0, len(ls.usersCfg.Users))
	for _, u := range ls.usersCfg.Users {
		if u.Username != username {
			newUsers = append(newUsers, u)
		}
	}
	ls.usersCfg.Users = newUsers
	ls.usersMu.Unlock()
	return ls.saveUsers()
}

// ── Role Management ──────────────────────────────────────────────────────

func (ls *LocalStore) loadRoles() error {
	data, err := os.ReadFile(ls.cfg.RolesPath)
	if err != nil {
		if os.IsNotExist(err) {
			ls.rolesMu.Lock()
			ls.rolesCfg = nil
			ls.rolesMu.Unlock()
			return nil
		}
		return err
	}
	h := sha256.Sum256(data)
	newHash := hex.EncodeToString(h[:])

	var defs []RoleDefinition
	if err := yaml.Unmarshal(data, &defs); err != nil {
		return fmt.Errorf("parse roles: %w", err)
	}
	ls.rolesMu.Lock()
	changed := newHash != ls.lastRolesHash
	ls.rolesCfg = defs
	if changed {
		ls.lastRolesHash = newHash
	}
	ls.rolesMu.Unlock()
	if changed {
		log.Printf(`{"time":%q,"event":"config_reload","config":"roles.yaml","sha256":%q,"entries":%d}`,
			time.Now().UTC().Format(time.RFC3339), newHash, len(defs))
	}
	return nil
}

func (ls *LocalStore) saveRoles() error {
	ls.rolesMu.RLock()
	data, err := yaml.Marshal(ls.rolesCfg)
	ls.rolesMu.RUnlock()
	if err != nil {
		return fmt.Errorf("marshal roles: %w", err)
	}
	tmp := ls.cfg.RolesPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("write tmp roles: %w", err)
	}
	if err := os.Rename(tmp, ls.cfg.RolesPath); err != nil {
		return fmt.Errorf("rename tmp roles: %w", err)
	}
	h := sha256.Sum256(data)
	ls.rolesMu.Lock()
	ls.lastRolesHash = hex.EncodeToString(h[:])
	ls.rolesMu.Unlock()
	return nil
}

// seedViewerRole ensures the default "viewer" role exists in roles.yaml.
// Called lazily on first GetRoles so the file is only created when needed.
func (ls *LocalStore) seedViewerRole() {
	ls.rolesMu.RLock()
	for _, r := range ls.rolesCfg {
		if r.Name == "viewer" {
			ls.rolesMu.RUnlock()
			return
		}
	}
	ls.rolesMu.RUnlock()

	ls.rolesMu.Lock()
	// Double-check after acquiring write lock.
	for _, r := range ls.rolesCfg {
		if r.Name == "viewer" {
			ls.rolesMu.Unlock()
			return
		}
	}
	ls.rolesCfg = append(ls.rolesCfg, RoleDefinition{
		Name:        "viewer",
		Description: "Default viewer: can list and replay own sessions",
		Permissions: []Permission{PermSessionsListOwn, PermSessionsReplayOwn},
	})
	ls.rolesMu.Unlock()
	if err := ls.saveRoles(); err != nil {
		log.Printf("store/local: seed viewer role: %v", err)
	}
}

// GetRoles implements SessionStore.
func (ls *LocalStore) GetRoles(_ context.Context) ([]RoleDefinition, error) {
	ls.seedViewerRole()
	ls.rolesMu.RLock()
	defer ls.rolesMu.RUnlock()

	// Always include the locked built-in "admin" role synthesized in-memory.
	admin := RoleDefinition{
		Name:        "admin",
		Description: "Built-in administrator: all permissions",
		Permissions: AllPermissions,
		BuiltIn:     true,
	}
	out := make([]RoleDefinition, 0, len(ls.rolesCfg)+1)
	out = append(out, admin)
	out = append(out, ls.rolesCfg...)
	return out, nil
}

// GetRole implements SessionStore.
func (ls *LocalStore) GetRole(_ context.Context, name string) (RoleDefinition, error) {
	if name == "admin" {
		return RoleDefinition{
			Name:        "admin",
			Description: "Built-in administrator: all permissions",
			Permissions: AllPermissions,
			BuiltIn:     true,
		}, nil
	}
	ls.rolesMu.RLock()
	defer ls.rolesMu.RUnlock()
	for _, r := range ls.rolesCfg {
		if r.Name == name {
			return r, nil
		}
	}
	return RoleDefinition{}, nil
}

// UpsertRole implements SessionStore.
func (ls *LocalStore) UpsertRole(_ context.Context, def RoleDefinition) error {
	if def.Name == "admin" {
		return fmt.Errorf("role %q is built-in and cannot be modified", def.Name)
	}
	def.BuiltIn = false
	ls.rolesMu.Lock()
	found := false
	for i, r := range ls.rolesCfg {
		if r.Name == def.Name {
			ls.rolesCfg[i] = def
			found = true
			break
		}
	}
	if !found {
		ls.rolesCfg = append(ls.rolesCfg, def)
	}
	ls.rolesMu.Unlock()
	return ls.saveRoles()
}

// DeleteRole implements SessionStore.
func (ls *LocalStore) DeleteRole(_ context.Context, name string) error {
	if name == "admin" {
		return fmt.Errorf("role %q is built-in and cannot be deleted", name)
	}
	ls.rolesMu.Lock()
	newRoles := make([]RoleDefinition, 0, len(ls.rolesCfg))
	for _, r := range ls.rolesCfg {
		if r.Name != name {
			newRoles = append(newRoles, r)
		}
	}
	ls.rolesCfg = newRoles
	ls.rolesMu.Unlock()
	return ls.saveRoles()
}

// ── Auth Configuration ───────────────────────────────────────────────────

func (ls *LocalStore) loadAuthConfig() error {
	data, err := os.ReadFile(ls.cfg.AuthConfigPath)
	if err != nil {
		if os.IsNotExist(err) {
			ls.authMu.Lock()
			ls.authCfg = AuthConfig{Source: "local"}
			ls.authMu.Unlock()
			return nil
		}
		return err
	}
	h := sha256.Sum256(data)
	newHash := hex.EncodeToString(h[:])

	var cfg AuthConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("parse auth-config: %w", err)
	}
	if cfg.Source == "" {
		cfg.Source = "local"
	}
	ls.authMu.Lock()
	changed := newHash != ls.lastAuthHash
	ls.authCfg = cfg
	if changed {
		ls.lastAuthHash = newHash
	}
	ls.authMu.Unlock()
	if changed {
		log.Printf(`{"time":%q,"event":"config_reload","config":"auth-config.yaml","sha256":%q,"source":%q}`,
			time.Now().UTC().Format(time.RFC3339), newHash, cfg.Source)
	}
	return nil
}

func (ls *LocalStore) saveAuthConfig() error {
	ls.authMu.RLock()
	data, err := yaml.Marshal(ls.authCfg)
	ls.authMu.RUnlock()
	if err != nil {
		return fmt.Errorf("marshal auth-config: %w", err)
	}

	tmp := ls.cfg.AuthConfigPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("write tmp auth-config: %w", err)
	}
	if err := os.Rename(tmp, ls.cfg.AuthConfigPath); err != nil {
		return fmt.Errorf("rename tmp auth-config: %w", err)
	}

	h := sha256.Sum256(data)
	ls.authMu.Lock()
	ls.lastAuthHash = hex.EncodeToString(h[:])
	ls.authMu.Unlock()

	return nil
}

// GetAuthConfig implements SessionStore.
func (ls *LocalStore) GetAuthConfig(_ context.Context) (AuthConfig, error) {
	ls.authMu.RLock()
	defer ls.authMu.RUnlock()
	return ls.authCfg, nil
}

// SetAuthConfig implements SessionStore.
func (ls *LocalStore) SetAuthConfig(_ context.Context, cfg AuthConfig) error {
	ls.authMu.Lock()
	ls.authCfg = cfg
	ls.authMu.Unlock()
	return ls.saveAuthConfig()
}
