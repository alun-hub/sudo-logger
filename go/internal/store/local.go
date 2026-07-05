package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"sudo-logger/internal/protocol"

	"github.com/fsnotify/fsnotify"
	"gopkg.in/yaml.v3"

	"sudo-logger/internal/iolog"
)

// ── LocalStore ────────────────────────────────────────────────────────────────

// LocalStore implements SessionStore using the local filesystem.
// It preserves the exact directory layout and file formats of the original
// single-node implementation, so existing sessions remain readable and no
// migration is required when upgrading.
type LocalStore struct {
	cfg Config

	// blocked-users state — reloaded every 30 s in background goroutine.
	blockedMu       sync.RWMutex
	blockedCfg      blockedUsersConfig
	lastBlockedHash string // SHA256 hex of last successfully loaded content

	// whitelisted-users state — reloaded every 30 s in background goroutine.
	whitelistMu       sync.RWMutex
	whitelistCfg      whitelistedUsersConfig
	lastWhitelistHash string // SHA256 hex of last successfully loaded content

	// users state — reloaded every 30 s in background goroutine.
	usersMu       sync.RWMutex
	usersCfg      usersConfig
	lastUsersHash string // SHA256 hex of last successfully loaded content

	// roles state — reloaded every 30 s in background goroutine.
	rolesMu       sync.RWMutex
	rolesCfg      []RoleDefinition
	lastRolesHash string // SHA256 hex of last successfully loaded content

	// auth-config state — reloaded every 30 s in background goroutine.
	authMu       sync.RWMutex
	authCfg      AuthConfig
	lastAuthHash string // SHA256 hex of last successfully loaded content

	// access log — bounded in-memory ring buffer (same behaviour as before
	// the store abstraction was introduced).
	viewMu  sync.Mutex
	viewLog []AccessLogEntry

	// sessionDirs maps session_id → absolute session directory path.
	// Populated by CreateSession; used by MarkSessionNetworkOutage to locate

	// the session directory without scanning the full log tree.
	// sync.Map is safe for concurrent use; values are never deleted (entries
	// are small strings and the process lifetime matches session lifetime).
	sessionDirs sync.Map // map[string]string

	// approval state — in-memory + YAML persistence.
	approvalMu      sync.RWMutex
	approvalPending map[string]*ApprovalRequest // id → request
	approvalWindows []localApprovalWindow

	stopOnce sync.Once
	stopCh   chan struct{}
}

const viewLogMax = 10_000

// blockedUsersConfig mirrors the YAML structure of blocked-users.yaml.
type blockedUsersConfig struct {
	BlockMessage string        `yaml:"block_message"`
	Users        []blockedUser `yaml:"users"`
}

type blockedUser struct {
	Username  string   `yaml:"username"`
	Hosts     []string `yaml:"hosts"` // empty = all hosts
	Reason    string   `yaml:"reason"`
	BlockedAt int64    `yaml:"blocked_at"`
}

// whitelistedUsersConfig mirrors the YAML structure of whitelisted-users.yaml.
type whitelistedUsersConfig struct {
	Users []whitelistedUser `yaml:"users"`
}

type whitelistedUser struct {
	Username string   `yaml:"username"`
	Hosts    []string `yaml:"hosts"` // empty = all hosts
	Reason   string   `yaml:"reason"`
}

// usersConfig mirrors the YAML structure of users.yaml.
type usersConfig struct {
	Users []User `yaml:"users"`
}

// newLocalStore creates a LocalStore and starts the background reload goroutine
// for blocked-users.yaml.
func newLocalStore(cfg Config) (*LocalStore, error) {
	if cfg.LogDir == "" {
		cfg.LogDir = "/var/log/sudoreplay"
	}
	if cfg.BlockedUsersPath == "" {
		cfg.BlockedUsersPath = "/etc/sudo-logger/blocked-users.yaml"
	}
	if cfg.WhitelistedUsersPath == "" {
		cfg.WhitelistedUsersPath = "/etc/sudo-logger/whitelisted-users.yaml"
	}
	if cfg.UsersPath == "" {
		cfg.UsersPath = "/etc/sudo-logger/users.yaml"
	}
	if cfg.RolesPath == "" {
		cfg.RolesPath = "/etc/sudo-logger/roles.yaml"
	}
	if cfg.AuthConfigPath == "" {
		cfg.AuthConfigPath = "/etc/sudo-logger/auth-config.yaml"
	}
	if cfg.SiemConfigPath == "" {
		cfg.SiemConfigPath = "/etc/sudo-logger/siem.yaml"
	}
	if cfg.RiskRulesPath == "" {
		cfg.RiskRulesPath = "/etc/sudo-logger/risk-rules.yaml"
	}
	if cfg.SandboxConfigPath == "" {
		cfg.SandboxConfigPath = "/etc/sudo-logger/sandbox.yaml"
	}
	if cfg.RetentionPath == "" {
		cfg.RetentionPath = "/etc/sudo-logger/retention.json"
	}
	if cfg.SandboxTemplatesPath == "" {
		cfg.SandboxTemplatesPath = "/etc/sudo-logger/sandbox-templates.json"
	}
	if cfg.ApprovalPolicyPath == "" {
		cfg.ApprovalPolicyPath = "/etc/sudo-logger/approval-policy.yaml"
	}
	if cfg.ApprovalStorePath == "" {
		cfg.ApprovalStorePath = "/etc/sudo-logger/approval-store.yaml"
	}
	if cfg.RedactionConfigPath == "" {
		cfg.RedactionConfigPath = "/etc/sudo-logger/redaction-config.json"
	}

	ls := &LocalStore{
		cfg:             cfg,
		stopCh:          make(chan struct{}),
		approvalPending: make(map[string]*ApprovalRequest),
	}

	// Initial load — non-fatal; file may not exist yet.
	if err := ls.loadBlockedUsers(); err != nil {
		log.Printf("store/local: blocked-users initial load: %v", err)
	}
	if err := ls.loadWhitelistedUsers(); err != nil {
		log.Printf("store/local: whitelisted-users initial load: %v", err)
	}
	if err := ls.loadUsers(); err != nil {
		log.Printf("store/local: users initial load: %v", err)
	}
	if err := ls.loadRoles(); err != nil {
		log.Printf("store/local: roles initial load: %v", err)
	}
	if err := ls.loadAuthConfig(); err != nil {
		log.Printf("store/local: auth-config initial load: %v", err)
	}
	if err := ls.loadApprovalStore(); err != nil {
		log.Printf("store/local: approval-store initial load: %v", err)
	}

	// Reload every 30 s.
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				if err := ls.loadBlockedUsers(); err != nil {
					log.Printf("store/local: blocked-users reload: %v", err)
				}
				if err := ls.loadWhitelistedUsers(); err != nil {
					log.Printf("store/local: whitelisted-users reload: %v", err)
				}
				if err := ls.loadUsers(); err != nil {
					log.Printf("store/local: users reload: %v", err)
				}
				if err := ls.loadRoles(); err != nil {
					log.Printf("store/local: roles reload: %v", err)
				}
				if err := ls.loadAuthConfig(); err != nil {
					log.Printf("store/local: auth-config reload: %v", err)
				}
			case <-ls.stopCh:
				return
			}
		}
	}()

	go ls.runCleanupWorker(context.Background())

	return ls, nil
}

func (ls *LocalStore) loadBlockedUsers() error {
	data, err := os.ReadFile(ls.cfg.BlockedUsersPath)
	if err != nil {
		if os.IsNotExist(err) {
			ls.blockedMu.Lock()
			ls.blockedCfg = blockedUsersConfig{}
			ls.blockedMu.Unlock()
			return nil
		}
		return err
	}
	h := sha256.Sum256(data)
	newHash := hex.EncodeToString(h[:])

	var cfg blockedUsersConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("parse blocked-users: %w", err)
	}
	ls.blockedMu.Lock()
	changed := newHash != ls.lastBlockedHash
	ls.blockedCfg = cfg
	if changed {
		ls.lastBlockedHash = newHash
	}
	ls.blockedMu.Unlock()
	if changed {
		log.Printf(`{"time":%q,"event":"config_reload","config":"blocked-users.yaml","sha256":%q,"entries":%d}`,
			time.Now().UTC().Format(time.RFC3339), newHash, len(cfg.Users))
	}
	return nil
}

// IsBlocked implements SessionStore.
func (ls *LocalStore) IsBlocked(_ context.Context, user, host string) (bool, string, error) {
	ls.blockedMu.RLock()
	cfg := ls.blockedCfg
	ls.blockedMu.RUnlock()

	for _, bu := range cfg.Users {
		if bu.Username != user {
			continue
		}
		if len(bu.Hosts) == 0 {
			return true, cfg.BlockMessage, nil
		}
		for _, h := range bu.Hosts {
			if h == host {
				return true, cfg.BlockMessage, nil
			}
		}
	}
	return false, "", nil
}

// ── User Management ──────────────────────────────────────────────────────

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

// CreateSession implements SessionStore.
func (ls *LocalStore) CreateSession(_ context.Context, meta iolog.SessionMeta, startTime time.Time) (SessionWriter, error) {
	w, err := iolog.NewWriter(ls.cfg.LogDir, meta, startTime)
	if err != nil {
		return nil, fmt.Errorf("create iolog writer: %w", err)
	}
	// Remember the directory so MarkSessionNetworkOutage can find it later
	// without scanning the full log tree.
	if meta.SessionID != "" {
		ls.sessionDirs.Store(meta.SessionID, w.Dir())
	}
	return &localWriter{w: w, logDir: ls.cfg.LogDir}, nil
}

// ListSessions implements SessionStore.
// It walks the two-level logDir/<user>/<session> directory tree and parses
// the asciinema v2 header from each session.cast file.
func (ls *LocalStore) ListSessions(_ context.Context) ([]SessionRecord, error) {
	return scanAllSessions(ls.cfg.LogDir)
}

// ReadEvents implements SessionStore.
// It resolves symlinks to prevent path traversal, then parses session.cast.
func (ls *LocalStore) ReadEvents(_ context.Context, tsid string) ([]RawEvent, error) {
	sessDir, err := ls.resolveSessionDir(tsid)
	if err != nil {
		return nil, err
	}
	return localReadEvents(sessDir)
}

// OpenCast implements SessionStore.
func (ls *LocalStore) OpenCast(_ context.Context, tsid string) (io.ReadCloser, error) {
	sessDir, err := ls.resolveSessionDir(tsid)
	if err != nil {
		return nil, err
	}
	return os.Open(filepath.Join(sessDir, "session.cast"))
}



// WatchSessions implements SessionStore.
// It uses fsnotify to detect session completion on the local filesystem:
//   - ACTIVE removed  → session ended cleanly
//   - INCOMPLETE created → session ended abnormally
func (ls *LocalStore) WatchSessions(ctx context.Context, ch chan<- string) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Printf("store/local: watcher create: %v", err)
		return
	}
	defer watcher.Close()

	logDir := ls.cfg.LogDir
	localWatchSubdirs(watcher, logDir)
	if err := watcher.Add(logDir); err != nil {
		log.Printf("store/local: watcher add %s: %v", logDir, err)
		return
	}

	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			if event.Has(fsnotify.Create) {
				fi, statErr := os.Stat(event.Name)
				if statErr == nil && fi.IsDir() {
					localWatchSubdirs(watcher, event.Name)
					_ = watcher.Add(event.Name)
				}
			}
			base := filepath.Base(event.Name)
			sessDir := filepath.Dir(event.Name)
			if event.Has(fsnotify.Remove) && base == "ACTIVE" {
				if tsid := ls.dirToTSID(sessDir); tsid != "" {
					select {
					case ch <- tsid:
					default:
					}
				}
			}
			if event.Has(fsnotify.Create) && base == "INCOMPLETE" {
				if tsid := ls.dirToTSID(sessDir); tsid != "" {
					select {
					case ch <- tsid:
					default:
					}
				}
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			log.Printf("store/local: watcher error: %v", err)
		}
	}
}

// RecordView implements SessionStore.
// Appends a session-view event to the in-memory ring buffer.
func (ls *LocalStore) RecordView(_ context.Context, tsid, viewer, replayURL string) error {
	ls.viewMu.Lock()
	defer ls.viewMu.Unlock()
	if len(ls.viewLog) >= viewLogMax {
		ls.viewLog = ls.viewLog[1:]
	}
	ls.viewLog = append(ls.viewLog, AccessLogEntry{
		Time:      time.Now().UTC(),
		Viewer:    viewer,
		TSID:      tsid,
		ReplayURL: replayURL,
	})
	return nil
}

// ListAccessLog implements SessionStore.
// Returns entries from the ring buffer, newest first, filtered by viewer.
// defaultAccessLogLimit matches the replay-server handler's own default so
// a limit<=0 (e.g. from a caller that forgets to guard it) behaves the same
// as omitting the query parameter, instead of returning a single entry.
const defaultAccessLogLimit = 200

func (ls *LocalStore) ListAccessLog(_ context.Context, viewer string, limit int) ([]AccessLogEntry, error) {
	if limit <= 0 {
		limit = defaultAccessLogLimit
	}
	ls.viewMu.Lock()
	snap := make([]AccessLogEntry, len(ls.viewLog))
	copy(snap, ls.viewLog)
	ls.viewMu.Unlock()

	// Reverse so newest is first.
	for i, j := 0, len(snap)-1; i < j; i, j = i+1, j-1 {
		snap[i], snap[j] = snap[j], snap[i]
	}

	result := snap[:0]
	for _, e := range snap {
		if viewer != "" && e.Viewer != viewer {
			continue
		}
		result = append(result, e)
		if len(result) >= limit {
			break
		}
	}
	return result, nil
}

// DeleteSession implements SessionStore.
// It appends an audit entry to <logdir>/.deletion-log.jsonl BEFORE removing
// the session directory, and aborts without deleting anything if the audit
// write fails — a deletion must always leave a trace. Returns an error if
// the session is still active or cannot be found.
func (ls *LocalStore) DeleteSession(_ context.Context, tsid, reason, deletedBy string) error {
	sessDir, err := ls.resolveSessionDir(tsid)
	if err != nil {
		return fmt.Errorf("session not found: %w", err)
	}
	if _, err := os.Stat(filepath.Join(sessDir, "ACTIVE")); err == nil {
		return fmt.Errorf("session %q is still in progress", tsid)
	}

	// Append JSON audit entry before removing anything.
	entry := fmt.Sprintf(`{"time":%q,"event":"session_deleted","tsid":%q,"reason":%q,"deleted_by":%q}`+"\n",
		time.Now().UTC().Format(time.RFC3339), tsid, reason, deletedBy)
	logPath := filepath.Join(ls.cfg.LogDir, ".deletion-log.jsonl")
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("deletion audit write: %w", err)
	}
	_, writeErr := f.WriteString(entry)
	syncErr := f.Sync()
	closeErr := f.Close()
	if writeErr != nil {
		return fmt.Errorf("deletion audit write: %w", writeErr)
	}
	if syncErr != nil {
		return fmt.Errorf("deletion audit sync: %w", syncErr)
	}
	if closeErr != nil {
		return fmt.Errorf("deletion audit close: %w", closeErr)
	}

	if err := os.RemoveAll(sessDir); err != nil {
		// The audit entry above is now inaccurate (it says the session was
		// deleted, but removal failed) — append a correction so the trail
		// stays truthful rather than silently under- or over-reporting.
		correction := fmt.Sprintf(`{"time":%q,"event":"session_delete_failed","tsid":%q,"error":%q}`+"\n",
			time.Now().UTC().Format(time.RFC3339), tsid, err.Error())
		if cf, cerr := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600); cerr == nil {
			_, _ = cf.WriteString(correction)
			cf.Close()
		} else {
			log.Printf("store/local: deletion-failure audit write: %v", cerr)
		}
		return fmt.Errorf("remove session: %w", err)
	}
	return nil
}

// Close implements SessionStore.
func (ls *LocalStore) Close() error {
	ls.stopOnce.Do(func() { close(ls.stopCh) })
	return nil
}

// ── Config API (siem.yaml / risk-rules.yaml) ──────────────────────────────────

func (ls *LocalStore) configFilePath(key string) string {
	switch key {
	case "siem.yaml":
		return ls.cfg.SiemConfigPath
	case "risk-rules.yaml":
		return ls.cfg.RiskRulesPath
	case "sandbox.yaml":
		return ls.cfg.SandboxConfigPath
	case "retention_policy":
		return ls.cfg.RetentionPath
	case "sandbox_templates":
		return ls.cfg.SandboxTemplatesPath
	case "approval-policy.yaml":
		return ls.cfg.ApprovalPolicyPath
	case "redaction_config":
		return ls.cfg.RedactionConfigPath
	default:
		return ""
	}
}

// sudoersConfigPath returns the filesystem path for a sudoers config key of
// the form "sudoers/<subkey>". path.Base is used to prevent directory traversal.
func (ls *LocalStore) sudoersConfigPath(key string) string {
	sub := filepath.Base(key[len("sudoers/"):])
	return filepath.Join(ls.cfg.LogDir, ".sudoers-config", sub)
}

// GetConfig reads a named config file from disk.
func (ls *LocalStore) GetConfig(_ context.Context, key string) (string, error) {
	if strings.HasPrefix(key, "sudoers/") {
		data, err := os.ReadFile(ls.sudoersConfigPath(key))
		if os.IsNotExist(err) {
			return "", nil
		}
		if err != nil {
			return "", err
		}
		return string(data), nil
	}
	path := ls.configFilePath(key)
	if path == "" {
		return "", fmt.Errorf("unknown config key %q", key)
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// SetConfig writes a named config file to disk.
func (ls *LocalStore) SetConfig(_ context.Context, key, value string) error {
	if strings.HasPrefix(key, "sudoers/") {
		p := ls.sudoersConfigPath(key)
		if value == "" {
			if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
				return err
			}
			return nil
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			return err
		}
		return os.WriteFile(p, []byte(value), 0o640)
	}
	path := ls.configFilePath(key)
	if path == "" {
		return fmt.Errorf("unknown config key %q", key)
	}
	return os.WriteFile(path, []byte(value), 0o640)
}

// ── Blocked-users policy API ──────────────────────────────────────────────────

const localBlockedUsersHeader = "# Blocked users config — managed by sudo-replay GUI\n" +
	"# Log server reloads this file automatically every 30 seconds.\n\n"

// GetBlockedPolicy returns the in-memory blocked-users policy (kept fresh by
// the background reload goroutine).
func (ls *LocalStore) GetBlockedPolicy(_ context.Context) (BlockedPolicy, error) {
	ls.blockedMu.RLock()
	cur := ls.blockedCfg
	ls.blockedMu.RUnlock()
	p := BlockedPolicy{BlockMessage: cur.BlockMessage}
	for _, u := range cur.Users {
		hosts := u.Hosts
		if hosts == nil {
			hosts = []string{}
		}
		p.Users = append(p.Users, BlockedUserEntry{
			Username:  u.Username,
			Hosts:     hosts,
			Reason:    u.Reason,
			BlockedAt: u.BlockedAt,
		})
	}
	if p.Users == nil {
		p.Users = []BlockedUserEntry{}
	}
	return p, nil
}

// SaveBlockedPolicy writes the blocked-users policy to blocked-users.yaml.
// The background reload goroutine will pick up the change within 30 seconds.
func (ls *LocalStore) SaveBlockedPolicy(_ context.Context, policy BlockedPolicy) error {
	raw := blockedUsersConfig{BlockMessage: policy.BlockMessage}
	for _, u := range policy.Users {
		hosts := u.Hosts
		if hosts == nil {
			hosts = []string{}
		}
		raw.Users = append(raw.Users, blockedUser{
			Username:  u.Username,
			Hosts:     hosts,
			Reason:    u.Reason,
			BlockedAt: u.BlockedAt,
		})
	}
	if raw.Users == nil {
		raw.Users = []blockedUser{}
	}
	data, err := yaml.Marshal(raw)
	if err != nil {
		return err
	}
	full := append([]byte(localBlockedUsersHeader), data...)
	tmp := ls.cfg.BlockedUsersPath + ".tmp"
	if err := os.WriteFile(tmp, full, 0o640); err != nil {
		return fmt.Errorf("write tmp blocked-users: %w", err)
	}
	if err := os.Rename(tmp, ls.cfg.BlockedUsersPath); err != nil {
		return fmt.Errorf("rename tmp blocked-users: %w", err)
	}
	return nil
}

// ── Whitelisted-users policy API ─────────────────────────────────────────────

const localWhitelistedUsersHeader = "# Whitelisted users config — managed by sudo-replay GUI\n" +
	"# Users on this list bypass JIT approval entirely.\n" +
	"# Log server reloads this file automatically every 30 seconds.\n\n"

func (ls *LocalStore) loadWhitelistedUsers() error {
	data, err := os.ReadFile(ls.cfg.WhitelistedUsersPath)
	if err != nil {
		if os.IsNotExist(err) {
			ls.whitelistMu.Lock()
			ls.whitelistCfg = whitelistedUsersConfig{}
			ls.whitelistMu.Unlock()
			return nil
		}
		return err
	}
	wh := sha256.Sum256(data)
	newHash := hex.EncodeToString(wh[:])

	var cfg whitelistedUsersConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("parse whitelisted-users: %w", err)
	}
	ls.whitelistMu.Lock()
	changed := newHash != ls.lastWhitelistHash
	ls.whitelistCfg = cfg
	if changed {
		ls.lastWhitelistHash = newHash
	}
	ls.whitelistMu.Unlock()
	if changed {
		log.Printf(`{"time":%q,"event":"config_reload","config":"whitelisted-users.yaml","sha256":%q,"entries":%d}`,
			time.Now().UTC().Format(time.RFC3339), newHash, len(cfg.Users))
	}
	return nil
}

// IsWhitelisted implements SessionStore.
func (ls *LocalStore) IsWhitelisted(_ context.Context, user, host string) (bool, error) {
	ls.whitelistMu.RLock()
	cfg := ls.whitelistCfg
	ls.whitelistMu.RUnlock()

	for _, wu := range cfg.Users {
		if wu.Username != user {
			continue
		}
		if len(wu.Hosts) == 0 {
			return true, nil
		}
		for _, h := range wu.Hosts {
			if h == host {
				return true, nil
			}
		}
	}
	return false, nil
}

// GetWhitelistPolicy returns the in-memory whitelisted-users policy.
func (ls *LocalStore) GetWhitelistPolicy(_ context.Context) (WhitelistPolicy, error) {
	ls.whitelistMu.RLock()
	cur := ls.whitelistCfg
	ls.whitelistMu.RUnlock()
	var p WhitelistPolicy
	for _, u := range cur.Users {
		hosts := u.Hosts
		if hosts == nil {
			hosts = []string{}
		}
		p.Users = append(p.Users, WhitelistedUserEntry{
			Username: u.Username,
			Hosts:    hosts,
			Reason:   u.Reason,
		})
	}
	if p.Users == nil {
		p.Users = []WhitelistedUserEntry{}
	}
	return p, nil
}

// SaveWhitelistPolicy writes the whitelisted-users policy to whitelisted-users.yaml.
func (ls *LocalStore) SaveWhitelistPolicy(_ context.Context, policy WhitelistPolicy) error {
	raw := whitelistedUsersConfig{}
	for _, u := range policy.Users {
		hosts := u.Hosts
		if hosts == nil {
			hosts = []string{}
		}
		raw.Users = append(raw.Users, whitelistedUser{
			Username: u.Username,
			Hosts:    hosts,
			Reason:   u.Reason,
		})
	}
	if raw.Users == nil {
		raw.Users = []whitelistedUser{}
	}
	data, err := yaml.Marshal(raw)
	if err != nil {
		return err
	}
	full := append([]byte(localWhitelistedUsersHeader), data...)
	tmp := ls.cfg.WhitelistedUsersPath + ".tmp"
	if err := os.WriteFile(tmp, full, 0o640); err != nil {
		return fmt.Errorf("write tmp whitelisted-users: %w", err)
	}
	if err := os.Rename(tmp, ls.cfg.WhitelistedUsersPath); err != nil {
		return fmt.Errorf("rename tmp whitelisted-users: %w", err)
	}
	return nil
}

// MarkSessionNetworkOutage implements SessionStore.
// Writes a NETWORK_OUTAGE marker file to the session directory so the replay
// UI can distinguish a freeze-timeout termination from an agent crash.
func (ls *LocalStore) MarkSessionNetworkOutage(_ context.Context, sessionID string) error {
	v, ok := ls.sessionDirs.Load(sessionID)
	if !ok {
		// Session was created before this process started (e.g. server restarted
		// mid-outage). Not an error — the session stays as generic INCOMPLETE.
		return nil
	}
	dir := v.(string)
	return os.WriteFile(filepath.Join(dir, "NETWORK_OUTAGE"),
		[]byte("session terminated by freeze-timeout watchdog\n"), 0o640)
}

// UpdateDivergenceStatus implements SessionStore.
// LocalStore has no DB — divergence status is not persisted to disk.
func (ls *LocalStore) UpdateDivergenceStatus(_ context.Context, _, _, _ string) error {
	return nil
}

func (ls *LocalStore) RecordSandboxViolation(_ context.Context, sid string, alert protocol.SandboxAlert) error {
	v, ok := ls.sessionDirs.Load(sid)
	if !ok {
		log.Printf("sandbox: RecordSandboxViolation: session %q not in sessionDirs — violation not stored", sid)
		return nil
	}
	dir := v.(string)
	path := filepath.Join(dir, "SANDBOX_VIOLATION")
	data, _ := json.Marshal(alert)
	if err := os.WriteFile(path, data, 0o640); err != nil {
		return err
	}
	log.Printf("sandbox: violation recorded: %s", path)
	return nil
}

func (ls *LocalStore) HasSandboxViolation(_ context.Context, tsid string) (bool, error) {
	dir, err := ls.resolveSessionDir(tsid)
	if err != nil {
		return false, err
	}
	_, err = os.Stat(filepath.Join(dir, "SANDBOX_VIOLATION"))
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

// resolveSessionDir converts tsid to an absolute directory path and checks
// that it stays within logDir (path-traversal guard).
func (ls *LocalStore) resolveSessionDir(tsid string) (string, error) {
	absLogDir, err := filepath.EvalSymlinks(ls.cfg.LogDir)
	if err != nil {
		return "", fmt.Errorf("eval logdir symlinks: %w", err)
	}
	sessDir := filepath.Join(absLogDir, tsid)
	absSessDir, err := filepath.EvalSymlinks(sessDir)
	if err != nil {
		return "", fmt.Errorf("session not found: %w", err)
	}
	if !strings.HasPrefix(absSessDir, absLogDir+string(filepath.Separator)) {
		return "", fmt.Errorf("tsid %q escapes log directory", tsid)
	}
	return absSessDir, nil
}

// dirToTSID converts an absolute session directory path back to a TSID
// (user/host_timestamp).  Returns "" if the path is not within logDir.
func (ls *LocalStore) dirToTSID(sessDir string) string {
	rel, err := filepath.Rel(ls.cfg.LogDir, sessDir)
	if err != nil || strings.HasPrefix(rel, "..") {
		return ""
	}
	// Normalise separators so TSID always uses forward slashes.
	return filepath.ToSlash(rel)
}

// ── localWriter ───────────────────────────────────────────────────────────────

// localWriter wraps iolog.Writer and implements SessionWriter for LocalStore.
type localWriter struct {
	w      *iolog.Writer
	logDir string
}

func (lw *localWriter) WriteOutput(data []byte, ts int64) error {
	return lw.w.WriteOutput(data, ts)
}

func (lw *localWriter) WriteInput(data []byte, ts int64) error {
	return lw.w.WriteInput(data, ts)
}

func (lw *localWriter) WriteResize(cols, rows int, ts int64) error {
	return lw.w.WriteResize(cols, rows, ts)
}

func (lw *localWriter) MarkActive() error {
	return os.WriteFile(filepath.Join(lw.w.Dir(), "ACTIVE"),
		[]byte("session in progress\n"), 0o640)
}

func (lw *localWriter) MarkIncomplete() error {
	return os.WriteFile(filepath.Join(lw.w.Dir(), "INCOMPLETE"),
		[]byte("connection lost without session_end\n"), 0o640)
}

func (lw *localWriter) MarkNetworkOutage() error {
	// Write both INCOMPLETE and NETWORK_OUTAGE so the session is correctly
	// flagged as both incomplete AND caused by network loss.
	_ = os.WriteFile(filepath.Join(lw.w.Dir(), "INCOMPLETE"),
		[]byte("connection lost without session_end\n"), 0o640)
	return os.WriteFile(filepath.Join(lw.w.Dir(), "NETWORK_OUTAGE"),
		[]byte("session terminated due to network outage\n"), 0o640)
}

func (lw *localWriter) MarkDone() error {
	return os.Remove(filepath.Join(lw.w.Dir(), "ACTIVE"))
}

func (lw *localWriter) WriteExitCode(code int32) error {
	return os.WriteFile(filepath.Join(lw.w.Dir(), "exit_code"),
		[]byte(fmt.Sprintf("%d\n", code)), 0o640)
}

func (lw *localWriter) Flush() error {
	return lw.w.Flush()
}

func (lw *localWriter) Close() error {
	return lw.w.Close()
}

func (lw *localWriter) TSID() string {
	rel, err := filepath.Rel(lw.logDir, lw.w.Dir())
	if err != nil {
		return lw.w.Dir()
	}
	return filepath.ToSlash(rel)
}






// localWatchSubdirs adds a fsnotify watch on every immediate subdirectory of dir.
func localWatchSubdirs(watcher *fsnotify.Watcher, dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			_ = watcher.Add(filepath.Join(dir, e.Name()))
		}
	}
}
