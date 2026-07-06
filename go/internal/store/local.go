package store

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
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
