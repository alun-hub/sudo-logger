package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

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
