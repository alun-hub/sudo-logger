package store

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"time"
)

// runCleanupWorker periodically deletes old sessions based on the configured
// retention policy. It runs once a day.
func (ls *LocalStore) runCleanupWorker(ctx context.Context) {
	// Initial delay to let the system settle on startup.
	select {
	case <-ctx.Done():
		return
	case <-time.After(1 * time.Minute):
		ls.doCleanup(ctx)
	}

	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ls.doCleanup(ctx)
		}
	}
}

func (ls *LocalStore) doCleanup(ctx context.Context) {
	cfgStr, err := ls.GetConfig(ctx, "retention_policy")
	if err != nil || cfgStr == "" {
		return
	}
	var policy RetentionPolicy
	if err := json.Unmarshal([]byte(cfgStr), &policy); err != nil {
		log.Printf("store/local: cleanup: parse policy: %v", err)
		return
	}
	if !policy.Enabled || policy.Days <= 0 {
		return
	}

	threshold := time.Now().AddDate(0, 0, -policy.Days)
	log.Printf("store/local: cleanup: starting (older than %d days)", policy.Days)

	// Walk log directory and find expired sessions.
	// sessions are stored in user/host_datetime/ format.
	users, err := os.ReadDir(ls.cfg.LogDir)
	if err != nil {
		log.Printf("store/local: cleanup: read log dir: %v", err)
		return
	}

	removed := 0
	for _, u := range users {
		if !u.IsDir() {
			continue
		}
		userDir := filepath.Join(ls.cfg.LogDir, u.Name())
		sessDirs, err := os.ReadDir(userDir)
		if err != nil {
			continue
		}

		for _, s := range sessDirs {
			if !s.IsDir() {
				continue
			}
			sessPath := filepath.Join(userDir, s.Name())
			fi, err := s.Info()
			if err != nil {
				continue
			}

			// Check if session is still in progress.
			if _, err := os.Stat(filepath.Join(sessPath, "ACTIVE")); err == nil {
				continue
			}

			// Use directory modtime as a proxy for session end time.
			if fi.ModTime().Before(threshold) {
				if err := os.RemoveAll(sessPath); err != nil {
					log.Printf("store/local: cleanup: remove %s: %v", sessPath, err)
				} else {
					removed++
				}
			}
		}

		// Try to remove empty user directory.
		_ = os.Remove(userDir)
	}

	if removed > 0 {
		log.Printf("store/local: cleanup: removed %d session(s)", removed)
	}
}
