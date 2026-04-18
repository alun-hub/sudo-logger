package store

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLocalStoreCleanup(t *testing.T) {
	logDir := t.TempDir()
	retentionPath := filepath.Join(t.TempDir(), "retention.json")

	ls := &LocalStore{
		cfg: Config{
			LogDir:        logDir,
			RetentionPath: retentionPath,
		},
	}

	ctx := context.Background()

	// 1. Create sessions of various ages
	now := time.Now()

	// Old session (10 days ago)
	oldSess := filepath.Join(logDir, "alice", "host_old")
	os.MkdirAll(oldSess, 0755)
	os.WriteFile(filepath.Join(oldSess, "session.cast"), []byte("cast"), 0644)
	// We use directory mtime as the proxy for age.
	os.Chtimes(oldSess, now.AddDate(0, 0, -10), now.AddDate(0, 0, -10))

	// New session (1 hour ago)
	newSess := filepath.Join(logDir, "bob", "host_new")
	os.MkdirAll(newSess, 0755)
	os.WriteFile(filepath.Join(newSess, "session.cast"), []byte("cast"), 0644)
	os.Chtimes(newSess, now.Add(-1*time.Hour), now.Add(-1*time.Hour))

	// In-progress session (old but has ACTIVE marker)
	activeSess := filepath.Join(logDir, "charity", "host_active")
	os.MkdirAll(activeSess, 0755)
	os.WriteFile(filepath.Join(activeSess, "ACTIVE"), []byte(""), 0644)
	os.Chtimes(activeSess, now.AddDate(0, 0, -10), now.AddDate(0, 0, -10))

	// 2. Set retention policy (7 days)
	policy := RetentionPolicy{Enabled: true, Days: 7}
	pdata, _ := json.Marshal(policy)
	if err := ls.SetConfig(ctx, "retention_policy", string(pdata)); err != nil {
		t.Fatalf("SetConfig: %v", err)
	}

	// 3. Trigger cleanup
	ls.doCleanup(ctx)

	// 4. Verify
	if _, err := os.Stat(oldSess); !os.IsNotExist(err) {
		t.Errorf("old session still exists")
	}
	if _, err := os.Stat(newSess); err != nil {
		t.Errorf("new session was deleted: %v", err)
	}
	if _, err := os.Stat(activeSess); err != nil {
		t.Errorf("active session was deleted: %v", err)
	}

	// Verify alice user dir was removed if empty
	if _, err := os.Stat(filepath.Join(logDir, "alice")); !os.IsNotExist(err) {
		t.Errorf("empty user dir alice still exists")
	}
}
