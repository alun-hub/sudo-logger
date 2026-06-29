package store

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// SaveHeartbeat implements SessionStore.
func (ls *LocalStore) SaveHeartbeat(_ context.Context, host string) error {
	p := filepath.Join(ls.cfg.LogDir, ".sudoers-config", ".seen-"+host)
	data := []byte(fmt.Sprintf("%d", time.Now().Unix()))
	return os.WriteFile(p, data, 0o640)
}

// GetLastSeen implements SessionStore.
func (ls *LocalStore) GetLastSeen(_ context.Context, host string) (int64, error) {
	p := filepath.Join(ls.cfg.LogDir, ".sudoers-config", ".seen-"+host)
	data, err := os.ReadFile(p)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	var ts int64
	_, err = fmt.Sscanf(string(data), "%d", &ts)
	return ts, err
}
