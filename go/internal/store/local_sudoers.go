package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"sudo-logger/internal/protocol"
)

// validSudoersHost rejects host values that could escape the .sudoers/
// directory via path traversal (e.g. "../", absolute paths, embedded slashes).
func validSudoersHost(host string) bool {
	if host == "" || len(host) > 255 || host[0] == '.' {
		return false
	}
	return !strings.ContainsAny(host, "/\\") && !strings.Contains(host, "..")
}

// SaveSudoersSnapshot implements SessionStore.
// Snapshots are stored as <logdir>/.sudoers/<host>/<unix_ts>.conf.
// If a file with the same sha256 already exists for the host, the write is
// skipped (deduplication).
func (ls *LocalStore) SaveSudoersSnapshot(_ context.Context, snap *protocol.SudoersSnapshot) error {
	if !validSudoersHost(snap.Host) {
		return fmt.Errorf("invalid host: %q", snap.Host)
	}
	dir := filepath.Join(ls.cfg.LogDir, ".sudoers", snap.Host)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("sudoers snapshot dir: %w", err)
	}

	// If a file with the same sha256 exists, remove it so the new write
	// below gets the current timestamp. Re-applying a previous config
	// (e.g. reverting to default) must become the most-recent snapshot so
	// that ListSudoersSnapshots returns it first and inSync is recomputed.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		h := sha256.Sum256(data)
		if hex.EncodeToString(h[:]) == snap.SHA256 {
			_ = os.Remove(filepath.Join(dir, e.Name()))
			break
		}
	}

	path := filepath.Join(dir, fmt.Sprintf("%d.conf", time.Now().Unix()))
	return os.WriteFile(path, []byte(snap.Content), 0o640)
}

// ListSudoersSnapshots implements SessionStore.
func (ls *LocalStore) ListSudoersSnapshots(_ context.Context, host string, limit int) ([]SudoersSnapshotRecord, error) {
	if !validSudoersHost(host) {
		return nil, fmt.Errorf("invalid host: %q", host)
	}
	dir := filepath.Join(ls.cfg.LogDir, ".sudoers", host)
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	type entry struct {
		name    string
		modTime time.Time
	}
	var files []entry
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		files = append(files, entry{e.Name(), info.ModTime()})
	}
	sort.Slice(files, func(i, j int) bool {
		return files[i].modTime.After(files[j].modTime)
	})

	var out []SudoersSnapshotRecord
	for _, f := range files {
		if len(out) >= limit {
			break
		}
		data, err := os.ReadFile(filepath.Join(dir, f.name))
		if err != nil {
			continue
		}
		h := sha256.Sum256(data)
		out = append(out, SudoersSnapshotRecord{
			Host:       host,
			SHA256:     hex.EncodeToString(h[:]),
			UploadedAt: f.modTime.Unix(),
			Content:    string(data),
		})
	}
	return out, nil
}

// ListSudoersHosts implements SessionStore.
func (ls *LocalStore) ListSudoersHosts(_ context.Context) ([]string, error) {
	dir := filepath.Join(ls.cfg.LogDir, ".sudoers")
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var hosts []string
	for _, e := range entries {
		if e.IsDir() {
			hosts = append(hosts, e.Name())
		}
	}
	return hosts, nil
}

// ListSudoersConfigs implements SessionStore.
func (ls *LocalStore) ListSudoersConfigs(_ context.Context) (map[string]bool, error) {
	dir := filepath.Join(ls.cfg.LogDir, ".sudoers-config")
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return make(map[string]bool), nil
	}
	if err != nil {
		return nil, err
	}
	out := make(map[string]bool)
	for _, e := range entries {
		if !e.IsDir() {
			out[e.Name()] = true
		}
	}
	return out, nil
}

// SaveSudoersError implements SessionStore.
func (ls *LocalStore) SaveSudoersError(_ context.Context, serr protocol.SudoersError) error {
	p := filepath.Join(ls.cfg.LogDir, ".sudoers-config", ".err-"+serr.Host)
	data, _ := json.Marshal(serr)
	return os.WriteFile(p, data, 0o640)
}

// GetSudoersError implements SessionStore.
func (ls *LocalStore) GetSudoersError(_ context.Context, host string) (*protocol.SudoersError, error) {
	p := filepath.Join(ls.cfg.LogDir, ".sudoers-config", ".err-"+host)
	data, err := os.ReadFile(p)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var serr protocol.SudoersError
	if err := json.Unmarshal(data, &serr); err != nil {
		return nil, err
	}
	return &serr, nil
}
