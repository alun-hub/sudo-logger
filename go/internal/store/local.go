package store

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

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
	blockedMu  sync.RWMutex
	blockedCfg blockedUsersConfig

	// access log — bounded in-memory ring buffer (same behaviour as before
	// the store abstraction was introduced).
	viewMu  sync.Mutex
	viewLog []AccessLogEntry

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

// newLocalStore creates a LocalStore and starts the background reload goroutine
// for blocked-users.yaml.
func newLocalStore(cfg Config) (*LocalStore, error) {
	if cfg.LogDir == "" {
		cfg.LogDir = "/var/log/sudoreplay"
	}
	if cfg.BlockedUsersPath == "" {
		cfg.BlockedUsersPath = "/etc/sudo-logger/blocked-users.yaml"
	}
	if cfg.SiemConfigPath == "" {
		cfg.SiemConfigPath = "/etc/sudo-logger/siem.yaml"
	}
	if cfg.RiskRulesPath == "" {
		cfg.RiskRulesPath = "/etc/sudo-logger/risk-rules.yaml"
	}

	ls := &LocalStore{
		cfg:    cfg,
		stopCh: make(chan struct{}),
	}

	// Initial load — non-fatal; file may not exist yet.
	if err := ls.loadBlockedUsers(); err != nil {
		log.Printf("store/local: blocked-users initial load: %v", err)
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
			case <-ls.stopCh:
				return
			}
		}
	}()

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
	var cfg blockedUsersConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("parse blocked-users: %w", err)
	}
	ls.blockedMu.Lock()
	ls.blockedCfg = cfg
	ls.blockedMu.Unlock()
	log.Printf("store/local: blocked-users: loaded %d entry/entries from %s",
		len(cfg.Users), ls.cfg.BlockedUsersPath)
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

// CreateSession implements SessionStore.
func (ls *LocalStore) CreateSession(_ context.Context, meta iolog.SessionMeta, startTime time.Time) (SessionWriter, error) {
	w, err := iolog.NewWriter(ls.cfg.LogDir, meta, startTime)
	if err != nil {
		return nil, fmt.Errorf("create iolog writer: %w", err)
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

// GetRiskCache implements SessionStore.
func (ls *LocalStore) GetRiskCache(_ context.Context, tsid, rulesHash string) (*RiskCache, error) {
	sessDir := filepath.Join(ls.cfg.LogDir, tsid)
	rc := localLoadRiskCache(sessDir, rulesHash)
	if rc == nil {
		return nil, nil
	}
	return rc, nil
}

// SaveRiskCache implements SessionStore.
func (ls *LocalStore) SaveRiskCache(_ context.Context, tsid, rulesHash string, score int, reasons []string) error {
	sessDir := filepath.Join(ls.cfg.LogDir, tsid)
	localSaveRiskCache(sessDir, rulesHash, score, reasons)
	return nil
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
func (ls *LocalStore) ListAccessLog(_ context.Context, viewer string, limit int) ([]AccessLogEntry, error) {
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
	default:
		return ""
	}
}

// GetConfig reads a named config file from disk.
func (ls *LocalStore) GetConfig(_ context.Context, key string) (string, error) {
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
	return os.WriteFile(ls.cfg.BlockedUsersPath, append([]byte(localBlockedUsersHeader), data...), 0o640)
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

func (lw *localWriter) MarkActive() error {
	return os.WriteFile(filepath.Join(lw.w.Dir(), "ACTIVE"),
		[]byte("session in progress\n"), 0o640)
}

func (lw *localWriter) MarkIncomplete() error {
	return os.WriteFile(filepath.Join(lw.w.Dir(), "INCOMPLETE"),
		[]byte("connection lost without session_end\n"), 0o640)
}

func (lw *localWriter) MarkDone() error {
	return os.Remove(filepath.Join(lw.w.Dir(), "ACTIVE"))
}

func (lw *localWriter) WriteExitCode(code int32) error {
	return os.WriteFile(filepath.Join(lw.w.Dir(), "exit_code"),
		[]byte(strconv.Itoa(int(code))), 0o640)
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

// ── Filesystem helpers (extracted from replay-server/main.go) ─────────────────

// scanAllSessions walks the two-level logDir/<user>/<session> hierarchy and
// returns metadata for every parseable session directory.
func scanAllSessions(logDir string) ([]SessionRecord, error) {
	records := make([]SessionRecord, 0)
	userEntries, err := os.ReadDir(logDir)
	if err != nil {
		if os.IsNotExist(err) {
			return records, nil
		}
		return nil, fmt.Errorf("read logdir: %w", err)
	}
	for _, userEntry := range userEntries {
		if !userEntry.IsDir() {
			continue
		}
		userDir := filepath.Join(logDir, userEntry.Name())
		sessEntries, err := os.ReadDir(userDir)
		if err != nil {
			continue
		}
		for _, sessEntry := range sessEntries {
			if !sessEntry.IsDir() {
				continue
			}
			sessDir := filepath.Join(userDir, sessEntry.Name())
			if _, err := os.Stat(filepath.Join(sessDir, "session.cast")); err != nil {
				continue // not a cast session directory
			}
			tsid := userEntry.Name() + "/" + sessEntry.Name()
			rec, err := parseSessionRecord(sessDir, tsid)
			if err != nil {
				log.Printf("store/local: parse session %s: %v", sessDir, err)
				continue
			}
			records = append(records, *rec)
		}
	}
	return records, nil
}

// parseSessionRecord reads the asciinema v2 header from session.cast and the
// marker files beside it, returning a SessionRecord.
func parseSessionRecord(sessDir, tsid string) (*SessionRecord, error) {
	f, err := os.Open(filepath.Join(sessDir, "session.cast"))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 64*1024)
	if !scanner.Scan() {
		return nil, fmt.Errorf("empty cast file")
	}

	var hdr struct {
		Timestamp       int64  `json:"timestamp"`
		SessionID       string `json:"session_id"`
		User            string `json:"user"`
		Host            string `json:"host"`
		RunasUser       string `json:"runas_user"`
		RunasUID        int    `json:"runas_uid"`
		RunasGID        int    `json:"runas_gid"`
		Cwd             string `json:"cwd"`
		Command         string `json:"command"`
		ResolvedCommand string `json:"resolved_command"`
		Flags           string `json:"flags"`
	}
	if err := json.Unmarshal(scanner.Bytes(), &hdr); err != nil {
		return nil, fmt.Errorf("parse cast header: %w", err)
	}

	rec := &SessionRecord{
		TSID:            tsid,
		SessionID:       hdr.SessionID,
		User:            hdr.User,
		Host:            hdr.Host,
		Runas:           hdr.RunasUser,
		RunasUID:        hdr.RunasUID,
		RunasGID:        hdr.RunasGID,
		Command:         hdr.Command,
		ResolvedCommand: hdr.ResolvedCommand,
		Cwd:             hdr.Cwd,
		Flags:           hdr.Flags,
		StartTime:       hdr.Timestamp,
		Duration:        castLastTime(sessDir),
	}

	if _, err := os.Stat(filepath.Join(sessDir, "INCOMPLETE")); err == nil {
		rec.Incomplete = true
	}
	if _, err := os.Stat(filepath.Join(sessDir, "ACTIVE")); err == nil {
		rec.InProgress = true
	}
	if data, err := os.ReadFile(filepath.Join(sessDir, "exit_code")); err == nil {
		if v, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 32); err == nil {
			rec.ExitCode = int32(v)
		}
	}

	return rec, nil
}

// castLastTime reads the timestamp of the last event line in session.cast by
// seeking to the file tail — O(1) regardless of recording length.
func castLastTime(sessDir string) float64 {
	f, err := os.Open(filepath.Join(sessDir, "session.cast"))
	if err != nil {
		return 0
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil || fi.Size() == 0 {
		return 0
	}

	const tailSize = 8 * 1024
	readFrom := fi.Size() - tailSize
	if readFrom < 0 {
		readFrom = 0
	}
	buf := make([]byte, fi.Size()-readFrom)
	if _, err := f.ReadAt(buf, readFrom); err != nil {
		return 0
	}

	lines := bytes.Split(bytes.TrimRight(buf, "\n"), []byte("\n"))
	for i := len(lines) - 1; i >= 0; i-- {
		line := bytes.TrimSpace(lines[i])
		if len(line) == 0 || line[0] != '[' {
			continue
		}
		var event []json.RawMessage
		if json.Unmarshal(line, &event) != nil || len(event) < 1 {
			continue
		}
		var t float64
		if json.Unmarshal(event[0], &t) == nil {
			return t
		}
	}
	return 0
}

// localReadEvents parses session.cast in sessDir and returns all playback events.
func localReadEvents(sessDir string) ([]RawEvent, error) {
	f, err := os.Open(filepath.Join(sessDir, "session.cast"))
	if err != nil {
		return nil, fmt.Errorf("open cast: %w", err)
	}
	defer f.Close()

	return parseRawEvents(f)
}

// parseRawEvents reads asciinema v2 events from r, skipping the header line.
func parseRawEvents(r io.Reader) ([]RawEvent, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 2*1024*1024), 2*1024*1024)

	// Skip header line.
	if !scanner.Scan() {
		return nil, fmt.Errorf("empty cast file")
	}

	events := make([]RawEvent, 0)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 || line[0] != '[' {
			continue
		}
		var raw [3]json.RawMessage
		if json.Unmarshal(line, &raw) != nil {
			continue
		}
		var t float64
		var kind, data string
		if json.Unmarshal(raw[0], &t) != nil {
			continue
		}
		if json.Unmarshal(raw[1], &kind) != nil {
			continue
		}
		if json.Unmarshal(raw[2], &data) != nil {
			continue
		}
		events = append(events, RawEvent{T: t, Kind: kind, Data: []byte(data)})
	}
	return events, scanner.Err()
}

// localLoadRiskCache reads risk.json from sessDir and returns it if the stored
// rules hash matches rulesHash.  Returns nil on cache miss or mismatch.
func localLoadRiskCache(sessDir, rulesHash string) *RiskCache {
	data, err := os.ReadFile(filepath.Join(sessDir, "risk.json"))
	if err != nil {
		return nil
	}
	var rc struct {
		RulesHash string   `json:"rules_hash"`
		Score     int      `json:"score"`
		Level     string   `json:"level"`
		Reasons   []string `json:"reasons"`
	}
	if err := json.Unmarshal(data, &rc); err != nil {
		return nil
	}
	if rc.RulesHash != rulesHash {
		return nil // rules changed — cache is stale
	}
	return &RiskCache{
		RulesHash: rc.RulesHash,
		Score:     rc.Score,
		Level:     rc.Level,
		Reasons:   rc.Reasons,
	}
}

// localSaveRiskCache writes the risk score to risk.json in sessDir.
// Failures are silently ignored (replay server may lack write access).
func localSaveRiskCache(sessDir, rulesHash string, score int, reasons []string) {
	rc := struct {
		RulesHash string   `json:"rules_hash"`
		Score     int      `json:"score"`
		Level     string   `json:"level"`
		Reasons   []string `json:"reasons"`
	}{
		RulesHash: rulesHash,
		Score:     score,
		Level:     riskLevel(score),
		Reasons:   reasons,
	}
	data, err := json.Marshal(rc)
	if err != nil {
		return
	}
	_ = os.WriteFile(filepath.Join(sessDir, "risk.json"), data, 0o644)
}

// riskLevel converts a numeric score to a level string.
// Kept here so LocalStore can populate the risk cache Level field without
// importing the replay-server package.
func riskLevel(score int) string {
	switch {
	case score >= 75:
		return "critical"
	case score >= 50:
		return "high"
	case score >= 25:
		return "medium"
	default:
		return "low"
	}
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
