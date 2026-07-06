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
	"time"

	"sudo-logger/internal/protocol"

	"github.com/fsnotify/fsnotify"

	"sudo-logger/internal/iolog"
)


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
			hasCast := false
			if _, err := os.Stat(filepath.Join(sessDir, "session.cast")); err == nil {
				hasCast = true
			}
			if _, err := os.Stat(filepath.Join(sessDir, "session.json")); err != nil && !hasCast {
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

// parseSessionRecord reads the session header and marker files, returning a
// SessionRecord. It prefers session.json (header-only, cheap) and falls back
// to reading the first line of session.cast for sessions created before
// session.json was introduced.
func parseSessionRecord(sessDir, tsid string) (*SessionRecord, error) {
	var headerBytes []byte

	if b, err := os.ReadFile(filepath.Join(sessDir, "session.json")); err == nil {
		headerBytes = b
	} else {
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
		headerBytes = scanner.Bytes()
	}

	var hdr struct {
		Timestamp       int64  `json:"timestamp"`
		SessionID       string `json:"session_id"`
		User            string `json:"user"`
		Host            string `json:"host"`
		RunasUser       string `json:"runas_user"`
		RunasUID        int    `json:"runas_uid"`
		RunasGID        int    `json:"runas_gid"`
		Width           int    `json:"width"`
		Height          int    `json:"height"`
		Cwd             string `json:"cwd"`
		Command         string `json:"command"`
		ResolvedCommand string `json:"resolved_command"`
		Flags           string `json:"flags"`
		Source          string `json:"source"`
		ParentSessionID string `json:"parent_session_id"`
		HasIO           bool   `json:"has_io"`
		CallerProcess   string `json:"caller_process"`
	}
	if err := json.Unmarshal(headerBytes, &hdr); err != nil {
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
		Cols:            hdr.Width,
		Rows:            hdr.Height,
		Command:         hdr.Command,
		ResolvedCommand: hdr.ResolvedCommand,
		Cwd:             hdr.Cwd,
		Flags:           hdr.Flags,
		StartTime:       hdr.Timestamp,
		Duration:        castLastTime(sessDir),
		Source:          hdr.Source,
		ParentSessionID: hdr.ParentSessionID,
		HasIO:           hdr.HasIO,
		CallerProcess:   hdr.CallerProcess,
	}

	if _, err := os.Stat(filepath.Join(sessDir, "INCOMPLETE")); err == nil {
		rec.Incomplete = true
	}
	if _, err := os.Stat(filepath.Join(sessDir, "NETWORK_OUTAGE")); err == nil {
		rec.NetworkOutage = true
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

// unescapeJSONString recovers raw bytes from a JSON string literal.
func unescapeJSONString(raw []byte) []byte {
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return raw
	}
	s := raw[1 : len(raw)-1]
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case '"':  out = append(out, '"'); i++
			case '\\': out = append(out, '\\'); i++
			case 'b':  out = append(out, '\b'); i++
			case 'f':  out = append(out, '\f'); i++
			case 'n':  out = append(out, '\n'); i++
			case 'r':  out = append(out, '\r'); i++
			case 't':  out = append(out, '\t'); i++
			case 'u':
				if i+5 < len(s) {
					var u uint16
					fmt.Sscanf(string(s[i+2:i+6]), "%04x", &u)
					out = append(out, byte(u))
					i += 5
					continue
				}
				out = append(out, '\\')
			default:
				out = append(out, '\\')
			}
		} else {
			out = append(out, s[i])
		}
	}
	return out
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
		var raw []json.RawMessage
		if json.Unmarshal(line, &raw) != nil || len(raw) < 3 {
			continue
		}
		var t float64
		var kind string
		var dataStr string
		if json.Unmarshal(raw[0], &t) != nil {
			continue
		}
		if json.Unmarshal(raw[1], &kind) != nil {
			continue
		}
		if json.Unmarshal(raw[2], &dataStr) != nil {
			continue
		}

		events = append(events, RawEvent{T: t, Kind: kind, Data: []byte(dataStr)})
	}
	return events, scanner.Err()
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
