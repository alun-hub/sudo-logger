// sudo-replay-server: browser-based playback interface for sudo session logs.
//
// Reads iolog directories written by sudo-logserver and serves a single-page
// application with a terminal player.
//
// Authentication modes (can be combined):
//
//	No flags              — open; deploy behind a reverse proxy that handles auth
//	-htpasswd file        — HTTP Basic Auth from an htpasswd file (bcrypt only)
//	-tls-cert/-tls-key    — enable HTTPS
//	-trusted-user-header  — log proxy-authenticated username from a request header
//
// Run: sudo-replay-server -logdir /var/log/sudoreplay -listen :8080
package main

import (
	"bufio"
	"crypto/tls"
	"embed"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"hash/fnv"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

//go:embed static
var staticFiles embed.FS

var (
	flagListen            = flag.String("listen", ":8080", "Listen address")
	flagLogDir            = flag.String("logdir", "/var/log/sudoreplay", "Base directory for session logs")
	flagRules             = flag.String("rules", "/etc/sudo-logger/risk-rules.yaml", "Risk scoring rules file")
	flagTLSCert           = flag.String("tls-cert", "", "TLS certificate file (enables HTTPS)")
	flagTLSKey            = flag.String("tls-key", "", "TLS private key file (enables HTTPS)")
	flagHTPasswd          = flag.String("htpasswd", "", "Path to htpasswd file for HTTP Basic Auth (bcrypt hashes only; reload with SIGHUP)")
	flagTrustedUserHeader = flag.String("trusted-user-header", "", "Header containing pre-authenticated username (e.g. X-Forwarded-User)")
)

// loggingResponseWriter captures the HTTP status code for access logging.
type loggingResponseWriter struct {
	http.ResponseWriter
	status int
}

func (lrw *loggingResponseWriter) WriteHeader(code int) {
	lrw.status = code
	lrw.ResponseWriter.WriteHeader(code)
}

// accessLogMiddleware logs every request with the authenticated username,
// resolved from the trusted header (proxy mode) or Basic Auth credentials.
func accessLogMiddleware(next http.Handler, trustedHeader string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := "-"
		if trustedHeader != "" {
			if v := r.Header.Get(trustedHeader); v != "" {
				user = v
			}
		} else if u, _, ok := r.BasicAuth(); ok {
			user = u
		}
		lrw := &loggingResponseWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(lrw, r)
		log.Printf("access user=%s addr=%s %s %s %d",
			user, r.RemoteAddr, r.Method, r.URL.Path, lrw.status)
	})
}

// htpasswdStore holds bcrypt-hashed credentials loaded from an htpasswd file.
// The file format is one "username:bcrypt-hash" entry per line; lines starting
// with '#' and blank lines are ignored.  Only bcrypt hashes are accepted.
// Reload at runtime by sending SIGHUP to the process.
type htpasswdStore struct {
	mu    sync.RWMutex
	users map[string][]byte // username → bcrypt hash
	path  string
}

func newHTPasswd(path string) (*htpasswdStore, error) {
	h := &htpasswdStore{path: path}
	if err := h.reload(); err != nil {
		return nil, err
	}
	return h, nil
}

// reload reads the htpasswd file and replaces the in-memory user map atomically.
func (h *htpasswdStore) reload() error {
	f, err := os.Open(h.path)
	if err != nil {
		return fmt.Errorf("open htpasswd %s: %w", h.path, err)
	}
	defer f.Close()

	users := make(map[string][]byte)
	lineNum := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.IndexByte(line, ':')
		if idx < 1 {
			log.Printf("htpasswd %s:%d: missing colon, skipping", h.path, lineNum)
			continue
		}
		username, hash := line[:idx], []byte(line[idx+1:])
		if _, err := bcrypt.Cost(hash); err != nil {
			log.Printf("htpasswd %s:%d: user %q: not a bcrypt hash, skipping", h.path, lineNum, username)
			continue
		}
		users[username] = hash
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read htpasswd: %w", err)
	}

	h.mu.Lock()
	h.users = users
	h.mu.Unlock()
	log.Printf("htpasswd: loaded %d user(s) from %s", len(users), h.path)
	return nil
}

// authenticate returns true if username and password match a stored entry.
// Always runs bcrypt even for unknown users to prevent timing-based
// username enumeration.
var dummyHash = func() []byte {
	h, _ := bcrypt.GenerateFromPassword([]byte("dummy"), bcrypt.MinCost)
	return h
}()

func (h *htpasswdStore) authenticate(username, password string) bool {
	h.mu.RLock()
	hash, ok := h.users[username]
	h.mu.RUnlock()
	if !ok {
		bcrypt.CompareHashAndPassword(dummyHash, []byte(password)) //nolint:errcheck
		return false
	}
	return bcrypt.CompareHashAndPassword(hash, []byte(password)) == nil
}

// basicAuthMiddleware enforces HTTP Basic Auth using the htpasswdStore.
func basicAuthMiddleware(next http.Handler, store *htpasswdStore) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || !store.authenticate(u, p) {
			w.Header().Set("WWW-Authenticate", `Basic realm="sudo-replay"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// SessionInfo is the metadata returned for each session in the list API.
type SessionInfo struct {
	TSID            string  `json:"tsid"`
	User            string  `json:"user"`
	Host            string  `json:"host"`
	Runas           string  `json:"runas"`
	TTY             string  `json:"tty"`
	Command         string  `json:"command"`
	ResolvedCommand string  `json:"resolved_command,omitempty"`
	Cwd             string  `json:"cwd,omitempty"`
	Flags           string  `json:"flags,omitempty"`
	StartTime       int64    `json:"start_time"` // unix seconds
	Duration        float64  `json:"duration"`   // seconds
	Incomplete      bool     `json:"incomplete,omitempty"`  // true if shipper was killed mid-session
	InProgress      bool     `json:"in_progress,omitempty"` // true if session is still being recorded
	RiskScore       int      `json:"risk_score"`
	RiskLevel       string   `json:"risk_level"`            // low | medium | high | critical
	RiskReasons     []string `json:"risk_reasons,omitempty"`
}

// PlaybackEvent is one timed chunk of terminal output or input.
type PlaybackEvent struct {
	T    float64 `json:"t"`    // cumulative seconds from session start
	Type int     `json:"type"` // 3=TtyIn, 4=TtyOut (sudo iolog event types)
	Data string  `json:"data"` // base64-encoded bytes
}

// SessionList is the envelope returned by /api/sessions.
type SessionList struct {
	Sessions []SessionInfo `json:"sessions"`
	Total    int           `json:"total"`
}

// ReportSummary holds aggregate statistics for a time period.
type ReportSummary struct {
	TotalSessions      int   `json:"total_sessions"`
	UniqueUsers        int   `json:"unique_users"`
	UniqueHosts        int   `json:"unique_hosts"`
	IncompleteSessions  int   `json:"incomplete_sessions"`
	LongSessions        int   `json:"long_sessions"`
	HighRiskSessions    int   `json:"high_risk_sessions"`
	CriticalSessions    int   `json:"critical_sessions"`
	PeriodFrom          int64 `json:"period_from"`
	PeriodTo            int64 `json:"period_to"`
}

// HostCount holds a host name and the number of sessions on that host.
type HostCount struct {
	Host  string `json:"host"`
	Count int    `json:"count"`
}

// UserStat holds per-user aggregate statistics.
type UserStat struct {
	User         string      `json:"user"`
	Sessions     int         `json:"sessions"`
	Hosts        int         `json:"hosts"`
	HostCounts   []HostCount `json:"host_counts"`
	AvgDuration  float64     `json:"avg_duration"`
	TopCommands  []string    `json:"top_commands"`
	Incomplete   int         `json:"incomplete"`
	LongSessions int         `json:"long_sessions"`
	HighRisk     int         `json:"high_risk"`
	Critical     int         `json:"critical"`
}

// Anomaly describes a session that triggered an anomaly rule.
type Anomaly struct {
	Kind      string  `json:"kind"`
	TSID      string  `json:"tsid"`
	User      string  `json:"user"`
	Host      string  `json:"host"`
	Command   string  `json:"command"`
	StartTime int64   `json:"start_time"`
	Duration  float64 `json:"duration"`
	Detail    string  `json:"detail"`
	RiskScore int     `json:"risk_score,omitempty"`
}

// ReportData is the envelope returned by /api/report.
type ReportData struct {
	Summary   ReportSummary `json:"summary"`
	PerUser   []UserStat    `json:"per_user"`
	Anomalies []Anomaly     `json:"anomalies"`
}

// ── Risk scoring types ────────────────────────────────────────────────────────

// MatchPattern holds substring conditions for a rule's command or content field.
// ContainsAny items are ORed; AlsoAny items are ORed — both groups must match (AND).
type MatchPattern struct {
	ContainsAny []string `yaml:"contains_any" json:"contains_any,omitempty"`
	AlsoAny     []string `yaml:"also_any"     json:"also_any,omitempty"`
}

// Rule is a single risk-scoring rule loaded from the rules YAML file.
// All specified conditions are ANDed; command and content are ORed with each other.
type Rule struct {
	ID             string        `yaml:"id"               json:"id"`
	Score          int           `yaml:"score"            json:"score"`
	Reason         string        `yaml:"reason"           json:"reason"`
	Command        *MatchPattern `yaml:"command"          json:"command,omitempty"`
	Content        *MatchPattern `yaml:"content"          json:"content,omitempty"`
	CommandBaseAny []string      `yaml:"command_base_any" json:"command_base_any,omitempty"`
	Runas          string        `yaml:"runas"            json:"runas,omitempty"`
	Incomplete     *bool         `yaml:"incomplete"       json:"incomplete,omitempty"`
	AfterHours     *bool         `yaml:"after_hours"      json:"after_hours,omitempty"`
	MinDuration    float64       `yaml:"min_duration"     json:"min_duration,omitempty"`
}

// RuleSet is the top-level structure of the risk-rules YAML file.
type RuleSet struct {
	Rules []Rule `yaml:"rules"`
}

// riskCache is the on-disk cache written to risk.json beside each session directory.
type riskCache struct {
	RulesHash string   `json:"rules_hash"`
	Score     int      `json:"score"`
	Level     string   `json:"level"`
	Reasons   []string `json:"reasons"`
}

// Global rule state — reloaded from disk when the rules file changes.
var (
	globalRules     []Rule
	globalRulesHash string
	rulesMu         sync.RWMutex
)

// maxTtyOutBytes is the maximum number of ttyout bytes read for content scanning.
const maxTtyOutBytes = 512 * 1024

// sessionIndex is an in-memory cache of all parsed session metadata.
// It is rebuilt from disk at most once per indexTTL to avoid a full directory
// scan on every /api/sessions request.
type sessionIndex struct {
	mu       sync.RWMutex
	sessions []SessionInfo
	built    bool
	lastScan time.Time
}

const indexTTL = 30 * time.Second

var index = &sessionIndex{}

// get returns a snapshot of all sessions, rebuilding the index if stale.
func (idx *sessionIndex) get(logDir string) ([]SessionInfo, error) {
	idx.mu.RLock()
	if idx.built && time.Since(idx.lastScan) < indexTTL {
		snap := make([]SessionInfo, len(idx.sessions))
		copy(snap, idx.sessions)
		idx.mu.RUnlock()
		return snap, nil
	}
	idx.mu.RUnlock()
	return idx.rebuild(logDir)
}

// rebuild scans the log directory and replaces the cached session list.
// Double-checked locking prevents redundant scans when multiple requests
// arrive simultaneously after cache expiry.
func (idx *sessionIndex) rebuild(logDir string) ([]SessionInfo, error) {
	idx.mu.Lock()
	defer idx.mu.Unlock()
	// Another goroutine may have rebuilt while we waited for the write lock.
	if idx.built && time.Since(idx.lastScan) < indexTTL {
		snap := make([]SessionInfo, len(idx.sessions))
		copy(snap, idx.sessions)
		return snap, nil
	}
	// Reload rules if the file has changed (cheap — only re-parses on hash change).
	if err := loadRules(*flagRules); err != nil {
		log.Printf("risk rules reload: %v", err)
	}
	sessions, err := scanAllSessions(logDir)
	if err != nil {
		return nil, err
	}
	idx.sessions = sessions
	idx.built = true
	idx.lastScan = time.Now()
	log.Printf("session index rebuilt: %d sessions", len(sessions))
	snap := make([]SessionInfo, len(sessions))
	copy(snap, sessions)
	return snap, nil
}

// scanAllSessions walks the two-level logDir/<user>/<session> hierarchy and
// returns metadata for every parseable session directory.
func scanAllSessions(logDir string) ([]SessionInfo, error) {
	sessions := make([]SessionInfo, 0)
	userEntries, err := os.ReadDir(logDir)
	if err != nil {
		if os.IsNotExist(err) {
			return sessions, nil
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
			tsid := userEntry.Name() + "/" + sessEntry.Name()
			sessDir := filepath.Join(userDir, sessEntry.Name())
			info, err := parseSession(sessDir, tsid)
			if err != nil {
				log.Printf("parse session %s: %v", sessDir, err)
				continue
			}
			sessions = append(sessions, *info)
		}
	}
	return sessions, nil
}

func main() {
	flag.Parse()

	if err := loadRules(*flagRules); err != nil {
		log.Fatalf("load risk rules: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/sessions", handleListSessions)
	mux.HandleFunc("/api/session/events", handleSessionEvents)
	mux.HandleFunc("/api/report", handleReport)
	mux.HandleFunc("/api/rules", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handleGetRules(w, r)
		case http.MethodPut:
			handlePutRules(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	staticFS, err := fs.Sub(staticFiles, "static")
	if err != nil {
		log.Fatalf("embed static: %v", err)
	}
	mux.Handle("/", http.FileServer(http.FS(staticFS)))

	// Pre-warm the session index so the first request is served from cache.
	go func() {
		if _, err := index.rebuild(*flagLogDir); err != nil {
			log.Printf("initial session index build: %v", err)
		}
	}()

	// Build middleware chain (innermost first):
	//   basicAuth (optional) → accessLog → handler
	var handler http.Handler = mux
	if *flagHTPasswd != "" {
		store, err := newHTPasswd(*flagHTPasswd)
		if err != nil {
			log.Fatalf("htpasswd: %v", err)
		}
		// Reload credentials on SIGHUP — no restart required for password rotation.
		sighup := make(chan os.Signal, 1)
		signal.Notify(sighup, syscall.SIGHUP)
		go func() {
			for range sighup {
				if err := store.reload(); err != nil {
					log.Printf("htpasswd reload: %v", err)
				}
			}
		}()
		handler = basicAuthMiddleware(handler, store)
	}
	handler = accessLogMiddleware(handler, *flagTrustedUserHeader)

	// Start server with TLS if certificates are provided.
	if *flagTLSCert != "" || *flagTLSKey != "" {
		if *flagTLSCert == "" || *flagTLSKey == "" {
			log.Fatal("both -tls-cert and -tls-key must be specified together")
		}
		tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
		srv := &http.Server{Addr: *flagListen, Handler: handler, TLSConfig: tlsCfg}
		log.Printf("sudo-replay-server listening on %s (TLS), logdir=%s", *flagListen, *flagLogDir)
		log.Fatal(srv.ListenAndServeTLS(*flagTLSCert, *flagTLSKey))
	} else {
		log.Printf("sudo-replay-server listening on %s, logdir=%s", *flagListen, *flagLogDir)
		log.Fatal(http.ListenAndServe(*flagListen, handler))
	}
}

func handleListSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	sortBy := r.URL.Query().Get("sort")
	order := r.URL.Query().Get("order")

	limit := 200
	offset := 0
	if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 && v <= 1000 {
		limit = v
	}
	if v, err := strconv.Atoi(r.URL.Query().Get("offset")); err == nil && v >= 0 {
		offset = v
	}

	var from, to int64
	if v, err := strconv.ParseInt(r.URL.Query().Get("from"), 10, 64); err == nil {
		from = v
	}
	if v, err := strconv.ParseInt(r.URL.Query().Get("to"), 10, 64); err == nil {
		to = v
	}

	result, err := listSessions(*flagLogDir, q, sortBy, order, from, to, limit, offset)
	if err != nil {
		log.Printf("list sessions: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(result); err != nil {
		log.Printf("encode session list: %v", err)
	}
}

func handleSessionEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	tsid := r.URL.Query().Get("tsid")
	if tsid == "" {
		http.Error(w, "missing tsid", http.StatusBadRequest)
		return
	}
	if err := validateTSID(tsid); err != nil {
		http.Error(w, "invalid tsid", http.StatusBadRequest)
		return
	}

	// Verify the resolved path stays within the log directory.
	// EvalSymlinks resolves all symlinks so a symlink pointing outside logdir
	// is caught even when filepath.Abs would pass it through.
	absLogDir, err := filepath.EvalSymlinks(*flagLogDir)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	sessDir := filepath.Join(absLogDir, tsid)
	absSessDir, err := filepath.EvalSymlinks(sessDir)
	if err != nil {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}
	if !strings.HasPrefix(absSessDir, absLogDir+string(filepath.Separator)) {
		http.Error(w, "invalid tsid", http.StatusBadRequest)
		return
	}

	events, err := readEvents(absSessDir)
	if err != nil {
		log.Printf("read events %s: %v", tsid, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(events); err != nil {
		log.Printf("encode session events: %v", err)
	}
}

// validateTSID ensures the TSID (e.g. "alice/host1_20260307-112244") contains
// only safe characters and no path-traversal sequences.
func validateTSID(tsid string) error {
	if strings.Contains(tsid, "..") {
		return fmt.Errorf("path traversal attempt")
	}
	for _, c := range tsid {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || //nolint:staticcheck // allowlist form is more readable than De Morgan
			(c >= '0' && c <= '9') || c == '/' || c == '_' || c == '-' || c == '.') {
			return fmt.Errorf("invalid character: %q", c)
		}
	}
	return nil
}

// listSessions filters, sorts and paginates sessions from the in-memory index.
func listSessions(logDir, q, sortBy, order string, from, to int64, limit, offset int) (*SessionList, error) {
	all, err := index.get(logDir)
	if err != nil {
		return nil, err
	}

	sessions := make([]SessionInfo, 0, len(all))
	for _, s := range all {
		if from > 0 && s.StartTime < from {
			continue
		}
		if to > 0 && s.StartTime > to {
			continue
		}
		if q != "" && !matchesAll(s, q) {
			continue
		}
		sessions = append(sessions, s)
	}

	switch sortBy {
	case "user":
		if order == "asc" {
			sort.Slice(sessions, func(i, j int) bool { return sessions[i].User < sessions[j].User })
		} else {
			sort.Slice(sessions, func(i, j int) bool { return sessions[i].User > sessions[j].User })
		}
	case "host":
		if order == "asc" {
			sort.Slice(sessions, func(i, j int) bool { return sessions[i].Host < sessions[j].Host })
		} else {
			sort.Slice(sessions, func(i, j int) bool { return sessions[i].Host > sessions[j].Host })
		}
	case "duration":
		if order == "asc" {
			sort.Slice(sessions, func(i, j int) bool { return sessions[i].Duration < sessions[j].Duration })
		} else {
			sort.Slice(sessions, func(i, j int) bool { return sessions[i].Duration > sessions[j].Duration })
		}
	case "risk":
		if order == "asc" {
			sort.Slice(sessions, func(i, j int) bool { return sessions[i].RiskScore < sessions[j].RiskScore })
		} else {
			sort.Slice(sessions, func(i, j int) bool { return sessions[i].RiskScore > sessions[j].RiskScore })
		}
	default: // "time" or ""
		if order == "asc" {
			sort.Slice(sessions, func(i, j int) bool { return sessions[i].StartTime < sessions[j].StartTime })
		} else {
			sort.Slice(sessions, func(i, j int) bool { return sessions[i].StartTime > sessions[j].StartTime })
		}
	}

	total := len(sessions)
	if offset >= total {
		return &SessionList{Sessions: make([]SessionInfo, 0), Total: total}, nil
	}
	end := offset + limit
	if end > total {
		end = total
	}
	return &SessionList{Sessions: sessions[offset:end], Total: total}, nil
}

// matchesAll returns true if every space-separated term in q appears in at
// least one of user, host, or command (case-insensitive AND logic).
func matchesAll(s SessionInfo, q string) bool {
	user := strings.ToLower(s.User)
	host := strings.ToLower(s.Host)
	cmd  := strings.ToLower(s.Command)
	for _, term := range strings.Fields(q) {
		if !strings.Contains(user, term) &&
			!strings.Contains(host, term) &&
			!strings.Contains(cmd, term) {
			return false
		}
	}
	return true
}

// parseSession reads the iolog "log" file and timing file for a session directory.
//
// The sudo iolog legacy log format (written by iolog.go):
//
//	line 1: unix_ts:submituser:runasuser::ttyname
//	line 2: cwd (always "/" in this implementation)
//	line 3: command with arguments
func parseSession(sessDir, tsid string) (*SessionInfo, error) {
	logData, err := os.ReadFile(filepath.Join(sessDir, "log"))
	if err != nil {
		return nil, err
	}

	lines := strings.SplitN(strings.TrimRight(string(logData), "\n"), "\n", 3)
	if len(lines) < 3 {
		return nil, fmt.Errorf("malformed log file (%d lines)", len(lines))
	}

	// "unix_ts:user:runas::tty" — split into at most 5 fields.
	// The double colon is because runasgroup is always empty here.
	parts := strings.SplitN(lines[0], ":", 5)
	if len(parts) < 5 {
		return nil, fmt.Errorf("malformed log metadata: %q", lines[0])
	}

	ts, _ := strconv.ParseInt(parts[0], 10, 64)
	user := parts[1]
	runas := parts[2]
	tty := parts[4]
	cwd := lines[1]
	command := lines[2]

	// Extract host from session directory name "host_YYYYMMDD-HHMMSS".
	// The timestamp suffix is always "_YYYYMMDD-HHMMSS" = 16 chars.
	host := ""
	dirName := filepath.Base(sessDir)
	if len(dirName) > 16 {
		host = dirName[:len(dirName)-16]
	}

	info := &SessionInfo{
		TSID:      tsid,
		User:      user,
		Host:      host,
		Runas:     runas,
		TTY:       tty,
		Command:   command,
		Cwd:       cwd,
		StartTime: ts,
		Duration:  calcDuration(filepath.Join(sessDir, "timing")),
	}

	// Merge extra metadata written by sudo-logserver (not in sudoreplay format).
	var meta struct {
		ResolvedCommand string `json:"resolved_command"`
		Flags           string `json:"flags"`
	}
	if b, err := os.ReadFile(filepath.Join(sessDir, "meta.json")); err == nil {
		if json.Unmarshal(b, &meta) == nil {
			info.ResolvedCommand = meta.ResolvedCommand
			info.Flags = meta.Flags
		}
	}

	// Mark sessions where the shipper was killed without sending session_end.
	if _, err := os.Stat(filepath.Join(sessDir, "INCOMPLETE")); err == nil {
		info.Incomplete = true
	}

	// Mark sessions that are still being recorded (ACTIVE written at start,
	// removed by the logserver when SESSION_END or INCOMPLETE is written).
	if _, err := os.Stat(filepath.Join(sessDir, "ACTIVE")); err == nil {
		info.InProgress = true
	}

	info.RiskScore, info.RiskReasons = scoreSession(info, sessDir)
	info.RiskLevel = riskLevel(info.RiskScore)

	return info, nil
}

// calcDuration sums all delta values in a timing file to get total duration.
func calcDuration(timingPath string) float64 {
	f, err := os.Open(timingPath)
	if err != nil {
		return 0
	}
	defer f.Close()
	var total float64
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 {
			delta, _ := strconv.ParseFloat(fields[1], 64)
			total += delta
		}
	}
	return total
}

func handleReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var from, to int64
	if v, err := strconv.ParseInt(r.URL.Query().Get("from"), 10, 64); err == nil {
		from = v
	}
	if v, err := strconv.ParseInt(r.URL.Query().Get("to"), 10, 64); err == nil {
		to = v
	}
	report, err := buildReport(*flagLogDir, from, to)
	if err != nil {
		log.Printf("build report: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(report); err != nil {
		log.Printf("encode report: %v", err)
	}
}

func buildReport(logDir string, from, to int64) (*ReportData, error) {
	all, err := index.get(logDir)
	if err != nil {
		return nil, err
	}

	sessions := make([]SessionInfo, 0, len(all))
	for _, s := range all {
		if from > 0 && s.StartTime < from {
			continue
		}
		if to > 0 && s.StartTime > to {
			continue
		}
		sessions = append(sessions, s)
	}

	// ── Summary ───────────────────────────────────────────────────────────────
	userSet := make(map[string]struct{})
	hostSet := make(map[string]struct{})
	nIncomplete, nLong, nHighRisk, nCritical := 0, 0, 0, 0
	var periodFrom, periodTo int64
	for _, s := range sessions {
		userSet[s.User] = struct{}{}
		hostSet[s.Host] = struct{}{}
		if s.Incomplete {
			nIncomplete++
		}
		if s.Duration > 7200 {
			nLong++
		}
		if s.RiskScore >= 75 {
			nCritical++
		} else if s.RiskScore >= 50 {
			nHighRisk++
		}
		if periodFrom == 0 || s.StartTime < periodFrom {
			periodFrom = s.StartTime
		}
		if s.StartTime > periodTo {
			periodTo = s.StartTime
		}
	}

	// ── Per-user ─────────────────────────────────────────────────────────────
	type userAccum struct {
		sessions     int
		hosts        map[string]int
		totalDur     float64
		commands     map[string]int
		incomplete   int
		longSessions int
		highRisk     int
		critical     int
	}
	accums := make(map[string]*userAccum)
	for _, s := range sessions {
		a, ok := accums[s.User]
		if !ok {
			a = &userAccum{
				hosts:    make(map[string]int),
				commands: make(map[string]int),
			}
			accums[s.User] = a
		}
		a.sessions++
		a.hosts[s.Host]++
		a.totalDur += s.Duration
		if parts := strings.Fields(s.Command); len(parts) > 0 {
			a.commands[filepath.Base(parts[0])]++
		}
		if s.Incomplete {
			a.incomplete++
		}
		if s.Duration > 7200 {
			a.longSessions++
		}
		if s.RiskScore >= 75 {
			a.critical++
		} else if s.RiskScore >= 50 {
			a.highRisk++
		}
	}

	type kv struct {
		k string
		v int
	}
	perUser := make([]UserStat, 0, len(accums))
	for user, a := range accums {
		kvs := make([]kv, 0, len(a.commands))
		for k, v := range a.commands {
			kvs = append(kvs, kv{k, v})
		}
		sort.Slice(kvs, func(i, j int) bool { return kvs[i].v > kvs[j].v })
		top := make([]string, 0, 3)
		for i := 0; i < len(kvs) && i < 3; i++ {
			top = append(top, kvs[i].k)
		}
		avg := 0.0
		if a.sessions > 0 {
			avg = a.totalDur / float64(a.sessions)
		}
		hostKVs := make([]kv, 0, len(a.hosts))
		for h, n := range a.hosts {
			hostKVs = append(hostKVs, kv{h, n})
		}
		sort.Slice(hostKVs, func(i, j int) bool { return hostKVs[i].v > hostKVs[j].v })
		hostCounts := make([]HostCount, len(hostKVs))
		for i, hkv := range hostKVs {
			hostCounts[i] = HostCount{Host: hkv.k, Count: hkv.v}
		}

		perUser = append(perUser, UserStat{
			User:         user,
			Sessions:     a.sessions,
			Hosts:        len(a.hosts),
			HostCounts:   hostCounts,
			AvgDuration:  avg,
			TopCommands:  top,
			Incomplete:   a.incomplete,
			LongSessions: a.longSessions,
			HighRisk:     a.highRisk,
			Critical:     a.critical,
		})
	}
	sort.Slice(perUser, func(i, j int) bool { return perUser[i].Sessions > perUser[j].Sessions })

	// ── Anomalies ─────────────────────────────────────────────────────────────
	anomalies := make([]Anomaly, 0)
	inAnomalies := make(map[string]bool)
	for _, s := range sessions {
		if s.Incomplete {
			anomalies = append(anomalies, Anomaly{
				Kind: "incomplete", TSID: s.TSID, User: s.User, Host: s.Host,
				Command: s.Command, StartTime: s.StartTime, Duration: s.Duration,
				Detail: "shipper killed mid-session", RiskScore: s.RiskScore,
			})
			inAnomalies[s.TSID] = true
		}
		t := time.Unix(s.StartTime, 0)
		if h := t.Hour(); h < 6 || h >= 23 {
			anomalies = append(anomalies, Anomaly{
				Kind: "after_hours", TSID: s.TSID, User: s.User, Host: s.Host,
				Command: s.Command, StartTime: s.StartTime, Duration: s.Duration,
				Detail: fmt.Sprintf("%02d:%02d local time", h, t.Minute()), RiskScore: s.RiskScore,
			})
			inAnomalies[s.TSID] = true
		}
		if s.Duration > 7200 {
			anomalies = append(anomalies, Anomaly{
				Kind: "long_session", TSID: s.TSID, User: s.User, Host: s.Host,
				Command: s.Command, StartTime: s.StartTime, Duration: s.Duration,
				Detail: "duration " + fmtDur(s.Duration), RiskScore: s.RiskScore,
			})
			inAnomalies[s.TSID] = true
		}
		if s.Runas == "root" {
			base := ""
			if parts := strings.Fields(s.Command); len(parts) > 0 {
				base = filepath.Base(parts[0])
			}
			switch base {
			case "bash", "sh", "zsh", "fish", "ksh", "tcsh", "csh":
				anomalies = append(anomalies, Anomaly{
					Kind: "root_shell", TSID: s.TSID, User: s.User, Host: s.Host,
					Command: s.Command, StartTime: s.StartTime, Duration: s.Duration,
					Detail: "direct root shell", RiskScore: s.RiskScore,
				})
				inAnomalies[s.TSID] = true
			}
		}
		// Flag high-risk sessions not already captured by other anomaly kinds.
		if s.RiskScore >= 50 && !inAnomalies[s.TSID] {
			detail := strings.Join(s.RiskReasons, "; ")
			anomalies = append(anomalies, Anomaly{
				Kind: "high_risk", TSID: s.TSID, User: s.User, Host: s.Host,
				Command: s.Command, StartTime: s.StartTime, Duration: s.Duration,
				Detail: detail, RiskScore: s.RiskScore,
			})
			inAnomalies[s.TSID] = true
		}
	}
	kindOrder := map[string]int{"incomplete": 0, "high_risk": 1, "root_shell": 2, "after_hours": 3, "long_session": 4}
	sort.Slice(anomalies, func(i, j int) bool {
		if anomalies[i].Kind != anomalies[j].Kind {
			return kindOrder[anomalies[i].Kind] < kindOrder[anomalies[j].Kind]
		}
		if anomalies[i].RiskScore != anomalies[j].RiskScore {
			return anomalies[i].RiskScore > anomalies[j].RiskScore
		}
		return anomalies[i].StartTime > anomalies[j].StartTime
	})

	return &ReportData{
		Summary: ReportSummary{
			TotalSessions:      len(sessions),
			UniqueUsers:        len(userSet),
			UniqueHosts:        len(hostSet),
			IncompleteSessions: nIncomplete,
			LongSessions:       nLong,
			HighRiskSessions:   nHighRisk,
			CriticalSessions:   nCritical,
			PeriodFrom:         periodFrom,
			PeriodTo:           periodTo,
		},
		PerUser:   perUser,
		Anomalies: anomalies,
	}, nil
}

// fmtDur formats a duration in seconds as a human-readable string.
func fmtDur(secs float64) string {
	d := time.Duration(secs) * time.Second
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	if h > 0 {
		return fmt.Sprintf("%dh %dm", h, m)
	}
	return fmt.Sprintf("%dm", m+1)
}

// ── Rules API ─────────────────────────────────────────────────────────────────

// rulesFileHeader is prepended when the Settings UI writes the rules YAML file.
const rulesFileHeader = `# sudo-replay risk scoring rules
# Managed by sudo-replay-server. Manual edits and Settings UI changes are both supported.
# Changes are detected automatically on each index rebuild — no restart required.
#
# score: points added to session total (capped at 100)
# reason: shown in the UI when this rule fires
#
# command / content: case-insensitive substring matching against command line / ttyout
#   contains_any  – at least one string must be present (OR)
#   also_any      – AND at least one of these must also be present (AND + OR)
#   Rules with both fields fire if EITHER matches.
#
# command_base_any: basename of the executed binary (e.g. bash, visudo)
# runas:            target user requirement (e.g. root)
# incomplete:       true when session ended without a clean session_end
# after_hours:      true when session started between 23:00 and 05:59 local time
# min_duration:     minimum session length in seconds

`

// RulesResponse is returned by GET /api/rules.
type RulesResponse struct {
	Path  string `json:"path"`
	Rules []Rule `json:"rules"`
}

func handleGetRules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rulesMu.RLock()
	rules := make([]Rule, len(globalRules))
	copy(rules, globalRules)
	rulesMu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(RulesResponse{Path: *flagRules, Rules: rules}); err != nil {
		log.Printf("encode rules: %v", err)
	}
}

func handlePutRules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Rules []Rule `json:"rules"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	yamlBody, err := yaml.Marshal(RuleSet{Rules: body.Rules})
	if err != nil {
		http.Error(w, "marshal yaml: "+err.Error(), http.StatusInternalServerError)
		return
	}
	content := []byte(rulesFileHeader)
	content = append(content, yamlBody...)
	if err := os.WriteFile(*flagRules, content, 0o644); err != nil {
		log.Printf("write rules file: %v", err)
		http.Error(w, "write failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := loadRules(*flagRules); err != nil {
		log.Printf("reload after write: %v", err)
	}
	// Invalidate session index so next request re-scores with new rules.
	index.mu.Lock()
	index.built = false
	index.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]bool{"ok": true}); err != nil {
		log.Printf("encode rules response: %v", err)
	}
}

// ── Risk scoring ──────────────────────────────────────────────────────────────

// riskLevel converts a numeric score to a level string.
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

// computeRulesHash returns a short FNV-32 hex hash of the YAML content.
func computeRulesHash(data []byte) string {
	h := fnv.New32a()
	h.Write(data)
	return fmt.Sprintf("%08x", h.Sum32())
}

// loadRules reads and parses the rules YAML file, updating the globals
// only when the content hash has changed.
func loadRules(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read rules file %s: %w", path, err)
	}
	hash := computeRulesHash(data)
	rulesMu.RLock()
	unchanged := hash == globalRulesHash
	rulesMu.RUnlock()
	if unchanged {
		return nil
	}
	var rs RuleSet
	if err := yaml.Unmarshal(data, &rs); err != nil {
		return fmt.Errorf("parse rules file: %w", err)
	}
	rulesMu.Lock()
	globalRules = rs.Rules
	globalRulesHash = hash
	rulesMu.Unlock()
	log.Printf("risk rules loaded: %d rules (hash %s)", len(rs.Rules), hash)
	return nil
}

// matchPattern returns true when text satisfies both ContainsAny and AlsoAny.
func matchPattern(p *MatchPattern, text string) bool {
	if len(p.ContainsAny) > 0 {
		found := false
		for _, s := range p.ContainsAny {
			if strings.Contains(text, strings.ToLower(s)) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if len(p.AlsoAny) > 0 {
		found := false
		for _, s := range p.AlsoAny {
			if strings.Contains(text, strings.ToLower(s)) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// matchesRule returns true when all conditions in the rule are satisfied.
// Metadata conditions (runas, incomplete, etc.) are all ANDed.
// command and content patterns are ORed with each other.
func matchesRule(rule Rule, s *SessionInfo, cmd, cmdBase string, getContent func() string) bool {
	if rule.Incomplete != nil && *rule.Incomplete != s.Incomplete {
		return false
	}
	if rule.AfterHours != nil {
		t := time.Unix(s.StartTime, 0)
		h := t.Hour()
		isAfterHours := h < 6 || h >= 23
		if *rule.AfterHours != isAfterHours {
			return false
		}
	}
	if rule.MinDuration > 0 && s.Duration < rule.MinDuration {
		return false
	}
	if rule.Runas != "" && !strings.EqualFold(s.Runas, rule.Runas) {
		return false
	}
	if len(rule.CommandBaseAny) > 0 {
		found := false
		for _, b := range rule.CommandBaseAny {
			if cmdBase == strings.ToLower(b) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	// command and content are ORed — at least one must match if either is defined.
	hasCmd := rule.Command != nil
	hasCon := rule.Content != nil
	if hasCmd || hasCon {
		cmdMatch := hasCmd && matchPattern(rule.Command, cmd)
		conMatch := hasCon && matchPattern(rule.Content, getContent())
		if !cmdMatch && !conMatch {
			return false
		}
	}
	return true
}

// stripANSI removes ANSI CSI escape sequences (ESC [ ... <letter>) from s.
func stripANSI(s string) string {
	out := make([]byte, 0, len(s))
	i := 0
	for i < len(s) {
		if s[i] == '\x1b' && i+1 < len(s) && s[i+1] == '[' {
			i += 2
			for i < len(s) && (s[i] < 0x40 || s[i] > 0x7e) {
				i++
			}
			if i < len(s) {
				i++ // consume the final command byte
			}
		} else {
			out = append(out, s[i])
			i++
		}
	}
	return string(out)
}

// loadTtyOut reads up to maxTtyOutBytes from the session's ttyout file,
// strips ANSI codes, and returns lowercase text for pattern matching.
func loadTtyOut(sessDir string) string {
	f, err := os.Open(filepath.Join(sessDir, "ttyout"))
	if err != nil {
		return ""
	}
	defer f.Close()
	data, _ := io.ReadAll(io.LimitReader(f, maxTtyOutBytes))
	return strings.ToLower(stripANSI(string(data)))
}

// loadRiskCache reads risk.json from sessDir and returns it if the
// stored rules hash matches the currently loaded rules.
func loadRiskCache(sessDir, rulesHash string) *riskCache {
	data, err := os.ReadFile(filepath.Join(sessDir, "risk.json"))
	if err != nil {
		return nil
	}
	var rc riskCache
	if err := json.Unmarshal(data, &rc); err != nil {
		return nil
	}
	if rc.RulesHash != rulesHash {
		return nil // rules changed — cache is stale
	}
	return &rc
}

// saveRiskCache writes the risk score to risk.json in sessDir.
// Failure is silently ignored (replay server may lack write access).
func saveRiskCache(sessDir, rulesHash string, score int, reasons []string) {
	rc := riskCache{
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

// scoreSession computes a risk score (0–100) for a session using the
// globally loaded rules.  Results are cached in risk.json next to the
// session files so ttyout is only read once per session per rules version.
func scoreSession(s *SessionInfo, sessDir string) (int, []string) {
	rulesMu.RLock()
	rules := globalRules
	rulesHash := globalRulesHash
	rulesMu.RUnlock()

	if cached := loadRiskCache(sessDir, rulesHash); cached != nil {
		return cached.Score, cached.Reasons
	}

	cmd := strings.ToLower(s.Command)
	cmdBase := ""
	if parts := strings.Fields(s.Command); len(parts) > 0 {
		cmdBase = strings.ToLower(filepath.Base(parts[0]))
	}

	// Lazy ttyout loader — only read disk if a content rule is evaluated.
	var contentOnce sync.Once
	var contentText string
	getContent := func() string {
		contentOnce.Do(func() { contentText = loadTtyOut(sessDir) })
		return contentText
	}

	score := 0
	var reasons []string
	for _, rule := range rules {
		if score >= 100 {
			break
		}
		if !matchesRule(rule, s, cmd, cmdBase, getContent) {
			continue
		}
		pts := rule.Score
		if score+pts > 100 {
			pts = 100 - score
		}
		score += pts
		reasons = append(reasons, rule.Reason)
	}

	saveRiskCache(sessDir, rulesHash, score, reasons)
	return score, reasons
}

// readEvents parses the timing file and streams the corresponding bytes from
// ttyout (EventTtyOut=4) and ttyin (EventTtyIn=3) — only the bytes referenced
// by each timing entry are read, avoiding loading entire data files into memory.
//
// The timing file format (one entry per line):
//
//	<event_type> <delta_seconds> <byte_count>
func readEvents(sessDir string) ([]PlaybackEvent, error) {
	timingData, err := os.ReadFile(filepath.Join(sessDir, "timing"))
	if err != nil {
		return nil, fmt.Errorf("read timing: %w", err)
	}

	outF, _ := os.Open(filepath.Join(sessDir, "ttyout"))
	if outF != nil {
		defer outF.Close()
	}
	inF, _ := os.Open(filepath.Join(sessDir, "ttyin"))
	if inF != nil {
		defer inF.Close()
	}

	events := make([]PlaybackEvent, 0)
	var cumTime float64

	for _, line := range strings.Split(string(timingData), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		eventType, _ := strconv.Atoi(fields[0])
		delta, _ := strconv.ParseFloat(fields[1], 64)
		nbytes, _ := strconv.Atoi(fields[2])
		cumTime += delta

		if nbytes <= 0 {
			continue
		}

		var f *os.File
		switch eventType {
		case 4: // TtyOut — what the user sees
			f = outF
		case 3: // TtyIn — what the user typed
			f = inF
		default:
			continue
		}
		if f == nil {
			continue
		}

		chunk := make([]byte, nbytes)
		if _, err := io.ReadFull(f, chunk); err != nil {
			continue
		}
		events = append(events, PlaybackEvent{
			T:    cumTime,
			Type: eventType,
			Data: base64.StdEncoding.EncodeToString(chunk),
		})
	}

	return events, nil
}
