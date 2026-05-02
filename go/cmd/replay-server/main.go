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
	"bytes"
	"context"
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
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"

	"sudo-logger/internal/siem"
	"sudo-logger/internal/store"
)

//go:embed static
var staticFiles embed.FS

var (
	flagListen            = flag.String("listen", ":8080", "Listen address")
	flagLogDir            = flag.String("logdir", "/var/log/sudoreplay", "Base directory for session logs")
	flagRules             = flag.String("rules", "/etc/sudo-logger/risk-rules.yaml", "Risk scoring rules file")
	flagSiemConfig        = flag.String("siem-config", "/etc/sudo-logger/siem.yaml", "SIEM forwarding config file (shared with log server)")
	flagBlockedUsers      = flag.String("blocked-users", "/etc/sudo-logger/blocked-users.yaml", "Blocked users config file (shared with log server)")
	flagTLSCert           = flag.String("tls-cert", "", "TLS certificate file (enables HTTPS)")
	flagTLSKey            = flag.String("tls-key", "", "TLS private key file (enables HTTPS)")
	flagHTPasswd          = flag.String("htpasswd", "", "Path to htpasswd file for HTTP Basic Auth (bcrypt hashes only; reload with SIGHUP)")
	flagTrustedUserHeader = flag.String("trusted-user-header", "", "Header containing pre-authenticated username (e.g. X-Forwarded-User)")

	// Storage backend flags.
	// NOTE: these flags are intentionally duplicated in cmd/server/main.go.
	// If you change a default or description here, update that file too.
	flagStorage     = flag.String("storage", "local", "Storage backend: local|distributed")
	flagS3Bucket    = flag.String("s3-bucket", "", "S3 bucket name (distributed storage)")
	flagS3Region    = flag.String("s3-region", "us-east-1", "S3 region (distributed storage)")
	flagS3Prefix    = flag.String("s3-prefix", "sessions/", "S3 key prefix (distributed storage)")
	flagS3Endpoint  = flag.String("s3-endpoint", "", "S3-compatible endpoint URL, e.g. https://minio.internal:9000")
	flagS3PathStyle = flag.Bool("s3-path-style", false, "Use path-style S3 URLs (required for MinIO/StorageGRID)")
	flagS3AccessKey = flag.String("s3-access-key", "", "Static S3 access key (leave empty to use IAM/env)")
	flagS3SecretKey = flag.String("s3-secret-key", "", "Static S3 secret key (leave empty to use IAM/env)")
	flagDBURL       = flag.String("db-url", "", "PostgreSQL DSN (distributed storage)")
	flagBufferDir   = flag.String("buffer-dir", "/var/lib/sudo-logger/buffer", "Local write-buffer dir for S3 uploads")
)

// sessionStore is the active storage backend, initialised in main().
var sessionStore store.SessionStore

// ctxKey is the unexported type for context keys in this package.
type ctxKey int

const ctxViewer ctxKey = 0

// viewerFromContext returns the authenticated username stored in ctx,
// or "-" if none was set.
func viewerFromContext(r *http.Request) string {
	if v, ok := r.Context().Value(ctxViewer).(string); ok && v != "" {
		return v
	}
	return "-"
}

var viewsTotal atomic.Int64 // monotonic per-process counter for Prometheus

func recordView(r *http.Request, tsid, replayURL string) {
	viewsTotal.Add(1)
	viewer := viewerFromContext(r)
	if err := sessionStore.RecordView(r.Context(), tsid, viewer, replayURL); err != nil {
		log.Printf("record view: %v", err)
	}
}

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
		ctx := context.WithValue(r.Context(), ctxViewer, user)
		next.ServeHTTP(lrw, r.WithContext(ctx))
		log.Printf("access identity=%s addr=%s method=%s path=%s status=%d",
			sanitizeForLog(user), r.RemoteAddr, r.Method, sanitizeForLog(r.URL.Path), lrw.status)
	})
}

// sanitizeForLog replaces ASCII control characters with '_' to prevent log injection.
func sanitizeForLog(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return '_'
		}
		return r
	}, s)
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
	TSID            string   `json:"tsid"`
	SessionID       string   `json:"session_id,omitempty"`
	User            string   `json:"user"`
	Host            string   `json:"host"`
	Runas           string   `json:"runas"`
	RunasUID        int      `json:"runas_uid,omitempty"`
	RunasGID        int      `json:"runas_gid,omitempty"`
	TTY             string   `json:"tty"`
	Command         string   `json:"command"`
	ResolvedCommand string   `json:"resolved_command,omitempty"`
	Cwd             string   `json:"cwd,omitempty"`
	Flags           string   `json:"flags,omitempty"`
	StartTime       int64    `json:"start_time"` // unix seconds
	Duration        float64  `json:"duration"`   // seconds
	ExitCode        int32    `json:"exit_code"`
	Incomplete      bool     `json:"incomplete,omitempty"`      // true if session ended without clean session_end
	NetworkOutage   bool     `json:"network_outage,omitempty"`  // true when terminated by network loss (not a shipper kill)
	InProgress      bool     `json:"in_progress,omitempty"`     // true if session is still being recorded
	RiskScore       int      `json:"risk_score"`
	RiskLevel       string   `json:"risk_level"`            // low | medium | high | critical
	RiskReasons     []string `json:"risk_reasons,omitempty"`
	HasFrames       bool     `json:"has_frames,omitempty"` // true for GUI sessions with screen capture
	// eBPF / divergence fields (agent v2+)
	Source           string `json:"source,omitempty"`            // "plugin" | "ebpf-tty" | "ebpf-pkexec"
	ParentSessionID  string `json:"parent_session_id,omitempty"` // for ebpf-pkexec → parent session
	HasIO            bool   `json:"has_io,omitempty"`            // false for pkexec background services
	DivergenceStatus string `json:"divergence_status,omitempty"` // "confirmed" | "unwitnessed" | "missing_plugin"
	MatchedSessionID string `json:"matched_session_id,omitempty"` // TSID of matched counterpart
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
// Metadata conditions are ANDed; command_base_any, command, and content are ORed with each other.
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
	// Source filters by session source ("plugin", "ebpf-tty", "ebpf-pkexec", "dbus-polkit").
	// Empty means the rule applies to all sources.
	Source   string `yaml:"source"    json:"source,omitempty"`
	// ExitCode, when non-nil, requires an exact exit-code match.
	ExitCode *int32 `yaml:"exit_code" json:"exit_code,omitempty"`
}

// RuleSet is the top-level structure of the risk-rules YAML file.
type RuleSet struct {
	Rules []Rule `yaml:"rules"`
}

// Global rule state — reloaded from disk when the rules file changes.
var (
	globalRules     []Rule
	globalRulesHash string
	rulesMu         sync.RWMutex
)

// BlockedUser describes a single blocked user entry in blocked-users.yaml.
type BlockedUser struct {
	Username  string   `yaml:"username"   json:"username"`
	Hosts     []string `yaml:"hosts"      json:"hosts"`
	Reason    string   `yaml:"reason"     json:"reason"`
	BlockedAt int64    `yaml:"blocked_at" json:"blocked_at"`
}

// BlockedUsersConfig is the top-level structure of blocked-users.yaml.
type BlockedUsersConfig struct {
	BlockMessage string        `yaml:"block_message" json:"block_message"`
	Users        []BlockedUser `yaml:"users"         json:"users"`
}

// maxTtyOutBytes is the maximum number of ttyout bytes read for content scanning.
const maxTtyOutBytes = 512 * 1024

// sessionCache is a TTL-based in-memory cache of scored SessionInfo values.
// It wraps sessionStore.ListSessions and adds risk scoring on top.
type sessionCache struct {
	mu       sync.RWMutex
	sessions []SessionInfo
	built    bool
	lastScan time.Time
}

const cacheTTL = 30 * time.Second

var cache = &sessionCache{}

// get returns a scored snapshot of all sessions, rebuilding if stale.
func (c *sessionCache) get(ctx context.Context) ([]SessionInfo, error) {
	c.mu.RLock()
	if c.built && time.Since(c.lastScan) < cacheTTL {
		snap := make([]SessionInfo, len(c.sessions))
		copy(snap, c.sessions)
		c.mu.RUnlock()
		return snap, nil
	}
	c.mu.RUnlock()
	return c.rebuild(ctx)
}

// rebuild fetches records from the store, scores each one, and updates the cache.
// The write lock is held only for the staleness check and the final state update,
// so concurrent readers are not blocked during I/O and scoring.
func (c *sessionCache) rebuild(ctx context.Context) ([]SessionInfo, error) {
	c.mu.Lock()
	if c.built && time.Since(c.lastScan) < cacheTTL {
		snap := make([]SessionInfo, len(c.sessions))
		copy(snap, c.sessions)
		c.mu.Unlock()
		return snap, nil
	}
	c.mu.Unlock()

	// Perform all I/O and CPU-heavy scoring without holding the lock so that
	// concurrent readers (e.g. the session-list endpoint) are not blocked.
	if rulesText, err := sessionStore.GetConfig(ctx, "risk-rules.yaml"); err != nil {
		log.Printf("risk rules reload: %v", err)
	} else if err := loadRulesFromText(rulesText); err != nil {
		log.Printf("risk rules parse: %v", err)
	}
	records, err := sessionStore.ListSessions(ctx)
	if err != nil {
		return nil, err
	}
	sfs, hasSFS := sessionStore.(store.ScreenFrameStore)
	sessions := make([]SessionInfo, 0, len(records))
	for _, rec := range records {
		info := recordToInfo(rec)
		info.RiskScore, info.RiskReasons = scoreSession(&info)
		info.RiskLevel = store.RiskLevel(info.RiskScore)
		if hasSFS && rec.TSID != "" {
			if has, _ := sfs.HasFrames(ctx, rec.TSID); has {
				info.HasFrames = true
			}
		}
		sessions = append(sessions, info)
	}

	c.mu.Lock()
	c.sessions = sessions
	c.built = true
	c.lastScan = time.Now()
	snap := make([]SessionInfo, len(sessions))
	copy(snap, sessions)
	c.mu.Unlock()

	log.Printf("session cache rebuilt: %d sessions", len(sessions))
	return snap, nil
}

// invalidate forces the next get() to rebuild from the store.
func (c *sessionCache) invalidate() {
	c.mu.Lock()
	c.built = false
	c.mu.Unlock()
}

// recordToInfo converts a store.SessionRecord to a SessionInfo (without risk fields).
func recordToInfo(r store.SessionRecord) SessionInfo {
	src := r.Source
	if src == "" {
		src = "plugin"
	}
	return SessionInfo{
		TSID:             r.TSID,
		SessionID:        r.SessionID,
		User:             r.User,
		Host:             r.Host,
		Runas:            r.Runas,
		RunasUID:         r.RunasUID,
		RunasGID:         r.RunasGID,
		Command:          r.Command,
		ResolvedCommand:  r.ResolvedCommand,
		Cwd:              r.Cwd,
		Flags:            r.Flags,
		StartTime:        r.StartTime,
		Duration:         r.Duration,
		ExitCode:         r.ExitCode,
		Incomplete:       r.Incomplete,
		NetworkOutage:    r.NetworkOutage,
		InProgress:       r.InProgress,
		Source:           src,
		ParentSessionID:  r.ParentSessionID,
		HasIO:            r.HasIO,
		DivergenceStatus: r.DivergenceStatus,
		MatchedSessionID: r.MatchedSessionID,
	}
}

// ── Blocked users API ─────────────────────────────────────────────────────────

func handleGetBlockedUsers(w http.ResponseWriter, r *http.Request) {
	policy, err := sessionStore.GetBlockedPolicy(r.Context())
	if err != nil {
		http.Error(w, "read config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	cfg := BlockedUsersConfig{BlockMessage: policy.BlockMessage}
	for _, u := range policy.Users {
		hosts := u.Hosts
		if hosts == nil {
			hosts = []string{}
		}
		cfg.Users = append(cfg.Users, BlockedUser{
			Username:  u.Username,
			Hosts:     hosts,
			Reason:    u.Reason,
			BlockedAt: u.BlockedAt,
		})
	}
	if cfg.Users == nil {
		cfg.Users = []BlockedUser{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"path":   *flagBlockedUsers,
		"config": cfg,
	})
}

func handlePutBlockedUsers(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Config BlockedUsersConfig `json:"config"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	for i, u := range body.Config.Users {
		if u.Username == "" {
			http.Error(w, fmt.Sprintf("user[%d]: username required", i), http.StatusBadRequest)
			return
		}
	}
	if body.Config.Users == nil {
		body.Config.Users = []BlockedUser{}
	}
	policy := store.BlockedPolicy{BlockMessage: body.Config.BlockMessage}
	for _, u := range body.Config.Users {
		hosts := u.Hosts
		if hosts == nil {
			hosts = []string{}
		}
		policy.Users = append(policy.Users, store.BlockedUserEntry{
			Username:  u.Username,
			Hosts:     hosts,
			Reason:    u.Reason,
			BlockedAt: u.BlockedAt,
		})
	}
	if err := sessionStore.SaveBlockedPolicy(r.Context(), policy); err != nil {
		http.Error(w, "write failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	log.Printf("blocked-users: config updated via GUI (%d blocked users)", len(body.Config.Users))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

func handleGetHosts(w http.ResponseWriter, r *http.Request) {
	all, err := cache.get(r.Context())
	if err != nil {
		http.Error(w, "index error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	seen := make(map[string]struct{})
	for _, s := range all {
		if s.Host != "" {
			seen[s.Host] = struct{}{}
		}
	}
	hosts := make([]string, 0, len(seen))
	for h := range seen {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"hosts": hosts})
}

func main() {
	flag.Parse()

	// Initialise storage first — rules and siem config may be loaded from DB.
	var storeErr error
	sessionStore, storeErr = store.New(store.Config{
		Backend:          *flagStorage,
		LogDir:           *flagLogDir,
		BlockedUsersPath: *flagBlockedUsers,
		SiemConfigPath:   *flagSiemConfig,
		RiskRulesPath:    *flagRules,
		S3Bucket:         *flagS3Bucket,
		S3Region:         *flagS3Region,
		S3Prefix:         *flagS3Prefix,
		S3Endpoint:       *flagS3Endpoint,
		S3PathStyle:      *flagS3PathStyle,
		S3AccessKey:      *flagS3AccessKey,
		S3SecretKey:      *flagS3SecretKey,
		DBURL:            *flagDBURL,
		BufferDir:        *flagBufferDir,
	})
	if storeErr != nil {
		log.Fatalf("init storage: %v", storeErr)
	}
	defer sessionStore.Close()

	// Load risk rules from store (file for local, DB for distributed).
	rulesText, err := sessionStore.GetConfig(context.Background(), "risk-rules.yaml")
	if err != nil {
		log.Fatalf("load risk rules: %v", err)
	}
	// In distributed mode the rules are stored in PostgreSQL.  On first
	// deployment the table is empty, so seed it from the -rules file so that
	// scoring works immediately without a manual UI save.
	if rulesText == "" && *flagStorage == "distributed" {
		if data, ferr := os.ReadFile(*flagRules); ferr == nil && len(data) > 0 {
			rulesText = string(data)
			if serr := sessionStore.SetConfig(context.Background(), "risk-rules.yaml", rulesText); serr != nil {
				log.Printf("risk rules: could not seed to DB: %v", serr)
			} else {
				log.Printf("risk rules: seeded %s into distributed config", *flagRules)
			}
		}
	}
	if rulesText == "" {
		log.Printf("risk rules: no config found — scoring disabled")
	} else if err := loadRulesFromText(rulesText); err != nil {
		log.Fatalf("parse risk rules: %v", err)
	}

	// Start SIEM background reload. In distributed mode poll the DB; in local
	// mode use the file-based poller (which has mtime optimisation).
	if *flagStorage == "distributed" {
		siem.LoadWithFunc(func() (string, error) {
			return sessionStore.GetConfig(context.Background(), "siem.yaml")
		})
	} else {
		siem.Load(*flagSiemConfig)
	}

	// Watch for completed sessions and forward to SIEM.
	siemCh := make(chan string, 100)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go sessionStore.WatchSessions(ctx, siemCh)
	go func() {
		for tsid := range siemCh {
			go sendSiemEvent(tsid)
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, "ok")
	})
	mux.HandleFunc("/api/sessions", handleListSessions)
	mux.HandleFunc("/api/session/events", handleSessionEvents)
	mux.HandleFunc("/api/session/frames", handleSessionFrames)
	mux.HandleFunc("/api/session/frame", handleSessionFrame)
	mux.HandleFunc("/api/access-log", handleAccessLog)
	mux.HandleFunc("/metrics", handleMetrics)
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
	mux.HandleFunc("/api/siem-config", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handleGetSiemConfig(w, r)
		case http.MethodPut:
			handlePutSiemConfig(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/api/siem-cert", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		handleUploadSiemCert(w, r)
	})
	mux.HandleFunc("/api/blocked-users", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handleGetBlockedUsers(w, r)
		case http.MethodPut:
			handlePutBlockedUsers(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/api/retention", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handleGetRetention(w, r)
		case http.MethodPut:
			handlePutRetention(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/api/hosts", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		handleGetHosts(w, r)
	})
	mux.HandleFunc("/api/me", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		user := ""
		if *flagTrustedUserHeader != "" {
			user = r.Header.Get(*flagTrustedUserHeader)
		} else if u, _, ok := r.BasicAuth(); ok {
			user = u
		}
		logoutURL := ""
		if *flagTrustedUserHeader != "" {
			logoutURL = "/oauth2/sign_out"
		}
		w.Header().Set("Content-Type", "application/json")
		// user is used in JSON output which is already quoted and escaped by fmt.Fprintf %q
		fmt.Fprintf(w, `{"user":%q,"logoutUrl":%q}`, user, logoutURL)
	})

	staticFS, err := fs.Sub(staticFiles, "static")
	if err != nil {
		log.Fatalf("embed static: %v", err)
	}
	mux.Handle("/", http.FileServer(http.FS(staticFS)))

	// Pre-warm the session cache so the first request is served from cache.
	go func() {
		if _, err := cache.rebuild(ctx); err != nil {
			log.Printf("initial session cache build: %v", err)
		}
	}()

	// Build middleware chain (innermost first):
	//   basicAuth (optional) → accessLog → handler
	var handler http.Handler = mux
	var htStore *htpasswdStore
	if *flagHTPasswd != "" {
		var err error
		htStore, err = newHTPasswd(*flagHTPasswd)
		if err != nil {
			log.Fatalf("htpasswd: %v", err)
		}
		handler = basicAuthMiddleware(handler, htStore)
	}
	handler = accessLogMiddleware(handler, *flagTrustedUserHeader)

	// Build the HTTP server so we can call Shutdown() on SIGTERM.
	var httpSrv *http.Server
	if *flagTLSCert != "" || *flagTLSKey != "" {
		if *flagTLSCert == "" || *flagTLSKey == "" {
			log.Fatal("both -tls-cert and -tls-key must be specified together")
		}
		httpSrv = &http.Server{
			Addr:      *flagListen,
			Handler:   handler,
			TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		}
	} else {
		httpSrv = &http.Server{Addr: *flagListen, Handler: handler}
	}

	// Signal handling: SIGHUP reloads htpasswd; SIGTERM/SIGINT triggers graceful shutdown.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		for sig := range sigCh {
			switch sig {
			case syscall.SIGHUP:
				if htStore != nil {
					if err := htStore.reload(); err != nil {
						log.Printf("htpasswd reload: %v", err)
					}
				}
			default:
				log.Printf("sudo-replay-server: received %v — shutting down", sig)
				shutCtx, shutCancel := context.WithTimeout(context.Background(), 30*time.Second)
				if err := httpSrv.Shutdown(shutCtx); err != nil {
					log.Printf("sudo-replay-server: shutdown: %v", err)
				}
				shutCancel()
			}
		}
	}()

	// Start serving.
	var serveErr error
	if httpSrv.TLSConfig != nil && *flagTLSCert != "" {
		log.Printf("sudo-replay-server listening on %s (TLS), logdir=%s", *flagListen, *flagLogDir)
		serveErr = httpSrv.ListenAndServeTLS(*flagTLSCert, *flagTLSKey)
	} else {
		log.Printf("sudo-replay-server listening on %s, logdir=%s", *flagListen, *flagLogDir)
		serveErr = httpSrv.ListenAndServe()
	}
	if serveErr != nil && serveErr != http.ErrServerClosed {
		log.Fatalf("listen: %v", serveErr)
	}
	log.Printf("sudo-replay-server: shutdown complete")
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

	result, err := listSessions(r.Context(), q, sortBy, order, from, to, limit, offset)
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

	// Record who viewed this session before streaming the response.
	var replayURL string
	if base := strings.TrimRight(siem.Get().ReplayURLBase, "/"); base != "" {
		replayURL = base + "/?tsid=" + url.QueryEscape(tsid)
	} else {
		scheme := "https"
		if r.TLS == nil {
			scheme = "http"
		}
		replayURL = scheme + "://" + r.Host + "/?tsid=" + url.QueryEscape(tsid)
	}
	viewer := viewerFromContext(r)
	recordView(r, tsid, replayURL)
	log.Printf("session-view user=%s addr=%s tsid=%s url=%s", sanitizeForLog(viewer), r.RemoteAddr, tsid, replayURL)

	rc, err := sessionStore.OpenCast(r.Context(), tsid)
	if err != nil {
		log.Printf("open cast %s: %v", tsid, err)
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}
	defer rc.Close()

	// Set headers for streaming NDJSON
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Accel-Buffering", "no") // Disable Nginx buffering
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	enc := json.NewEncoder(w)

	scanner := bufio.NewScanner(rc)
	// Allow for very long lines (e.g. large screen frames or terminal bursts)
	scanner.Buffer(make([]byte, 1024*1024), 10*1024*1024)

	// Skip header line
	if !scanner.Scan() {
		return
	}

	lineCount := 0
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 || line[0] != '[' {
			continue
		}

		var raw [3]json.RawMessage
		if err := json.Unmarshal(line, &raw); err != nil {
			continue
		}

		var relTime float64
		var kind string
		var dataStr string
		_ = json.Unmarshal(raw[0], &relTime)
		_ = json.Unmarshal(raw[1], &kind)
		_ = json.Unmarshal(raw[2], &dataStr)

		evType := 4 // TtyOut
		if kind == "i" {
			evType = 3 // TtyIn
		}

		event := PlaybackEvent{
			T:    relTime,
			Type: evType,
			Data: base64.StdEncoding.EncodeToString([]byte(dataStr)),
		}

		if err := enc.Encode(event); err != nil {
			return
		}

		lineCount++
		// Flush every 100 events to keep the connection alive and the proxy happy
		if ok && lineCount%100 == 0 {
			flusher.Flush()
		}
	}
	if ok {
		flusher.Flush()
	}

	if err := scanner.Err(); err != nil {
		log.Printf("[%s] scan error during streaming: %v", tsid, err)
	}
}

// handleSessionFrames returns a JSON list of screen frame metadata for a GUI session.
// GET /api/session/frames?tsid=<tsid>
func handleSessionFrames(w http.ResponseWriter, r *http.Request) {
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
	sfs, ok := sessionStore.(store.ScreenFrameStore)
	if !ok {
		http.Error(w, "screen frames not supported by storage backend", http.StatusNotImplemented)
		return
	}
	frames, err := sfs.ListFrames(r.Context(), tsid)
	if err != nil {
		http.Error(w, "frames not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(frames)
}

// handleSessionFrame serves one JPEG screen frame.
// GET /api/session/frame?tsid=<tsid>&n=<index>
func handleSessionFrame(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	tsid := r.URL.Query().Get("tsid")
	n, err := strconv.Atoi(r.URL.Query().Get("n"))
	if err != nil || n < 0 {
		http.Error(w, "invalid frame index", http.StatusBadRequest)
		return
	}
	if err := validateTSID(tsid); err != nil {
		http.Error(w, "invalid tsid", http.StatusBadRequest)
		return
	}
	sfs, ok := sessionStore.(store.ScreenFrameStore)
	if !ok {
		http.Error(w, "not supported", http.StatusNotImplemented)
		return
	}
	rc, err := sfs.OpenFrame(r.Context(), tsid, "", n)
	if err != nil {
		http.Error(w, "frame not found", http.StatusNotFound)
		return
	}
	defer rc.Close()
	w.Header().Set("Content-Type", "image/jpeg")
	w.Header().Set("Cache-Control", "public, max-age=86400, immutable")
	io.Copy(w, rc)
}

// handleAccessLog returns the view audit log as JSON, newest entries first.
// Optional query params:
//
//	viewer=alice  — filter to a specific viewer
//	limit=N       — max entries to return (default 200, max 1000)
func handleAccessLog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	filterViewer := r.URL.Query().Get("viewer")
	limit := 200
	if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 && v <= 1000 {
		limit = v
	}

	entries, err := sessionStore.ListAccessLog(r.Context(), filterViewer, limit)
	if err != nil {
		log.Printf("list access log: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(entries); err != nil {
		log.Printf("encode access log: %v", err)
	}
}

// handleMetrics serves a Prometheus text exposition (no external library needed).
// Endpoint: GET /metrics
func handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	sessions, err := cache.get(r.Context())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	var total, active, incomplete int
	byRisk := map[string]int{"low": 0, "medium": 0, "high": 0, "critical": 0}
	for _, s := range sessions {
		total++
		if s.InProgress {
			active++
		}
		if s.Incomplete {
			incomplete++
		}
		byRisk[store.RiskLevel(s.RiskScore)]++
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	fmt.Fprintf(w, "# HELP sudoreplay_sessions_total Total number of recorded sessions.\n")
	fmt.Fprintf(w, "# TYPE sudoreplay_sessions_total gauge\n")
	fmt.Fprintf(w, "sudoreplay_sessions_total %d\n", total)

	fmt.Fprintf(w, "# HELP sudoreplay_sessions_active Sessions currently being recorded.\n")
	fmt.Fprintf(w, "# TYPE sudoreplay_sessions_active gauge\n")
	fmt.Fprintf(w, "sudoreplay_sessions_active %d\n", active)

	fmt.Fprintf(w, "# HELP sudoreplay_sessions_incomplete Sessions that ended without clean termination.\n")
	fmt.Fprintf(w, "# TYPE sudoreplay_sessions_incomplete gauge\n")
	fmt.Fprintf(w, "sudoreplay_sessions_incomplete %d\n", incomplete)

	fmt.Fprintf(w, "# HELP sudoreplay_sessions_by_risk Number of sessions per risk level.\n")
	fmt.Fprintf(w, "# TYPE sudoreplay_sessions_by_risk gauge\n")
	for _, level := range []string{"low", "medium", "high", "critical"} {
		fmt.Fprintf(w, "sudoreplay_sessions_by_risk{level=%q} %d\n", level, byRisk[level])
	}

	fmt.Fprintf(w, "# HELP sudoreplay_session_views_total Total session views via the replay UI since last restart.\n")
	fmt.Fprintf(w, "# TYPE sudoreplay_session_views_total counter\n")
	fmt.Fprintf(w, "sudoreplay_session_views_total %d\n", viewsTotal.Load())
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

// listSessions filters, sorts and paginates sessions from the in-memory cache.
func listSessions(ctx context.Context, q, sortBy, order string, from, to int64, limit, offset int) (*SessionList, error) {
	all, err := cache.get(ctx)
	if err != nil {
		return nil, err
	}

	sessions := make([]SessionInfo, 0, len(all))
	for _, s := range all {
		// Hide eBPF TTY sessions that are matched to a plugin session — the
		// plugin session already appears in the list with full detail.
		// Unmatched eBPF sessions (su, screen, SSH without sudo) are shown.
		if s.Source == "ebpf-tty" && s.MatchedSessionID != "" {
			continue
		}
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
	report, err := buildReport(r.Context(), from, to)
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

func buildReport(ctx context.Context, from, to int64) (*ReportData, error) {
	all, err := cache.get(ctx)
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
	content := string(rulesFileHeader) + string(yamlBody)
	if err := sessionStore.SetConfig(r.Context(), "risk-rules.yaml", content); err != nil {
		log.Printf("write rules: %v", err)
		http.Error(w, "write failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := loadRulesFromText(content); err != nil {
		log.Printf("reload after write: %v", err)
	}
	// Invalidate session cache so next request re-scores with new rules.
	cache.invalidate()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]bool{"ok": true}); err != nil {
		log.Printf("encode rules response: %v", err)
	}
}

// ── Retention API ──────────────────────────────────────────────────────────────

func handleGetRetention(w http.ResponseWriter, r *http.Request) {
	cfgStr, err := sessionStore.GetConfig(r.Context(), "retention_policy")
	if err != nil {
		http.Error(w, "read failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	var policy store.RetentionPolicy
	if cfgStr != "" {
		_ = json.Unmarshal([]byte(cfgStr), &policy)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(policy)
}

func handlePutRetention(w http.ResponseWriter, r *http.Request) {
	var policy store.RetentionPolicy
	if err := json.NewDecoder(r.Body).Decode(&policy); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	data, _ := json.Marshal(policy)
	if err := sessionStore.SetConfig(r.Context(), "retention_policy", string(data)); err != nil {
		http.Error(w, "write failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

// ── SIEM config API ───────────────────────────────────────────────────────────

// handleGetSiemConfig reads the siem config from the store and returns it as JSON.
// Using the store (rather than siem.Get()) ensures the response reflects the
// persisted state even before the background reload cycle fires.
func handleGetSiemConfig(w http.ResponseWriter, r *http.Request) {
	text, err := sessionStore.GetConfig(r.Context(), "siem.yaml")
	if err != nil {
		http.Error(w, "read config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	var cfg siem.Config
	if text != "" {
		if err := yaml.Unmarshal([]byte(text), &cfg); err != nil {
			http.Error(w, "parse config: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{
		"path":   *flagSiemConfig,
		"config": cfg,
	}); err != nil {
		log.Printf("encode siem config: %v", err)
	}
}

// validateTLSPaths returns an error if any non-empty path in c is not an
// absolute path or contains a ".." component.
func validateTLSPaths(label string, c siem.TLSCfg) error {
	for _, p := range []string{c.CA, c.Cert, c.Key} {
		if p == "" {
			continue
		}
		if !filepath.IsAbs(p) {
			return fmt.Errorf("%s TLS path %q must be absolute", label, p)
		}
		// Check the raw path before cleaning — filepath.Clean resolves traversal
		// components (e.g. /a/b/../../etc/passwd → /etc/passwd), which would
		// silently accept the traversal attempt.
		if strings.Contains(p, "..") {
			return fmt.Errorf("%s TLS path %q must not contain '..'", label, p)
		}
	}
	return nil
}

// handlePutSiemConfig validates and persists an updated SIEM config.
// Both servers reload within 30 s (file poller for local, DB poll for distributed).
func handlePutSiemConfig(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Config siem.Config `json:"config"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	cfg := body.Config

	// Validate transport and format values to avoid writing garbage.
	switch cfg.Transport {
	case "", "https", "syslog", "stdout": // ok
	default:
		http.Error(w, "transport must be https, syslog, or stdout", http.StatusBadRequest)
		return
	}
	switch cfg.Format {
	case "", "json", "cef", "ocsf": // ok
	default:
		http.Error(w, "format must be json, cef, or ocsf", http.StatusBadRequest)
		return
	}

	// Validate TLS certificate file paths to prevent path traversal.
	if err := validateTLSPaths("https", cfg.HTTPS.TLS); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := validateTLSPaths("syslog", cfg.Syslog.TLS); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	yamlBytes, err := yaml.Marshal(cfg)
	if err != nil {
		http.Error(w, "marshal yaml: "+err.Error(), http.StatusInternalServerError)
		return
	}
	content := "# SIEM forwarding configuration — managed by sudo-replay GUI\n" +
		"# Reload cycle: 30 s (file poller for local, DB poll for distributed).\n\n" +
		string(yamlBytes)
	if err := sessionStore.SetConfig(r.Context(), "siem.yaml", content); err != nil {
		log.Printf("write siem config: %v", err)
		http.Error(w, "write failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// Apply immediately so this replica doesn't wait for the next reload cycle.
	siem.Set(cfg)
	log.Printf("siem: config updated via GUI (enabled=%v transport=%s format=%s)",
		cfg.Enabled, cfg.Transport, cfg.Format)
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]bool{"ok": true}); err != nil {
		log.Printf("encode siem response: %v", err)
	}
}

// handleUploadSiemCert accepts a PEM file upload (multipart field "file") and
// saves it under /etc/sudo-logger/ with a validated filename.
//
// Only filenames matching [a-zA-Z0-9._-]{1,64}\.(crt|pem|key) are accepted.
// The file must contain at least one PEM block and be ≤ 64 KB.
// Saved with mode 0640 (root:sudologger) so the log server can read it.
func handleUploadSiemCert(w http.ResponseWriter, r *http.Request) {
	if *flagStorage == "distributed" {
		http.Error(w,
			"cert upload is not supported in distributed mode; "+
				"mount certificates via Kubernetes Secrets instead",
			http.StatusNotImplemented)
		return
	}

	const maxSize = 64 * 1024 // 64 KB
	r.Body = http.MaxBytesReader(w, r.Body, maxSize+1024)

	if err := r.ParseMultipartForm(maxSize); err != nil {
		http.Error(w, "file too large or bad multipart: "+err.Error(), http.StatusBadRequest)
		return
	}

	f, hdr, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "missing file field", http.StatusBadRequest)
		return
	}
	defer f.Close()

	name := filepath.Base(hdr.Filename)
	if !validCertName.MatchString(name) {
		http.Error(w, "filename must match [a-zA-Z0-9._-]{1,64}.(crt|pem|key)", http.StatusBadRequest)
		return
	}

	data := make([]byte, maxSize+1)
	n, err := f.Read(data)
	if err != nil && n == 0 {
		http.Error(w, "read file: "+err.Error(), http.StatusBadRequest)
		return
	}
	if n > maxSize {
		http.Error(w, "file exceeds 64 KB limit", http.StatusRequestEntityTooLarge)
		return
	}
	data = data[:n]

	if !containsPEMBlock(data) {
		http.Error(w, "file does not contain a valid PEM block", http.StatusBadRequest)
		return
	}

	destDir := filepath.Dir(*flagSiemConfig) // same dir as siem.yaml, e.g. /etc/sudo-logger
	dest := filepath.Join(destDir, name)

	// Path traversal guard — dest must stay inside destDir.
	if filepath.Dir(dest) != destDir {
		http.Error(w, "invalid filename", http.StatusBadRequest)
		return
	}

	if err := os.WriteFile(dest, data, 0o640); err != nil {
		log.Printf("siem cert upload: write %s: %v", dest, err)
		http.Error(w, "write failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	log.Printf("siem: cert uploaded → %s (%d bytes)", dest, n)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{"path": dest}); err != nil {
		log.Printf("encode cert upload response: %v", err)
	}
}

// validCertName accepts safe filenames with a .crt, .pem, or .key extension.
var validCertName = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,64}\.(crt|pem|key)$`)

// containsPEMBlock returns true if data contains at least one valid PEM block.
func containsPEMBlock(data []byte) bool {
	return bytes.Contains(data, []byte("-----BEGIN "))
}

// ── SIEM forwarding ───────────────────────────────────────────────────────────

// sendSiemEvent looks up the completed session by tsid and forwards it to the
// configured SIEM.
func sendSiemEvent(tsid string) {
	ctx := context.Background()

	// Invalidate the cache so the completed session is visible, then find it.
	cache.invalidate()
	all, err := cache.get(ctx)
	if err != nil {
		log.Printf("siem: list sessions for %s: %v", tsid, err)
		return
	}
	var info *SessionInfo
	for i := range all {
		if all[i].TSID == tsid {
			info = &all[i]
			break
		}
	}
	if info == nil {
		log.Printf("siem: session %s not found after completion", tsid)
		return
	}

	startTime := time.Unix(info.StartTime, 0)
	endTime := startTime.Add(time.Duration(info.Duration * float64(time.Second)))

	siem.Send(siem.Event{
		SessionID:       info.SessionID,
		TSID:            tsid,
		User:            info.User,
		Host:            info.Host,
		RunasUser:       info.Runas,
		RunasUID:        info.RunasUID,
		RunasGID:        info.RunasGID,
		Cwd:             info.Cwd,
		Command:         info.Command,
		ResolvedCommand: info.ResolvedCommand,
		Flags:           info.Flags,
		StartTime:       startTime,
		EndTime:         endTime,
		ExitCode:        info.ExitCode,
		Incomplete:      info.Incomplete,
		RiskScore:       info.RiskScore,
		RiskReasons:     info.RiskReasons,
	})
}

// ── Risk scoring ──────────────────────────────────────────────────────────────

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

// loadRulesFromText parses YAML rules from an in-memory string.
// A empty text is treated as "no rules" and is a no-op.
func loadRulesFromText(text string) error {
	if text == "" {
		return nil
	}
	data := []byte(text)
	hash := computeRulesHash(data)
	rulesMu.RLock()
	unchanged := hash == globalRulesHash
	rulesMu.RUnlock()
	if unchanged {
		return nil
	}
	var rs RuleSet
	if err := yaml.Unmarshal(data, &rs); err != nil {
		return fmt.Errorf("parse rules: %w", err)
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
// Metadata conditions (runas, incomplete, after_hours, min_duration) are ANDed.
// command_base_any, command, and content are ORed with each other — at least
// one must match if any of the three is specified. This allows a single rule
// to catch both "sudo visudo" (command_base_any matches) and "sudo bash →
// type visudo" (content matches) without requiring separate rules.
func matchesRule(rule Rule, s *SessionInfo, cmd, cmdBase string, getContent func() string) bool {
	if rule.Source != "" && s.Source != rule.Source {
		return false
	}
	if rule.ExitCode != nil && s.ExitCode != *rule.ExitCode {
		return false
	}
	if rule.Incomplete != nil {
		// A freeze-timeout is a network event, not a security incident — treat
		// it as "not unexpectedly terminated" for risk scoring purposes so it
		// doesn't accumulate the same score as a shipper-killed session.
		incompleteForSecurity := s.Incomplete && !s.NetworkOutage
		if *rule.Incomplete != incompleteForSecurity {
			return false
		}
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
	// command_base_any, command, and content are all ORed — at least one must
	// match if any is specified.
	hasCmdBase := len(rule.CommandBaseAny) > 0
	hasCmd := rule.Command != nil
	hasCon := rule.Content != nil
	if hasCmdBase || hasCmd || hasCon {
		cmdBaseMatch := false
		if hasCmdBase {
			for _, b := range rule.CommandBaseAny {
				if cmdBase == strings.ToLower(b) {
					cmdBaseMatch = true
					break
				}
			}
		}
		cmdMatch := hasCmd && matchPattern(rule.Command, cmd)
		conMatch := hasCon && matchPattern(rule.Content, getContent())
		if !cmdBaseMatch && !cmdMatch && !conMatch {
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

// loadTtyOut reads "o" (output) events via the store up to maxTtyOutBytes,
// strips ANSI codes, and returns lowercase text for pattern matching.
func loadTtyOut(ctx context.Context, tsid string) string {
	rc, err := sessionStore.OpenCast(ctx, tsid)
	if err != nil {
		return ""
	}
	defer rc.Close()

	return parseTtyOut(rc)
}

// parseTtyOut extracts and lowercases terminal output from a cast reader.
func parseTtyOut(r io.Reader) string {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 2*1024*1024), 2*1024*1024)
	// Skip header line.
	if !scanner.Scan() {
		return ""
	}

	var sb strings.Builder
	for scanner.Scan() {
		if sb.Len() >= maxTtyOutBytes {
			break
		}
		line := scanner.Bytes()
		if len(line) == 0 || line[0] != '[' {
			continue
		}
		var raw [3]json.RawMessage
		if json.Unmarshal(line, &raw) != nil {
			continue
		}
		var kind, data string
		if json.Unmarshal(raw[1], &kind) != nil || kind != "o" {
			continue
		}
		if json.Unmarshal(raw[2], &data) != nil {
			continue
		}
		sb.WriteString(data)
	}
	return strings.ToLower(stripANSI(sb.String()))
}


// scoreSession computes a risk score (0–100) for a session using the globally
// loaded rules.  Results are cached via sessionStore so ttyout is only read
// once per session per rules version.
func scoreSession(s *SessionInfo) (int, []string) {
	rulesMu.RLock()
	rules := globalRules
	rulesHash := globalRulesHash
	rulesMu.RUnlock()

	ctx := context.Background()
	if cached, _ := sessionStore.GetRiskCache(ctx, s.TSID, rulesHash); cached != nil {
		return cached.Score, cached.Reasons
	}

	cmd := strings.ToLower(s.Command)
	cmdBase := ""
	if parts := strings.Fields(s.Command); len(parts) > 0 {
		cmdBase = strings.ToLower(filepath.Base(parts[0]))
	}

	// Lazy ttyout loader — only read from store if a content rule is evaluated.
	var contentOnce sync.Once
	var contentText string
	getContent := func() string {
		contentOnce.Do(func() { contentText = loadTtyOut(ctx, s.TSID) })
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

	_ = sessionStore.SaveRiskCache(ctx, s.TSID, rulesHash, score, reasons)
	return score, reasons
}
