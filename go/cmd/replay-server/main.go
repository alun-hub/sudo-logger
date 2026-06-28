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
	"crypto/sha256"
	"crypto/tls"
	"embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash/fnv"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	_ "time/tzdata" // embed IANA timezone data so TZ env var works in minimal containers

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"

	"sudo-logger/internal/config"
	"sudo-logger/internal/iolog"
	"sudo-logger/internal/siem"
	"sudo-logger/internal/store"
)

//go:embed static
var staticFiles embed.FS



// sessionStore is the active storage backend, initialised in main().
var sessionStore store.SessionStore



// validRoleName matches safe role names: lowercase letters, digits, hyphens, underscores; 1–64 chars.
var validRoleName = regexp.MustCompile(`^[a-z0-9_-]{1,64}$`)



















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

// WhitelistedUser describes a single whitelisted user entry in whitelisted-users.yaml.
type WhitelistedUser struct {
	Username string   `yaml:"username" json:"username"`
	Hosts    []string `yaml:"hosts"    json:"hosts"`
	Reason   string   `yaml:"reason"   json:"reason"`
}

// WhitelistedUsersConfig is the top-level structure of whitelisted-users.yaml.
type WhitelistedUsersConfig struct {
	Users []WhitelistedUser `yaml:"users" json:"users"`
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
	sessions := make([]SessionInfo, 0, len(records))
	for _, rec := range records {
		info := recordToInfo(rec)
		info.RiskScore, info.RiskReasons = scoreSession(&info)
		info.RiskLevel = store.RiskLevel(info.RiskScore)
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
		CallerProcess:    r.CallerProcess,
		Cols:             r.Cols,
		Rows:             r.Rows,
	}
}

// ── Blocked users API ─────────────────────────────────────────────────────────

func handleGetBlockedUsers(w http.ResponseWriter, r *http.Request) {
	if !require(w, r, store.PermConfigRead) {
		return
	}
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
	if !require(w, r, store.PermConfigWrite) {
		return
	}
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

func handleGetWhitelistedUsers(w http.ResponseWriter, r *http.Request) {
	if !require(w, r, store.PermConfigRead) {
		return
	}
	policy, err := sessionStore.GetWhitelistPolicy(r.Context())
	if err != nil {
		http.Error(w, "read config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	cfg := WhitelistedUsersConfig{}
	for _, u := range policy.Users {
		hosts := u.Hosts
		if hosts == nil {
			hosts = []string{}
		}
		cfg.Users = append(cfg.Users, WhitelistedUser{
			Username: u.Username,
			Hosts:    hosts,
			Reason:   u.Reason,
		})
	}
	if cfg.Users == nil {
		cfg.Users = []WhitelistedUser{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"path":   *flagWhitelistedUsers,
		"config": cfg,
	})
}

func handlePutWhitelistedUsers(w http.ResponseWriter, r *http.Request) {
	if !require(w, r, store.PermConfigWrite) {
		return
	}
	var body struct {
		Config WhitelistedUsersConfig `json:"config"`
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
		body.Config.Users = []WhitelistedUser{}
	}
	var policy store.WhitelistPolicy
	for _, u := range body.Config.Users {
		hosts := u.Hosts
		if hosts == nil {
			hosts = []string{}
		}
		policy.Users = append(policy.Users, store.WhitelistedUserEntry{
			Username: u.Username,
			Hosts:    hosts,
			Reason:   u.Reason,
		})
	}
	if err := sessionStore.SaveWhitelistPolicy(r.Context(), policy); err != nil {
		http.Error(w, "write failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	log.Printf("whitelisted-users: config updated via GUI (%d whitelisted users)", len(body.Config.Users))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}



func handleGetUsers(w http.ResponseWriter, r *http.Request) {
	if !require(w, r, store.PermUsersRead) {
		return
	}
	users, err := sessionStore.ListUsers(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}

func handlePutUser(w http.ResponseWriter, r *http.Request) {
	log.Printf("PUT /api/users called")
	// Bootstrap exception: allow creating the first user without admin role.
	if !isBootstrapMode(r) && !require(w, r, store.PermUsersWrite) {
		log.Printf("PUT /api/users: require failed (bootstrap=%v)", isBootstrapMode(r))
		return
	}

	var input struct {
		store.User
		Password string `json:"password_hash"` // We use password_hash field name from UI
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		log.Printf("PUT /api/users: decode failed: %v", err)
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	u := input.User
	log.Printf("PUT /api/users: user=%q, role=%s, source=%s, has_pass=%v", u.Username, u.Role, u.Source, input.Password != "")

	if u.Username == "" {
		http.Error(w, "username required", http.StatusBadRequest)
		return
	}

	// Hash password if provided
	if input.Password != "" {
		log.Printf("PUT /api/users: validating password for %q", u.Username)
		if err := validatePassword(input.Password); err != nil {
			log.Printf("PUT /api/users: password validation failed for %q: %v", u.Username, err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		log.Printf("PUT /api/users: hashing password for %q", u.Username)
		hash, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
		if err != nil {
			log.Printf("PUT /api/users: bcrypt failed for %q: %v", u.Username, err)
			http.Error(w, "hash failed", http.StatusInternalServerError)
			return
		}
		u.PasswordHash = string(hash) // pragma: allowlist secret
		log.Printf("PUT /api/users: password hashed successfully for %q", u.Username)
	} else if u.Source == "local" {
		// Keep existing hash if not changing password
		if existing, _ := sessionStore.GetUser(r.Context(), u.Username); existing != nil {
			u.PasswordHash = existing.PasswordHash // pragma: allowlist secret
		}
	}

	if u.Role == "" {
		u.Role = RoleViewer
	}
	if u.Source == "" {
		u.Source = "local"
	}
	if u.CreatedAt.IsZero() {
		u.CreatedAt = time.Now()
	}

	// Prevent privilege escalation: caller cannot assign a role with permissions they lack.
	if !isBootstrapMode(r) {
		targetPerms := resolveRolePerms(r, u.Role)
		callerPerms := permsFromContext(r)
		for p := range targetPerms {
			if !callerPerms[p] {
				http.Error(w, "cannot assign role with permission you do not hold: "+string(p), http.StatusForbidden)
				return
			}
		}
	}

	if err := sessionStore.UpsertUser(r.Context(), u); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Printf("user %q updated (source=%s, role=%s)", u.Username, u.Source, u.Role)
	w.WriteHeader(http.StatusNoContent)
}

func handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	if !require(w, r, store.PermUsersWrite) {
		return
	}
	username := strings.TrimPrefix(r.URL.Path, "/api/users/")
	if username == "" {
		http.Error(w, "username required", http.StatusBadRequest)
		return
	}

	if err := sessionStore.DeleteUser(r.Context(), username); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Printf("user %q deleted", username)
	w.WriteHeader(http.StatusNoContent)
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
		BlockedUsersPath:     *flagBlockedUsers,
		WhitelistedUsersPath: *flagWhitelistedUsers,
		SiemConfigPath:   *flagSiemConfig,
		RiskRulesPath:    *flagRules,
		SandboxConfigPath: *flagSandbox,
		SandboxTemplatesPath: *flagSandboxTemplates,
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

	// Seed sandbox.yaml into distributed config on first deployment.
	sandboxText, err := sessionStore.GetConfig(context.Background(), "sandbox.yaml")
	if err != nil {
		log.Printf("sandbox config: load: %v", err)
	}
	if sandboxText == "" && *flagStorage == "distributed" {
		if data, ferr := os.ReadFile(*flagSandbox); ferr == nil && len(data) > 0 {
			if serr := sessionStore.SetConfig(context.Background(), "sandbox.yaml", string(data)); serr != nil {
				log.Printf("sandbox config: could not seed to DB: %v", serr)
			} else {
				log.Printf("sandbox config: seeded %s into distributed config", *flagSandbox)
			}
		}
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
	mux.HandleFunc("/api/session/cast", handleSessionCast)
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
	if *flagLogServerAdmin != "" {
		adminBase := strings.TrimRight(*flagLogServerAdmin, "/")
		adminToken, err := config.ResolveSecret(*flagLogServerAdminToken, *flagLogServerAdminTokenFile, "SUDO_LOGGER_ADMIN_TOKEN")
		if err != nil {
			log.Fatalf("admin token: %v", err)
		}
		mux.HandleFunc("/api/approvals", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				if !require(w, r, store.PermApprovalsRead) {
					return
				}
			} else {
				if !require(w, r, store.PermApprovalsDecide) {
					return
				}
			}
			proxyToLogServer(w, r, adminBase+"/api/approvals", adminToken, viewerFromContext(r))
		})
		mux.HandleFunc("/api/approvals/", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				if !require(w, r, store.PermApprovalsRead) {
					return
				}
			} else {
				if !require(w, r, store.PermApprovalsDecide) {
					return
				}
			}
			tail := strings.TrimPrefix(r.URL.Path, "/api/approvals/")
			proxyToLogServer(w, r, adminBase+"/api/approvals/"+tail, adminToken, viewerFromContext(r))
		})
		mux.HandleFunc("/api/approvals/callback", func(w http.ResponseWriter, r *http.Request) {
			// No decidedBy passed — identity is in the callback payload verified by HMAC
			proxyToLogServer(w, r, adminBase+"/api/approvals/callback", adminToken, "")
		})
		mux.HandleFunc("/api/approval-config", func(w http.ResponseWriter, r *http.Request) {
			if !require(w, r, store.PermApprovalsDecide) {
				return
			}
			proxyToLogServer(w, r, adminBase+"/api/approval-config", adminToken, viewerFromContext(r))
		})
		mux.HandleFunc("/api/jit-policy", func(w http.ResponseWriter, r *http.Request) {
			if !require(w, r, store.PermApprovalsDecide) {
				return
			}
			proxyToLogServer(w, r, adminBase+"/api/jit-policy", adminToken, viewerFromContext(r))
		})
		mux.HandleFunc("/api/sessions/", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodDelete {
				http.NotFound(w, r)
				return
			}
			if !require(w, r, store.PermSessionsDelete) {
				return
			}
			tsid := strings.TrimPrefix(r.URL.Path, "/api/sessions/")
			viewer := viewerFromContext(r)
			lrw := &loggingResponseWriter{ResponseWriter: w, status: http.StatusOK}
			proxyToLogServer(lrw, r, adminBase+r.URL.Path, adminToken, viewer)
			if lrw.status == http.StatusNoContent {
				go siem.SendAudit("session_deleted", map[string]any{
					"tsid":       tsid,
					"deleted_by": viewer,
				})
			}
		})
	}

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
	mux.HandleFunc("/api/whitelisted-users", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handleGetWhitelistedUsers(w, r)
		case http.MethodPut:
			handlePutWhitelistedUsers(w, r)
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
	mux.HandleFunc("/api/sandbox", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handleGetSandbox(w, r)
		case http.MethodPut:
			handlePutSandbox(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/api/redaction-config", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handleGetRedactionConfig(w, r)
		case http.MethodPut:
			handlePutRedactionConfig(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/api/sandbox/templates", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handleGetSandboxTemplates(w, r)
		case http.MethodPut:
			handlePutSandboxTemplates(w, r)
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
	mux.HandleFunc("/api/users", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handleGetUsers(w, r)
		case http.MethodPut, http.MethodPost:
			handlePutUser(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/api/users/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.NotFound(w, r)
			return
		}
		handleDeleteUser(w, r)
	})
	mux.HandleFunc("/api/roles", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			if !require(w, r, store.PermUsersRead) {
				return
			}
			roles, err := sessionStore.GetRoles(r.Context())
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(roles)
		case http.MethodPost, http.MethodPut:
			if !require(w, r, store.PermUsersWrite) {
				return
			}
			var def store.RoleDefinition
			if err := json.NewDecoder(r.Body).Decode(&def); err != nil {
				http.Error(w, "invalid JSON", http.StatusBadRequest)
				return
			}
			if !validRoleName.MatchString(def.Name) {
				http.Error(w, "role name must match ^[a-z0-9_-]{1,64}$", http.StatusBadRequest)
				return
			}
			if !requirePermissionsContained(w, r, def.Permissions) {
				return
			}
			if err := sessionStore.UpsertRole(r.Context(), def); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/api/roles/", func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/api/roles/")
		if !validRoleName.MatchString(name) {
			http.Error(w, "role name must match ^[a-z0-9_-]{1,64}$", http.StatusBadRequest)
			return
		}
		switch r.Method {
		case http.MethodGet:
			if !require(w, r, store.PermUsersRead) {
				return
			}
			def, err := sessionStore.GetRole(r.Context(), name)
			if err != nil || def.Name == "" {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(def)
		case http.MethodPut:
			if !require(w, r, store.PermUsersWrite) {
				return
			}
			var def store.RoleDefinition
			if err := json.NewDecoder(r.Body).Decode(&def); err != nil {
				http.Error(w, "invalid JSON", http.StatusBadRequest)
				return
			}
			def.Name = name
			if !requirePermissionsContained(w, r, def.Permissions) {
				return
			}
			if err := sessionStore.UpsertRole(r.Context(), def); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		case http.MethodDelete:
			if !require(w, r, store.PermUsersWrite) {
				return
			}
			if err := sessionStore.DeleteRole(r.Context(), name); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/api/auth-config", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			if !require(w, r, store.PermConfigRead) {
				return
			}
			cfg, err := sessionStore.GetAuthConfig(r.Context())
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			// Mask the secret before sending to client
			if cfg.OIDC.ClientSecret != "" {
				cfg.OIDC.ClientSecret = "***"
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"config": cfg})
			return
		}

		if r.Method == http.MethodPut {
			if !require(w, r, store.PermConfigWrite) {
				return
			}
			var body struct {
				Config store.AuthConfig `json:"config"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, "invalid JSON", http.StatusBadRequest)
				return
			}

			oldCfg, _ := sessionStore.GetAuthConfig(r.Context())

			// If client sends "***" or empty, keep the existing secret
			if body.Config.OIDC.ClientSecret == "***" || body.Config.OIDC.ClientSecret == "" { // pragma: allowlist secret
				body.Config.OIDC.ClientSecret = oldCfg.OIDC.ClientSecret // pragma: allowlist secret
			}

			// Keep existing admin_groups unless client explicitly sends them
			if body.Config.AdminGroups == nil {
				body.Config.AdminGroups = oldCfg.AdminGroups
			}

			if err := sessionStore.SetAuthConfig(r.Context(), body.Config); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	})
	mux.HandleFunc("/api/auth-mapping", func(w http.ResponseWriter, r *http.Request) {
		if !require(w, r, store.PermConfigWrite) {
			return
		}
		if r.Method == http.MethodPut {
			var body struct {
				AdminGroups []string `json:"admin_groups"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, "invalid JSON", http.StatusBadRequest)
				return
			}

			cfg, _ := sessionStore.GetAuthConfig(r.Context())
			cfg.AdminGroups = body.AdminGroups
			if err := sessionStore.SetAuthConfig(r.Context(), cfg); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	})
	mux.HandleFunc("/api/oidc/login", handleOIDCLogin)
	mux.HandleFunc("/api/oidc/callback", handleOIDCCallback)
	mux.HandleFunc("/api/oidc/logout", handleLogout) // Redirect to unified logout
	mux.HandleFunc("/api/login", handleLocalLogin)
	mux.HandleFunc("/logout", handleLogout)
	mux.HandleFunc("/api/me", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		user := viewerFromContext(r)
		if user == "-" {
			user = ""
		}

		cfg, _ := sessionStore.GetAuthConfig(r.Context())
		logoutURL := ""
		if cfg.Source == "oidc" {
			logoutURL = "/api/oidc/logout"
		} else if *flagTrustedUserHeader != "" || cfg.Source == "proxy" {
			logoutURL = "/oauth2/sign_out"
		}

		perms := permsFromContext(r)
		permList := make([]string, 0, len(perms))
		for p := range perms {
			permList = append(permList, string(p))
		}
		sort.Strings(permList)
		permJSON, _ := json.Marshal(permList)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"user":%q,"logoutUrl":%q,"role":%q,"permissions":%s}`, user, logoutURL, roleFromContext(r), permJSON)
	})

	mux.HandleFunc("/api/sudoers/hosts", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		handleGetSudoersHosts(w, r)
	})
	mux.HandleFunc("/api/sudoers/snapshots", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		handleGetSudoersSnapshots(w, r)
	})
	mux.HandleFunc("/api/sudoers/config", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handleGetSudoersConfig(w, r)
		case http.MethodPut:
			handlePutSudoersConfig(w, r)
		case http.MethodDelete:
			handleDeleteSudoersConfig(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	staticFS, err := fs.Sub(staticFiles, "static")
	if err != nil {
		log.Fatalf("embed static: %v", err)
	}
	fileServer := http.FileServer(http.FS(staticFS))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Let the file server handle real static assets (JS, CSS, images).
		// For all other non-API paths, serve index.html so React Router works.
		if _, statErr := fs.Stat(staticFS, strings.TrimPrefix(r.URL.Path, "/")); statErr == nil {
			fileServer.ServeHTTP(w, r)
			return
		}
		idx, err := staticFS.Open("index.html")
		if err != nil {
			http.Error(w, "index.html not found — rebuild the UI first", http.StatusInternalServerError)
			return
		}
		defer idx.Close()
		http.ServeContent(w, r, "index.html", time.Time{}, idx.(io.ReadSeeker))
	})

	// Pre-warm the session cache so the first request is served from cache.
	go func() {
		if _, err := cache.rebuild(ctx); err != nil {
			log.Printf("initial session cache build: %v", err)
		}
	}()

	// Periodically remove expired login sessions from the in-memory store.
	go func() {
		t := time.NewTicker(15 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				loginSessions.purgeExpired()
			case <-ctx.Done():
				return
			}
		}
	}()

	// Seed admin users from --admin-users flag if the store is empty (bootstrap).
	users, _ := sessionStore.ListUsers(context.Background())
	if len(users) == 0 && *flagAdminUsers != "" {
		for _, u := range strings.Split(*flagAdminUsers, ",") {
			if u = strings.TrimSpace(u); u != "" {
				err := sessionStore.UpsertUser(context.Background(), store.User{
					Username: u,
					Role:     string(RoleAdmin),
					Source:   "local", // or "proxy" if they use trusted header
				})
				if err != nil {
					log.Printf("seed admin %q: %v", u, err)
				} else {
					log.Printf("seeded admin user %q from --admin-users flag", u)
				}
			}
		}
	}

	// Build middleware chain (innermost first):
	//   security → basicAuth → accessLog → handler
	var handler http.Handler = mux
	handler = accessLogMiddleware(handler, *flagTrustedUserHeader)
	handler = basicAuthMiddleware(handler)
	handler = securityHeadersMiddleware(handler)

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

	// Signal handling: SIGTERM/SIGINT triggers graceful shutdown.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		for sig := range sigCh {
			log.Printf("sudo-replay-server: received %v — shutting down", sig)
			shutCtx, shutCancel := context.WithTimeout(context.Background(), 30*time.Second)
			if err := httpSrv.Shutdown(shutCtx); err != nil {
				log.Printf("sudo-replay-server: shutdown: %v", err)
			}
			shutCancel()
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
	if !require(w, r, store.PermAuditLogRead) {
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
				Detail: "agent killed mid-session", RiskScore: s.RiskScore,
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
	if !require(w, r, store.PermConfigRead) {
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
	if !require(w, r, store.PermConfigWrite) {
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
	if !require(w, r, store.PermConfigRead) {
		return
	}
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
	if !require(w, r, store.PermConfigWrite) {
		return
	}
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

// ── Redaction config API ──────────────────────────────────────────────────────

func handleGetRedactionConfig(w http.ResponseWriter, r *http.Request) {
	if !require(w, r, store.PermConfigRead) {
		return
	}
	cfgStr, err := sessionStore.GetConfig(r.Context(), "redaction_config")
	if err != nil {
		http.Error(w, "read failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	custom := []string{}
	if cfgStr != "" {
		_ = json.Unmarshal([]byte(cfgStr), &custom)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"system_rules":    iolog.SystemRedactionRules,
		"custom_patterns": custom,
	})
}

func handlePutRedactionConfig(w http.ResponseWriter, r *http.Request) {
	if !require(w, r, store.PermConfigWrite) {
		return
	}
	var body struct {
		CustomPatterns []string `json:"custom_patterns"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	// Sanity check: compile each regex
	for _, p := range body.CustomPatterns {
		if _, err := regexp.Compile(p); err != nil {
			http.Error(w, fmt.Sprintf("invalid regex %q: %v", p, err), http.StatusBadRequest)
			return
		}
	}

	data, _ := json.Marshal(body.CustomPatterns)
	if err := sessionStore.SetConfig(r.Context(), "redaction_config", string(data)); err != nil {
		http.Error(w, "write failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

// ── Sandbox config API ────────────────────────────────────────────────────────

// sandboxYAML mirrors the agent's sandboxYAML struct and is used for strict
// schema validation of sandbox configs submitted via the API.
type sandboxYAML struct {
	Enabled *bool `yaml:"enabled"` // nil → true; explicit false disables enforcement
	// Features must be declared here so that strict (KnownFields) validation in
	// handlePutSandbox accepts a config that carries the feature-flag block —
	// which every config written by the Settings UI does.
	Features struct {
		DenyNetlink         *bool `yaml:"deny_netlink"`
		DenyMount           *bool `yaml:"deny_mount"`
		DenyPtrace          *bool `yaml:"deny_ptrace"`
		DenyCapAuditControl *bool `yaml:"deny_cap_audit_control"`
		DenyCapNetAdmin     *bool `yaml:"deny_cap_net_admin"`
		DenyCapSysModule    *bool `yaml:"deny_cap_sys_module"`
		DenyCapMacAdmin     *bool `yaml:"deny_cap_mac_admin"`
		DenyCapSysRawio     *bool `yaml:"deny_cap_sys_rawio"`
		DenyCapSysBoot      *bool `yaml:"deny_cap_sys_boot"`
		DenySystemdIPC      *bool `yaml:"deny_systemd_ipc"`
	} `yaml:"features"`
	Protect struct {
		Files     []string `yaml:"files"`
		Forbidden []string `yaml:"forbidden"`
		Noexec    []string `yaml:"noexec"`
		Devices   []string `yaml:"devices"`
		Proc      []string `yaml:"proc"`
		Sockets   []string `yaml:"sockets"`
		Processes []string `yaml:"processes"`
	} `yaml:"protect"`
}

const (
	maxSandboxConfigSize  = 1 << 20 // 1 MB — generous for any sandbox.yaml
	maxSandboxTemplates   = 50
	maxSandboxTemplateLen = 64 * 1024 // 64 KB per template
)

func handleGetSandbox(w http.ResponseWriter, r *http.Request) {
	if !require(w, r, store.PermConfigRead) {
		return
	}
	content, err := sessionStore.GetConfig(r.Context(), "sandbox.yaml")
	if err != nil {
		http.Error(w, "read config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{
		"content": content,
		"path":    *flagSandbox,
	}); err != nil {
		log.Printf("encode sandbox config: %v", err)
	}
}

func handlePutSandbox(w http.ResponseWriter, r *http.Request) {
	if !require(w, r, store.PermConfigWrite) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxSandboxConfigSize)
	var body struct {
		Content string `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	// Validate against the typed schema with strict unknown-field rejection.
	if body.Content != "" {
		dec := yaml.NewDecoder(strings.NewReader(body.Content))
		dec.KnownFields(true)
		var check sandboxYAML
		if err := dec.Decode(&check); err != nil {
			http.Error(w, "invalid sandbox config: "+err.Error(), http.StatusBadRequest)
			return
		}
	}
	if err := sessionStore.SetConfig(r.Context(), "sandbox.yaml", body.Content); err != nil {
		http.Error(w, "write failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

func handleGetSandboxTemplates(w http.ResponseWriter, r *http.Request) {
	if !require(w, r, store.PermConfigRead) {
		return
	}
	content, err := sessionStore.GetConfig(r.Context(), "sandbox_templates")
	if err != nil {
		http.Error(w, "read config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if content == "" {
		content = "{}"
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(content))
}

func handlePutSandboxTemplates(w http.ResponseWriter, r *http.Request) {
	if !require(w, r, store.PermConfigWrite) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxSandboxConfigSize)
	var templates map[string]string
	if err := json.NewDecoder(r.Body).Decode(&templates); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if len(templates) > maxSandboxTemplates {
		http.Error(w, fmt.Sprintf("too many templates (max %d)", maxSandboxTemplates), http.StatusBadRequest)
		return
	}
	for name, content := range templates {
		if len(content) > maxSandboxTemplateLen {
			http.Error(w, fmt.Sprintf("template %q exceeds maximum size", name), http.StatusBadRequest)
			return
		}
		if content == "" {
			continue
		}
		dec := yaml.NewDecoder(strings.NewReader(content))
		dec.KnownFields(true)
		var check sandboxYAML
		if err := dec.Decode(&check); err != nil {
			http.Error(w, fmt.Sprintf("template %q: invalid sandbox config: %s", name, err.Error()), http.StatusBadRequest)
			return
		}
	}
	data, err := json.Marshal(templates)
	if err != nil {
		http.Error(w, "marshal failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := sessionStore.SetConfig(r.Context(), "sandbox_templates", string(data)); err != nil {
		http.Error(w, "write failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

// ── Sudoers API ───────────────────────────────────────────────────────────────

// handleGetSudoersHosts returns the union of hosts that have sent snapshots
// and hosts that have recorded sessions, including their override status.
func handleGetSudoersHosts(w http.ResponseWriter, r *http.Request) {
	snapHosts, err := sessionStore.ListSudoersHosts(r.Context())
	if err != nil {
		http.Error(w, "list hosts: "+err.Error(), http.StatusInternalServerError)
		return
	}
	configs, err := sessionStore.ListSudoersConfigs(r.Context())
	if err != nil {
		log.Printf("sudoers configs list: %v", err)
		configs = make(map[string]bool)
	}

	// Merge with session hosts so operators can stage config before first snapshot.
	sessions := cachedListSessions(r.Context())
	{
		seen := make(map[string]struct{}, len(snapHosts))
		for _, h := range snapHosts {
			seen[h] = struct{}{}
		}
		for _, s := range sessions {
			if _, ok := seen[s.Host]; !ok {
				seen[s.Host] = struct{}{}
				snapHosts = append(snapHosts, s.Host)
			}
		}
	}

	type hostJSON struct {
		Name       string `json:"name"`
		IsOverride bool   `json:"isOverride"`
		Error      string `json:"error,omitempty"`
		InSync     bool   `json:"inSync"`
		IsOffline  bool   `json:"isOffline"`
	}

	defaultCfg, _ := sessionStore.GetConfig(r.Context(), "sudoers/_default")
	cleanDefault := stripSudoersHeader(defaultCfg)
	now := time.Now().Unix()

	var out []hostJSON
	for _, h := range snapHosts {
		if h == "_default" {
			continue
		}
		var errMsg string
		if serr, err := sessionStore.GetSudoersError(r.Context(), h); err == nil && serr != nil {
			errMsg = serr.Error
		}

		staged := cleanDefault
		isOverride := false
		if configs[h] {
			cfg, _ := sessionStore.GetConfig(r.Context(), "sudoers/"+h)
			if cfg != "" {
				staged = stripSudoersHeader(cfg)
				isOverride = true
			}
		}

		inSync := false
		isOffline := true

		// Check last seen activity (heartbeats)
		lastSeen, _ := sessionStore.GetLastSeen(r.Context(), h)

		// Check last sudoers activity
		if snaps, err := sessionStore.ListSudoersSnapshots(r.Context(), h, 1); err == nil && len(snaps) > 0 {
			if snaps[0].UploadedAt > lastSeen {
				lastSeen = snaps[0].UploadedAt
			}
			managed := extractManagedSudoers(snaps[0].Content)
			inSync = (staged == managed)
		}

		// Also check last session activity as fallback
		for _, s := range sessions {
			if s.Host == h {
				ts := s.StartTime + int64(s.Duration)
				if s.Duration == 0 && (now-s.StartTime) < 600 {
					ts = now // session recently started, likely still in progress
				}
				if ts > lastSeen {
					lastSeen = ts
				}
			}
		}

		if lastSeen > 0 {
			isOffline = (now - lastSeen) > 600
		}

		out = append(out, hostJSON{h, isOverride, errMsg, inSync, isOffline})
	}
	// Also ensure _default status is correct (it's never an "override", it's the base)
	// but the UI might want to know if it exists.

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(out); err != nil {
		log.Printf("sudoers hosts encode: %v", err)
	}
}

func sha256Sum(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

// handleGetSudoersSnapshots returns the most recent 20 snapshots for a host.
func handleGetSudoersSnapshots(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if host == "" {
		http.Error(w, "host required", http.StatusBadRequest)
		return
	}
	snaps, err := sessionStore.ListSudoersSnapshots(r.Context(), host, 20)
	if err != nil {
		http.Error(w, "list snapshots: "+err.Error(), http.StatusInternalServerError)
		return
	}
	type snapJSON struct {
		SHA256     string `json:"sha256"`
		UploadedAt int64  `json:"uploaded_at"`
		Content    string `json:"content"`
	}
	var out []snapJSON
	for _, s := range snaps {
		out = append(out, snapJSON{s.SHA256, s.UploadedAt, s.Content})
	}
	if out == nil {
		out = []snapJSON{}
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{"host": host, "snapshots": out}); err != nil {
		log.Printf("sudoers snapshots encode: %v", err)
	}
}

// handleGetSudoersConfig returns the staged (desired) config for a host,
// falling back to the _default template if no host-specific config is set.
func handleGetSudoersConfig(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	key := "sudoers/_default"
	isOverride := false
	if host != "" {
		key = "sudoers/" + host
	}
	content, err := sessionStore.GetConfig(r.Context(), key)
	if err != nil {
		http.Error(w, "get config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if host != "" && content == "" {
		// No host-specific config — fall back to _default.
		content, err = sessionStore.GetConfig(r.Context(), "sudoers/_default")
		if err != nil {
			http.Error(w, "get default config: "+err.Error(), http.StatusInternalServerError)
			return
		}
	} else if host != "" && content != "" {
		isOverride = true
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{
		"host":        host,
		"content":     content,
		"is_override": isOverride,
	}); err != nil {
		log.Printf("sudoers config encode: %v", err)
	}
}

// handlePutSudoersConfig stores a desired sudoers config for a host (or the
// global _default when host is empty).
func handlePutSudoersConfig(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, int64(256*1024))
	var body struct {
		Content string `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Validate sudoers syntax before saving
	if body.Content != "" {
		if err := validateSudoers(body.Content); err != nil {
			http.Error(w, "invalid sudoers syntax: "+err.Error(), http.StatusBadRequest)
			return
		}
	}

	host := r.URL.Query().Get("host")
	if host != "" && (len(host) > 255 || host[0] == '.' ||
		strings.ContainsAny(host, "/\\") || strings.Contains(host, "..")) {
		http.Error(w, "invalid host", http.StatusBadRequest)
		return
	}
	key := "sudoers/_default"
	if host != "" {
		key = "sudoers/" + host
	}
	if err := sessionStore.SetConfig(r.Context(), key, body.Content); err != nil {
		http.Error(w, "set config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	log.Printf("sudoers: config updated key=%s by %s", key, viewerFromContext(r))
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

// validateSudoers checks the syntax of content using visudo -c.
func validateSudoers(content string) error {
	tmpFile, err := os.CreateTemp("", "sudoers-valid-*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	if _, err := tmpFile.WriteString(content); err != nil {
		return fmt.Errorf("write temp: %w", err)
	}
	_ = tmpFile.Close()

	// visudo -c -f <file> checks syntax without affecting the system.
	cmd := exec.Command("visudo", "-c", "-f", tmpFile.Name())
	out, err := cmd.CombinedOutput()
	if err != nil {
		// Clean up output to remove the temp filename and just show the error.
		msg := strings.ReplaceAll(string(out), tmpFile.Name(), "sudoers")
		msg = strings.TrimSpace(msg)
		return errors.New(msg)
	}
	return nil
}

func stripSudoersHeader(text string) string {
	lines := strings.Split(text, "\n")
	var out []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" ||
			strings.HasPrefix(trimmed, "# Managed by sudo-logger") ||
			strings.HasPrefix(trimmed, "# Generated:") ||
			strings.HasPrefix(trimmed, "# ---") {
			continue
		}
		// Normalize line: internal spacing and redundant (ALL)
		l := strings.Join(strings.Fields(trimmed), " ")
		l = strings.ReplaceAll(l, "(ALL) ", "")
		l = strings.ReplaceAll(l, "(ALL:ALL) ", "")
		l = strings.ReplaceAll(l, "(ALL)", "")
		l = strings.ReplaceAll(l, "(ALL:ALL)", "")
		// Strip spaces around operators to match visudo variations
		l = strings.ReplaceAll(l, " = ", "=")
		l = strings.ReplaceAll(l, "= ", "=")
		l = strings.ReplaceAll(l, " =", "=")
		l = strings.ReplaceAll(l, " : ", ":")
		l = strings.ReplaceAll(l, ": ", ":")
		l = strings.ReplaceAll(l, " :", ":")
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}

func extractManagedSudoers(full string) string {
	marker := "# --- /etc/sudoers.d/sudo-logger-managed ---"
	idx := strings.Index(full, marker)
	if idx == -1 {
		return ""
	}
	content := full[idx+len(marker):]
	if endIdx := strings.Index(content, "# --- "); endIdx != -1 {
		content = content[:endIdx]
	}
	return stripSudoersHeader(content)
}

// handleDeleteSudoersConfig removes a host-specific config override, causing
// the agent to fall back to the _default template.
func handleDeleteSudoersConfig(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if host == "" {
		http.Error(w, "host required for delete", http.StatusBadRequest)
		return
	}
	if len(host) > 255 || host[0] == '.' ||
		strings.ContainsAny(host, "/\\") || strings.Contains(host, "..") {
		http.Error(w, "invalid host", http.StatusBadRequest)
		return
	}
	if err := sessionStore.SetConfig(r.Context(), "sudoers/"+host, ""); err != nil {
		http.Error(w, "delete config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	log.Printf("sudoers: config deleted for host=%s by %s", host, viewerFromContext(r))
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

// ── SIEM config API ───────────────────────────────────────────────────────────

// handleGetSiemConfig reads the siem config from the store and returns it as JSON.
// Using the store (rather than siem.Get()) ensures the response reflects the
// persisted state even before the background reload cycle fires.
func handleGetSiemConfig(w http.ResponseWriter, r *http.Request) {
	if !require(w, r, store.PermConfigRead) {
		return
	}
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
	if !require(w, r, store.PermConfigWrite) {
		return
	}
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
	log.Printf(`{"time":%q,"event":"config_reload","config":"risk-rules.yaml","sha256":%q,"rules":%d}`,
		time.Now().UTC().Format(time.RFC3339), hash, len(rs.Rules))
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
	log.Printf(`{"time":%q,"event":"config_reload","config":"risk-rules.yaml","sha256":%q,"rules":%d}`,
		time.Now().UTC().Format(time.RFC3339), hash, len(rs.Rules))
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
		// doesn't accumulate the same score as a agent-killed session.
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


func hasViolation(ctx context.Context, tsid string) bool {
	violation, _ := sessionStore.HasSandboxViolation(ctx, tsid)
	return violation
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

	// Sandbox violation check must run before the cache — a violation can be
	// recorded after the session was first scored and cached.
	if s.TSID != "" && hasViolation(ctx, s.TSID) {
		return 100, []string{"Sandbox Violation"}
	}

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
