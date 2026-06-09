// Package store provides pluggable session storage backends for sudo-logger.
//
// Two backends are available:
//
//   - "local"       — reads/writes sessions on the local filesystem, identical
//     to the original single-node behaviour.  No external dependencies.
//
//   - "distributed" — stores cast files in S3 (or any S3-compatible endpoint
//     such as MinIO or NetApp StorageGRID) and session metadata in PostgreSQL.
//     Allows log-server and replay-server to run as separate, horizontally
//     scalable deployments.
//
// Use New(Config) to obtain a SessionStore.
package store

import (
	"context"
	"fmt"
	"io"
	"time"

	"sudo-logger/internal/iolog"
	"sudo-logger/internal/protocol"
)

// SessionWriter abstracts writing a single session's cast data and lifecycle
// markers.  One writer is created per sudo session and used exclusively by the
// goroutine that handles that connection.
type SessionWriter interface {
	// WriteOutput appends a terminal output ("o") event.
	WriteOutput(data []byte, ts int64) error

	// WriteInput appends a terminal input ("i") event.
	WriteInput(data []byte, ts int64) error

	// MarkActive writes the ACTIVE marker (session is in progress).
	// Called immediately after the session directory / DB row is created.
	MarkActive() error

	// MarkIncomplete writes the INCOMPLETE marker when the connection is lost
	// before a clean SESSION_END.
	MarkIncomplete() error

	// MarkNetworkOutage writes the NETWORK_OUTAGE marker when the session is
	// known to have ended because of network loss (not a agent kill).
	// Called instead of MarkIncomplete when the server received SESSION_FREEZING
	// on the existing connection before the TCP timeout fired.
	MarkNetworkOutage() error

	// MarkDone removes the ACTIVE marker on a clean session end.
	MarkDone() error

	// WriteExitCode persists the numeric exit code from SESSION_END.
	WriteExitCode(code int32) error

	// Flush explicitly flushes the underlying buffer to disk.
	Flush() error

	// Close flushes and releases all resources held by the writer.
	Close() error

	// TSID returns the unique path-safe identifier for this session,
	// e.g. "alice/host1_20260408-120000".
	TSID() string
}

// SessionStore abstracts listing, reading, and watching sessions, as well as
// the blocked-users policy check.  Implementations must be safe for concurrent
// use by multiple goroutines.
type SessionStore interface {
	// CreateSession opens a new recording session and returns its writer.
	// Used only by log-server.
	CreateSession(ctx context.Context, meta iolog.SessionMeta, startTime time.Time) (SessionWriter, error)

	// ListSessions returns metadata for all known sessions.
	// Used by replay-server to build / refresh its in-memory index.
	// The returned slice is a fresh snapshot; callers may sort and filter it.
	ListSessions(ctx context.Context) ([]SessionRecord, error)

	// ReadEvents returns the ordered playback events for the session identified
	// by tsid.  Used by replay-server to stream session content to the browser.
	ReadEvents(ctx context.Context, tsid string) ([]RawEvent, error)

	// OpenCast returns a ReadCloser for the raw session.cast content of tsid.
	// Used by replay-server's risk scorer to read terminal output without going
	// through the full event parse.  Callers must close the returned reader.
	OpenCast(ctx context.Context, tsid string) (io.ReadCloser, error)

	// GetRiskCache loads a previously stored risk score for tsid.
	// Returns nil if the score has not been cached or the stored rules hash
	// does not match rulesHash (i.e. the cache is stale).
	GetRiskCache(ctx context.Context, tsid, rulesHash string) (*RiskCache, error)

	// SaveRiskCache persists a risk score alongside a session so that
	// subsequent requests avoid re-scoring.
	SaveRiskCache(ctx context.Context, tsid, rulesHash string, score int, reasons []string) error

	// IsBlocked reports whether user@host is currently denied by policy.
	// Returns (true, blockMessage, nil) when denied.
	IsBlocked(ctx context.Context, user, host string) (bool, string, error)

	// GetConfig retrieves a named configuration blob (e.g. "siem.yaml",
	// "risk-rules.yaml"). Returns ("", nil) if the key has not been stored yet.
	// LocalStore reads the corresponding file; DistributedStore queries sudo_config.
	GetConfig(ctx context.Context, key string) (string, error)

	// SetConfig stores a named configuration blob.
	// LocalStore writes the corresponding file; DistributedStore upserts sudo_config.
	SetConfig(ctx context.Context, key, value string) error

	// GetBlockedPolicy returns the full blocked-users policy for the GUI.
	// LocalStore reads blocked-users.yaml; DistributedStore queries sudo_blocked_users.
	GetBlockedPolicy(ctx context.Context) (BlockedPolicy, error)

	// SaveBlockedPolicy replaces the full blocked-users policy.
	// LocalStore writes blocked-users.yaml; DistributedStore updates sudo_blocked_users.
	SaveBlockedPolicy(ctx context.Context, policy BlockedPolicy) error

	// IsWhitelisted reports whether user@host should bypass JIT approval.
	IsWhitelisted(ctx context.Context, user, host string) (bool, error)

	// GetWhitelistPolicy returns the full whitelisted-users policy for the GUI.
	GetWhitelistPolicy(ctx context.Context) (WhitelistPolicy, error)

	// SaveWhitelistPolicy replaces the full whitelisted-users policy.
	SaveWhitelistPolicy(ctx context.Context, policy WhitelistPolicy) error

	// MarkSessionNetworkOutage upgrades a session's termination reason from
	// generic INCOMPLETE to NETWORK_OUTAGE.  Called by the log-server when it
	// receives SESSION_FREEZING or SESSION_ABANDON from the agent after the
	// session was already closed.
	// Returns nil if the session is not found (idempotent).
	MarkSessionNetworkOutage(ctx context.Context, sessionID string) error

	// WatchSessions delivers TSIDs for newly completed sessions to ch.
	// The implementation decides the delivery mechanism:
	//   LocalStore       — fsnotify on the log directory
	//   DistributedStore — DB polling loop (advisory lock ensures only one replica forwards)
	// The goroutine exits when ctx is cancelled.
	WatchSessions(ctx context.Context, ch chan<- string)

	// RecordView appends a session-view event to the access log.
	// LocalStore stores it in an in-memory ring buffer (10 000 entries).
	// DistributedStore persists it to the sudo_access_log table.
	RecordView(ctx context.Context, tsid, viewer, replayURL string) error

	// ListAccessLog returns recent session-view events, newest first.
	// viewer filters to a specific viewer when non-empty.
	// limit caps the number of entries (max 1000).
	ListAccessLog(ctx context.Context, viewer string, limit int) ([]AccessLogEntry, error)

	// UpdateDivergenceStatus sets the divergence_status and optionally the
	// matched_session_id for a session identified by tsid.
	// matchedTSID may be empty when no counterpart session exists.
	// Returns nil if the session is not found (idempotent).
	UpdateDivergenceStatus(ctx context.Context, tsid, status, matchedTSID string) error

	// RecordSandboxViolation persists a kernel LSM sandbox alert beside
	// the session identified by sid (session_id).
	RecordSandboxViolation(ctx context.Context, sid string, alert protocol.SandboxAlert) error

	// HasSandboxViolation reports whether any sandbox alerts were recorded
	// for the session identified by tsid.
	HasSandboxViolation(ctx context.Context, tsid string) (bool, error)

	// SaveSudoersSnapshot persists a sudoers snapshot from an agent.
	// Deduplicates by (host, sha256): a snapshot with the same content as a
	// previously stored one for that host is silently ignored.
	SaveSudoersSnapshot(ctx context.Context, snap *protocol.SudoersSnapshot) error

	// ListSudoersSnapshots returns the most recent `limit` snapshots for host,
	// newest first. Used by the replay-server to show history and current state.
	ListSudoersSnapshots(ctx context.Context, host string, limit int) ([]SudoersSnapshotRecord, error)

	// ListSudoersHosts returns the distinct hostnames that have sent at least
	// one snapshot. Used to populate the host list in the Sudoers UI tab.
	ListSudoersHosts(ctx context.Context) ([]string, error)

	// ListSudoersConfigs returns a map of key names (without "sudoers/" prefix)
	// that have a stored configuration.
	ListSudoersConfigs(ctx context.Context) (map[string]bool, error)

	// SaveSudoersError persists a configuration application failure.
	SaveSudoersError(ctx context.Context, err protocol.SudoersError) error

	// GetSudoersError returns the most recent error for a host, if any.
	GetSudoersError(ctx context.Context, host string) (*protocol.SudoersError, error)

	// SaveHeartbeat updates the "last seen" timestamp for host.
	SaveHeartbeat(ctx context.Context, host string) error

	// GetLastSeen returns the unix timestamp (seconds) of the host's last activity.
	GetLastSeen(ctx context.Context, host string) (int64, error)

	// DeleteSession permanently removes a session and all associated data
	// (cast file, risk cache, access log). reason must be non-empty and is
	// persisted in the deletion audit log. deletedBy identifies the caller
	// (e.g. "api", username). Returns an error if the session is still in
	// progress or cannot be found.
	DeleteSession(ctx context.Context, tsid, reason, deletedBy string) error

	// ── User Management ──────────────────────────────────────────────────────

	// GetUser retrieves a user by username. Returns nil if not found.
	GetUser(ctx context.Context, username string) (*User, error)

	// UpsertUser creates or updates a user.
	UpsertUser(ctx context.Context, user User) error

	// ListUsers returns all users.
	ListUsers(ctx context.Context) ([]User, error)

	// DeleteUser removes a user.
	DeleteUser(ctx context.Context, username string) error

	// ── Auth Configuration ───────────────────────────────────────────────────

	// GetAuthConfig returns the current authentication strategy and OIDC/Proxy settings.
	GetAuthConfig(ctx context.Context) (AuthConfig, error)

	// SetAuthConfig saves the authentication strategy and settings.
	SetAuthConfig(ctx context.Context, cfg AuthConfig) error

	// Close releases background resources (DB pool, fsnotify watchers, etc.).
	Close() error
}

// AuthConfig defines the authentication strategy and related settings.
type AuthConfig struct {
	Source string `json:"source" yaml:"source"` // "local", "oidc", "proxy"
	OIDC   struct {
		Issuer       string `json:"issuer" yaml:"issuer"`
		ClientID     string `json:"client_id" yaml:"client_id"`
		ClientSecret string `json:"client_secret" yaml:"client_secret"`
	} `json:"oidc" yaml:"oidc"`
	Proxy struct {
		UserHeader   string `json:"user_header" yaml:"user_header"`
		GroupsHeader string `json:"groups_header" yaml:"groups_header"`
	} `json:"proxy" yaml:"proxy"`
	AdminGroups []string `json:"admin_groups" yaml:"admin_groups"`
}

// User represents a person with access to the replay-server.
type User struct {
	Username     string    `json:"username"`
	PasswordHash string    `json:"-"` // bcrypt hash, only for Source="local"
	Role         string    `json:"role"`     // "admin" | "viewer"
	Source       string    `json:"source"`   // "local" | "oidc" | "proxy"
	FullName     string    `json:"full_name"`
	Email        string    `json:"email"`
	CreatedAt    time.Time `json:"created_at"`
	LastLogin    time.Time `json:"last_login,omitempty"`
}

// ApprovalStore handles the state for the JIT sudo approval system.
// Both LocalStore and DistributedStore implement this interface.
// LocalStore uses an in-memory map + YAML file; DistributedStore uses PostgreSQL.
type ApprovalStore interface {
	// ListApprovalRequests returns all non-expired pending requests.
	ListApprovalRequests(ctx context.Context) ([]ApprovalRequest, error)

	// CreateApprovalRequest persists a new pending request.
	CreateApprovalRequest(ctx context.Context, req ApprovalRequest) error

	// DeleteApprovalRequest removes a request by ID and returns it.
	// Returns (nil, nil) if the ID is not found (idempotent).
	DeleteApprovalRequest(ctx context.Context, id string) (*ApprovalRequest, error)

	// HasApprovalWindow reports whether user@host has an active (non-expired) window.
	// Returns the expiry time and found=true when a valid window exists.
	HasApprovalWindow(ctx context.Context, user, host string) (expiresAt time.Time, found bool, err error)

	// CreateApprovalWindow records a new active window, replacing any previous one
	// for the same user@host.
	CreateApprovalWindow(ctx context.Context, user, host, grantedBy string, expiresAt time.Time) error

	// GetConfig retrieves a named configuration blob.
	GetConfig(ctx context.Context, key string) (string, error)

	// SetConfig stores a named configuration blob.
	SetConfig(ctx context.Context, key, value string) error
}

// ApprovalRequest is a pending sudo approval waiting for an admin decision.
type ApprovalRequest struct {
	ID            string    `json:"id"`
	User          string    `json:"user"`
	Host          string    `json:"host"`
	Command       string    `json:"command"`
	Justification string    `json:"justification"`
	NotifyVia     string    `json:"notify_via"`
	SubmittedAt   time.Time `json:"submitted_at"`
	ExpiresAt     time.Time `json:"expires_at"`
}

// AccessLogEntry records a single session-view event.
type AccessLogEntry struct {
	Time      time.Time `json:"time"`
	Viewer    string    `json:"viewer"`
	TSID      string    `json:"tsid"`
	ReplayURL string    `json:"replay_url,omitempty"`
}

// SessionRecord carries the metadata the replay-server needs to list, filter,
// and display sessions.  It maps directly to the SessionInfo struct used by the
// HTTP API but does not include computed risk fields (those are added by the
// replay-server's scoring layer).
type SessionRecord struct {
	TSID            string
	SessionID       string
	User            string
	Host            string
	Runas           string
	RunasUID        int
	RunasGID        int
	Command         string
	ResolvedCommand string
	Cwd             string
	Flags           string
	StartTime       int64   // unix seconds
	Duration        float64 // seconds; 0 while in progress
	ExitCode        int32
	Incomplete    bool
	NetworkOutage bool // true when terminated by network loss (not a agent kill)
	InProgress    bool
	// Agent v2+ fields (zero value = backward-compatible defaults).
	Source           string // "plugin" | "ebpf-tty" | "ebpf-pkexec"; empty = "plugin"
	ParentSessionID  string // links ebpf-pkexec to its parent session
	HasIO            bool   // false for pkexec background services with no TTY
	DivergenceStatus string // "pending" | "confirmed" | "unwitnessed" | "missing_plugin"
	MatchedSessionID string // TSID of the matched counterpart stream
	CallerProcess    string // process name or service that triggered polkit (dbus-polkit only)
	Cols             int    // terminal width from cast header; 0 if unknown
	Rows             int    // terminal height from cast header; 0 if unknown
}

// RawEvent is a single playback event read from a session cast file.
// It corresponds to one line of an asciinema v2 recording.
type RawEvent struct {
	T    float64 // elapsed seconds from session start
	Kind string  // "o" (output) or "i" (input)
	Data []byte  // raw bytes; callers base64-encode for JSON transport
}

// BlockedUserEntry is a single entry in the blocked-users policy.
type BlockedUserEntry struct {
	Username  string   // required
	Hosts     []string // empty = blocked on all hosts
	Reason    string
	BlockedAt int64 // unix seconds
}

// BlockedPolicy is the full blocked-users configuration.
type BlockedPolicy struct {
	BlockMessage string
	Users        []BlockedUserEntry
}

// WhitelistedUserEntry is a single entry in the whitelisted-users policy.
// Users on this list bypass JIT approval entirely.
type WhitelistedUserEntry struct {
	Username string
	Hosts    []string // empty = all hosts
	Reason   string
}

// WhitelistPolicy is the full whitelisted-users configuration.
type WhitelistPolicy struct {
	Users []WhitelistedUserEntry
}

// SudoersSnapshotRecord is a single stored sudoers snapshot.
type SudoersSnapshotRecord struct {
	Host       string
	SHA256     string
	UploadedAt int64 // unix seconds
	Content    string
}

// RiskCache is the persisted result of a risk-scoring run.
type RiskCache struct {
	RulesHash string
	Score     int
	Level     string
	Reasons   []string
}

// RetentionPolicy defines how long sessions are kept before being deleted.
type RetentionPolicy struct {
	Enabled bool `json:"enabled"`
	Days    int  `json:"days"`
}

// Config carries all backend-specific configuration parsed from CLI flags.
// Fields that are not relevant to the selected backend are ignored.
type Config struct {
	// Backend selects the storage implementation: "local" or "distributed".
	Backend string

	// ── LocalStore fields ────────────────────────────────────────────────────

	// LogDir is the base directory for session recordings.
	// Default: /var/log/sudoreplay
	LogDir string

	// BlockedUsersPath is the YAML file listing blocked users.
	// Default: /etc/sudo-logger/blocked-users.yaml
	BlockedUsersPath string

	// WhitelistedUsersPath is the YAML file listing users who bypass JIT approval.
	// Default: /etc/sudo-logger/whitelisted-users.yaml
	WhitelistedUsersPath string

	// UsersPath is the YAML file listing users and roles for the replay UI.
	// Default: /etc/sudo-logger/users.yaml
	UsersPath string

	// AuthConfigPath is the YAML file containing auth settings (LocalStore only).
	// Default: /etc/sudo-logger/auth-config.yaml
	AuthConfigPath string

	// SiemConfigPath is the path to siem.yaml (LocalStore only).
	// Default: /etc/sudo-logger/siem.yaml
	SiemConfigPath string

	// RiskRulesPath is the path to risk-rules.yaml (LocalStore only).
	// Default: /etc/sudo-logger/risk-rules.yaml
	RiskRulesPath string

	// SandboxConfigPath is the path to sandbox.yaml (LocalStore only).
	// Default: /etc/sudo-logger/sandbox.yaml
	SandboxConfigPath string

	// RetentionPath is the path to retention.json (LocalStore only).
	// Default: /etc/sudo-logger/retention.json
	RetentionPath string

	// SandboxTemplatesPath is the path to sandbox-templates.json (LocalStore only).
	// Default: /etc/sudo-logger/sandbox-templates.json
	SandboxTemplatesPath string

	// ApprovalStorePath is the YAML file used by LocalStore to persist pending
	// approval requests and active windows across restarts.
	// Default: /etc/sudo-logger/approval-store.yaml
	ApprovalStorePath string

	// ApprovalPolicyPath is the path to approval-policy.yaml (LocalStore only).
	// Default: /etc/sudo-logger/approval-policy.yaml
	ApprovalPolicyPath string

	// ── DistributedStore fields ──────────────────────────────────────────────

	// S3Bucket is the bucket used for storing cast files.
	S3Bucket string

	// S3Region is the AWS region (or equivalent) for S3 requests.
	// Default: us-east-1
	S3Region string

	// S3Prefix is the optional key prefix applied to all S3 objects.
	// Default: "sessions/"
	S3Prefix string

	// S3Endpoint overrides the default AWS endpoint.
	// Set to a MinIO or NetApp StorageGRID URL, e.g. https://minio.internal:9000
	S3Endpoint string

	// S3PathStyle forces path-style S3 URLs (required by MinIO and StorageGRID).
	// When S3Endpoint is set this should typically be true.
	S3PathStyle bool

	// S3AccessKey and S3SecretKey are static credentials.
	// When empty the standard AWS credential chain is used
	// (env vars → ~/.aws/credentials → IAM instance profile / IRSA).
	S3AccessKey string
	S3SecretKey string

	// DBURL is the PostgreSQL connection string (DSN).
	// Example: postgres://user@host:5432/dbname?sslmode=require (pass password via PGPASSWORD)
	DBURL string

	// BufferDir is the local directory used as a write-buffer before cast files
	// are uploaded to S3.  In Kubernetes this is typically an emptyDir volume.
	// Default: /var/lib/sudo-logger/buffer
	BufferDir string
}

// RiskLevel converts a numeric risk score to a level string.
// The thresholds mirror the UI display: critical ≥75, high ≥50, medium ≥25.
func RiskLevel(score int) string {
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

// New returns a SessionStore for the backend named by cfg.Backend.
// Returns an error if the backend name is unknown or if required configuration
// fields are missing.
func New(cfg Config) (SessionStore, error) {
	switch cfg.Backend {
	case "", "local":
		return newLocalStore(cfg)
	case "distributed":
		return newDistributedStore(cfg)
	default:
		return nil, fmt.Errorf("unknown storage backend %q (want \"local\" or \"distributed\")", cfg.Backend)
	}
}
