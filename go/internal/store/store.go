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

	// MarkDone removes the ACTIVE marker on a clean session end.
	MarkDone() error

	// WriteExitCode persists the numeric exit code from SESSION_END.
	WriteExitCode(code int32) error

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

	// WatchSessions delivers TSIDs for newly completed sessions to ch.
	// The implementation decides the delivery mechanism:
	//   LocalStore       — fsnotify on the log directory
	//   DistributedStore — DB polling loop
	// The goroutine exits when ctx is cancelled.
	WatchSessions(ctx context.Context, ch chan<- string)

	// Close releases background resources (DB pool, fsnotify watchers, etc.).
	Close() error
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
	Incomplete      bool
	InProgress      bool
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

// RiskCache is the persisted result of a risk-scoring run.
type RiskCache struct {
	RulesHash string
	Score     int
	Level     string
	Reasons   []string
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

	// SiemConfigPath is the path to siem.yaml (LocalStore only).
	// Default: /etc/sudo-logger/siem.yaml
	SiemConfigPath string

	// RiskRulesPath is the path to risk-rules.yaml (LocalStore only).
	// Default: /etc/sudo-logger/risk-rules.yaml
	RiskRulesPath string

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
