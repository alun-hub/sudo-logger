package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"path/filepath"
	"sync"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// s3UploadSem limits the number of concurrent S3 uploads so that a burst of
// closing sessions (e.g. after a restart) does not exhaust memory or open
// file descriptors. 8 concurrent uploads is generous for typical deployments.
var s3UploadSem = make(chan struct{}, 8)

// ── DistributedStore ──────────────────────────────────────────────────────────

// DistributedStore implements SessionStore using S3 (or S3-compatible storage
// such as MinIO / NetApp StorageGRID) for cast files and PostgreSQL for session
// metadata, blocked-users policy, and the risk score cache.
type DistributedStore struct {
	cfg  Config
	db   *pgxpool.Pool
	s3   *s3.Client

	stopOnce   sync.Once
	stopCancel context.CancelFunc
}

func newDistributedStore(cfg Config) (*DistributedStore, error) {
	if cfg.S3Bucket == "" {
		return nil, fmt.Errorf("distributed storage: --s3-bucket is required")
	}
	if cfg.DBURL == "" {
		return nil, fmt.Errorf("distributed storage: --db-url is required")
	}
	if cfg.BufferDir == "" {
		cfg.BufferDir = "/var/lib/sudo-logger/buffer"
	}
	if cfg.S3Region == "" {
		cfg.S3Region = "us-east-1"
	}
	if cfg.S3Prefix == "" {
		cfg.S3Prefix = "sessions/"
	}

	// ── PostgreSQL pool ───────────────────────────────────────────────────────
	pool, err := pgxpool.New(context.Background(), cfg.DBURL)
	if err != nil {
		return nil, fmt.Errorf("open postgres pool: %w", err)
	}
	if err := pool.Ping(context.Background()); err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres ping: %w", err)
	}
	if err := applySchema(context.Background(), pool); err != nil {
		pool.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}

	// ── S3 client ─────────────────────────────────────────────────────────────
	s3Client, err := buildS3Client(context.Background(), cfg)
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("build s3 client: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	d := &DistributedStore{
		cfg:        cfg,
		db:         pool,
		s3:         s3Client,
		stopCancel: cancel,
	}
	go d.runCleanupWorker(ctx)
	return d, nil
}

// buildS3Client creates an S3 client supporting AWS, MinIO, and StorageGRID.
func buildS3Client(ctx context.Context, cfg Config) (*s3.Client, error) {
	var awsOpts []func(*awsconfig.LoadOptions) error
	awsOpts = append(awsOpts, awsconfig.WithRegion(cfg.S3Region))

	// Static credentials take priority over the standard chain
	// (env vars / ~/.aws/credentials / IAM instance profile).
	if cfg.S3AccessKey != "" && cfg.S3SecretKey != "" {
		awsOpts = append(awsOpts,
			awsconfig.WithCredentialsProvider(
				credentials.NewStaticCredentialsProvider(cfg.S3AccessKey, cfg.S3SecretKey, ""),
			),
		)
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsOpts...)
	if err != nil {
		return nil, err
	}

	s3Opts := []func(*s3.Options){}
	if cfg.S3Endpoint != "" {
		s3Opts = append(s3Opts, func(o *s3.Options) {
			o.BaseEndpoint = aws.String(cfg.S3Endpoint)
			o.UsePathStyle = cfg.S3PathStyle
		})
	}
	return s3.NewFromConfig(awsCfg, s3Opts...), nil
}

// currentSchemaVersion is incremented whenever the DDL changes.
// applySchema skips the full DDL when the stored version already matches,
// avoiding unnecessary round-trips to PostgreSQL on every startup.
//
// Version history:
//
//	1 — initial schema (sudo_sessions, sudo_risk_cache, sudo_blocked_users, sudo_config, sudo_access_log)
//	2 — added network_outage column to sudo_sessions
//	3 — added sudo_schema_version table; schema version tracking
//	4 — added FOREIGN KEY ON DELETE CASCADE to sudo_access_log
//	5 — added source, parent_session_id, has_io, divergence_status, matched_session_id
//	6 — added caller_process (polkit/dbus calling process name or service)
//	7 — added sandbox_violation column to sudo_sessions
//	8 — added tty_cols, tty_rows to capture terminal dimensions
//	9 — added sudo_approval_requests and sudo_approval_windows for JIT approval
//	10 — added sudo_whitelisted_users for JIT approval bypass
//	11 — added sudo_sudoers_snapshots for sudoers state tracking
//	12 — added sudo_deletion_log for GDPR/audit deletion records
//	13 — added sudo_users for Enterprise RBAC and Auth management
//	14 — added sudo_auth_config for dynamic SSO configuration
//	15 — added sudo_roles for custom role definitions
const currentSchemaVersion = 15

// applySchema creates the required tables when starting up.
// It reads a version number from sudo_schema_version and skips the full DDL
// if the schema is already at the current version, so that production restarts
// do not issue unnecessary DDL round-trips to PostgreSQL.
func applySchema(ctx context.Context, pool *pgxpool.Pool) error {
	// Fast path: check stored version. If the table does not exist yet
	// (fresh install), the query returns an error and we fall through to
	// the full DDL.
	var storedVersion int
	if err := pool.QueryRow(ctx, `SELECT version FROM sudo_schema_version LIMIT 1`).Scan(&storedVersion); err == nil {
		if storedVersion >= currentSchemaVersion {
			return nil
		}
	}

	// Full DDL — all statements are idempotent (IF NOT EXISTS / IF NOT EXISTS).
	if _, err := pool.Exec(ctx, `
CREATE TABLE IF NOT EXISTS sudo_sessions (
    tsid             TEXT PRIMARY KEY,
    session_id       TEXT NOT NULL,
    "user"           TEXT NOT NULL,
    host             TEXT NOT NULL,
    runas            TEXT,
    runas_uid        INT,
    runas_gid        INT,
    command          TEXT,
    resolved_command TEXT,
    cwd              TEXT,
    flags            TEXT,
    start_time       BIGINT NOT NULL,
    duration         DOUBLE PRECISION,
    exit_code        INT,
    incomplete       BOOLEAN DEFAULT FALSE,
    network_outage   BOOLEAN DEFAULT FALSE,
    in_progress      BOOLEAN DEFAULT TRUE,
    created_at       TIMESTAMPTZ DEFAULT NOW(),
    updated_at       TIMESTAMPTZ DEFAULT NOW()
);

-- migration v2: add network_outage to existing deployments
ALTER TABLE sudo_sessions ADD COLUMN IF NOT EXISTS network_outage BOOLEAN DEFAULT FALSE;

CREATE TABLE IF NOT EXISTS sudo_risk_cache (
    tsid        TEXT PRIMARY KEY REFERENCES sudo_sessions(tsid) ON DELETE CASCADE,
    rules_hash  TEXT NOT NULL,
    score       INT,
    level       TEXT,
    reasons     JSONB,
    cached_at   TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS sudo_blocked_users (
    username    TEXT NOT NULL,
    host        TEXT,
    reason      TEXT,
    blocked_at  BIGINT
);
CREATE UNIQUE INDEX IF NOT EXISTS sudo_blocked_users_uk
    ON sudo_blocked_users (username, COALESCE(host, ''));

CREATE TABLE IF NOT EXISTS sudo_config (
    key   TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS sudo_access_log (
    id         BIGSERIAL PRIMARY KEY,
    tsid       TEXT NOT NULL REFERENCES sudo_sessions(tsid) ON DELETE CASCADE,
    viewer     TEXT NOT NULL,
    replay_url TEXT,
    viewed_at  TIMESTAMPTZ DEFAULT NOW()
);

-- migration v4: add cascading delete to existing access log table
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'sudo_access_log') THEN
        -- Only add if not already present (check constraint name)
        IF NOT EXISTS (SELECT 1 FROM information_schema.table_constraints WHERE constraint_name = 'sudo_access_log_tsid_fkey') THEN
            ALTER TABLE sudo_access_log ADD CONSTRAINT sudo_access_log_tsid_fkey FOREIGN KEY (tsid) REFERENCES sudo_sessions(tsid) ON DELETE CASCADE;
        END IF;
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS sudo_access_log_viewer    ON sudo_access_log(viewer);
CREATE INDEX IF NOT EXISTS sudo_access_log_viewed_at ON sudo_access_log(viewed_at DESC);

-- migration v5: eBPF source tracking + divergence status
ALTER TABLE sudo_sessions ADD COLUMN IF NOT EXISTS source             TEXT DEFAULT 'plugin';
ALTER TABLE sudo_sessions ADD COLUMN IF NOT EXISTS parent_session_id  TEXT;
ALTER TABLE sudo_sessions ADD COLUMN IF NOT EXISTS has_io             BOOLEAN DEFAULT TRUE;
ALTER TABLE sudo_sessions ADD COLUMN IF NOT EXISTS divergence_status  TEXT DEFAULT 'pending';
ALTER TABLE sudo_sessions ADD COLUMN IF NOT EXISTS matched_session_id TEXT;

CREATE INDEX IF NOT EXISTS sudo_sessions_source
    ON sudo_sessions(source);
CREATE INDEX IF NOT EXISTS sudo_sessions_parent
    ON sudo_sessions(parent_session_id)
    WHERE parent_session_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS sudo_sessions_div_pending
    ON sudo_sessions(divergence_status)
    WHERE divergence_status != 'confirmed';

-- migration v6: caller_process for polkit/D-Bus events
ALTER TABLE sudo_sessions ADD COLUMN IF NOT EXISTS caller_process TEXT DEFAULT '';
ALTER TABLE sudo_sessions ADD COLUMN IF NOT EXISTS sandbox_violation BOOLEAN DEFAULT FALSE;

-- migration v8: terminal dimensions from cast header
ALTER TABLE sudo_sessions ADD COLUMN IF NOT EXISTS tty_cols INT DEFAULT 0;
ALTER TABLE sudo_sessions ADD COLUMN IF NOT EXISTS tty_rows INT DEFAULT 0;

-- migration v9: JIT sudo approval system
CREATE TABLE IF NOT EXISTS sudo_approval_requests (
    id             TEXT PRIMARY KEY,
    username       TEXT NOT NULL,
    host           TEXT NOT NULL,
    command        TEXT NOT NULL,
    justification  TEXT NOT NULL DEFAULT '',
    notify_via     TEXT NOT NULL DEFAULT '',
    submitted_at   BIGINT NOT NULL,
    expires_at     BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS sudo_approval_requests_user_host
    ON sudo_approval_requests (username, host);

CREATE TABLE IF NOT EXISTS sudo_approval_windows (
    username    TEXT NOT NULL,
    host        TEXT NOT NULL,
    granted_by  TEXT NOT NULL DEFAULT '',
    expires_at  BIGINT NOT NULL,
    PRIMARY KEY (username, host)
);

CREATE TABLE IF NOT EXISTS sudo_schema_version (version INT NOT NULL);

-- migration v10: whitelisted users for JIT approval bypass
CREATE TABLE IF NOT EXISTS sudo_whitelisted_users (
    username TEXT NOT NULL,
    host     TEXT,
    reason   TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS sudo_whitelisted_users_uk
    ON sudo_whitelisted_users (username, COALESCE(host, ''));

-- migration v11: sudoers state snapshots
CREATE TABLE IF NOT EXISTS sudo_sudoers_snapshots (
    id          BIGSERIAL PRIMARY KEY,
    host        TEXT NOT NULL,
    content     TEXT NOT NULL,
    sha256      TEXT NOT NULL,
    uploaded_at BIGINT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS sudo_sudoers_snapshots_host_sha256
    ON sudo_sudoers_snapshots (host, sha256);
CREATE INDEX IF NOT EXISTS sudo_sudoers_snapshots_host_ts
    ON sudo_sudoers_snapshots (host, uploaded_at DESC);

-- migration v12: deletion audit log for GDPR/right-to-erasure requests
CREATE TABLE IF NOT EXISTS sudo_deletion_log (
    id         BIGSERIAL PRIMARY KEY,
    tsid       TEXT NOT NULL,
    reason     TEXT NOT NULL,
    deleted_by TEXT NOT NULL,
    deleted_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS sudo_deletion_log_deleted_at
    ON sudo_deletion_log (deleted_at DESC);

-- migration v13: Enterprise RBAC and Auth management
CREATE TABLE IF NOT EXISTS sudo_users (
    username      TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL DEFAULT '',
    role          TEXT NOT NULL DEFAULT 'viewer',
    source        TEXT NOT NULL DEFAULT 'local',
    full_name     TEXT NOT NULL DEFAULT '',
    email         TEXT NOT NULL DEFAULT '',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login    TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS sudo_users_role ON sudo_users(role);

-- migration v14: Dynamic SSO/Auth configuration
CREATE TABLE IF NOT EXISTS sudo_auth_config (
    id          INT PRIMARY KEY,
    config_json JSONB NOT NULL
);
INSERT INTO sudo_auth_config (id, config_json) VALUES (1, '{}') ON CONFLICT DO NOTHING;

-- migration v15: custom role definitions
CREATE TABLE IF NOT EXISTS sudo_roles (
    name        TEXT PRIMARY KEY,
    description TEXT NOT NULL DEFAULT '',
    permissions JSONB NOT NULL DEFAULT '[]',
    built_in    BOOLEAN NOT NULL DEFAULT FALSE
);
INSERT INTO sudo_roles (name, description, permissions) VALUES
    ('viewer', 'Default viewer: can list and replay own sessions', '["sessions:list_own","sessions:replay_own"]')
ON CONFLICT DO NOTHING;
`); err != nil {
		return err
	}

	// Record current schema version (replace any existing row).
	// Two separate statements: pgx's extended protocol rejects parameters
	// in multi-statement strings.
	if _, err := pool.Exec(ctx, `DELETE FROM sudo_schema_version`); err != nil {
		return err
	}
	_, err := pool.Exec(ctx, `INSERT INTO sudo_schema_version (version) VALUES ($1)`, currentSchemaVersion)
	return err
}

// s3Key converts a TSID to an S3 object key.
func (d *DistributedStore) s3Key(tsid string) string {
	return d.cfg.S3Prefix + tsid + "/session.cast"
}

// bufferPath returns the local write-buffer path for a TSID.
func (d *DistributedStore) bufferPath(tsid string) string {
	return filepath.Join(d.cfg.BufferDir, filepath.FromSlash(tsid), "session.cast")
}


// runCleanupWorker periodically deletes old sessions based on the configured
// retention policy. It runs once a day.
func (d *DistributedStore) runCleanupWorker(ctx context.Context) {
	// 0x434c4e50 = "CLNP" in ASCII
	const cleanupLockID int64 = 0x434c4e50

	// Initial delay to let the system settle on startup.
	select {
	case <-ctx.Done():
		return
	case <-time.After(1 * time.Minute):
		d.doCleanup(ctx, cleanupLockID)
	}

	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.doCleanup(ctx, cleanupLockID)
		}
	}
}

func (d *DistributedStore) doCleanup(ctx context.Context, lockID int64) {
	// Try to acquire the session-level advisory lock. Only one replica performs cleanup.
	var locked bool
	if err := d.db.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", lockID).Scan(&locked); err != nil {
		log.Printf("store/distributed: cleanup: advisory lock: %v", err)
		return
	}
	if !locked {
		return
	}
	// Note: PostgreSQL session-level advisory locks are held for the lifetime
	// of the connection. We use pg_advisory_unlock explicitly so other replicas
	// could potentially run sooner if this pod restarts.
	defer func() {
		_, _ = d.db.Exec(ctx, "SELECT pg_advisory_unlock($1)", lockID)
	}()

	// Expired approval requests are independent of the session retention
	// policy below, so purge them unconditionally on every cleanup pass.
	if tag, err := d.db.Exec(ctx, "DELETE FROM sudo_approval_requests WHERE expires_at < $1",
		time.Now().Unix()); err != nil {
		log.Printf("store/distributed: cleanup: delete expired approval requests: %v", err)
	} else if n := tag.RowsAffected(); n > 0 {
		log.Printf("store/distributed: cleanup: removed %d expired approval request(s)", n)
	}

	// Fetch retention policy from config.
	cfgStr, err := d.GetConfig(ctx, "retention_policy")
	if err != nil || cfgStr == "" {
		return
	}
	var policy RetentionPolicy
	if err := json.Unmarshal([]byte(cfgStr), &policy); err != nil {
		log.Printf("store/distributed: cleanup: parse policy: %v", err)
		return
	}
	if !policy.Enabled || policy.Days <= 0 {
		return
	}

	threshold := time.Now().AddDate(0, 0, -policy.Days).Unix()

	// Find expired sessions that are not in progress.
	rows, err := d.db.Query(ctx,
		"SELECT tsid FROM sudo_sessions WHERE start_time < $1 AND in_progress = FALSE",
		threshold)
	if err != nil {
		log.Printf("store/distributed: cleanup: query expired: %v", err)
		return
	}
	defer rows.Close()

	var tsids []string
	for rows.Next() {
		var tsid string
		if err := rows.Scan(&tsid); err == nil {
			tsids = append(tsids, tsid)
		}
	}
	rows.Close()

	if len(tsids) == 0 {
		return
	}

	log.Printf("store/distributed: cleanup: removing %d expired session(s) (older than %d days)", len(tsids), policy.Days)

	for _, tsid := range tsids {
		// 1. Delete all S3 objects for this session.
		d.deleteS3Session(ctx, tsid)

		// 2. Delete the session row. Cascades to risk_cache and access_log.
		if _, err := d.db.Exec(ctx, "DELETE FROM sudo_sessions WHERE tsid = $1", tsid); err != nil {
			log.Printf("store/distributed: cleanup: delete row %s: %v", tsid, err)
		}
	}
	log.Printf("store/distributed: cleanup: finished removing %d session(s)", len(tsids))
}

func (d *DistributedStore) deleteS3Session(ctx context.Context, tsid string) {
	prefix := d.cfg.S3Prefix + tsid + "/"
	paginator := s3.NewListObjectsV2Paginator(d.s3, &s3.ListObjectsV2Input{
		Bucket: aws.String(d.cfg.S3Bucket),
		Prefix: aws.String(prefix),
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			log.Printf("store/distributed: cleanup: list objects for %s: %v", tsid, err)
			return
		}
		if len(page.Contents) == 0 {
			continue
		}

		var objects []s3types.ObjectIdentifier
		for _, obj := range page.Contents {
			objects = append(objects, s3types.ObjectIdentifier{Key: obj.Key})
		}

		_, err = d.s3.DeleteObjects(ctx, &s3.DeleteObjectsInput{
			Bucket: aws.String(d.cfg.S3Bucket),
			Delete: &s3types.Delete{
				Objects: objects,
				Quiet:   aws.Bool(true),
			},
		})
		if err != nil {
			log.Printf("store/distributed: cleanup: delete objects for %s: %v", tsid, err)
		}
	}
}


// Close implements SessionStore.
func (d *DistributedStore) Close() error {
	d.stopOnce.Do(func() {
		d.stopCancel()
		d.db.Close()
	})
	return nil
}

// ── Config API ────────────────────────────────────────────────────────────────

// GetConfig retrieves a named config blob from sudo_config.
// Returns ("", nil) when the key does not exist yet.
func (d *DistributedStore) GetConfig(ctx context.Context, key string) (string, error) {
	var value string
	err := d.db.QueryRow(ctx, `SELECT value FROM sudo_config WHERE key = $1`, key).Scan(&value)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", nil
		}
		return "", err
	}
	return value, nil
}

// SetConfig upserts a named config blob into sudo_config.
func (d *DistributedStore) SetConfig(ctx context.Context, key, value string) error {
	if value == "" {
		_, err := d.db.Exec(ctx, `DELETE FROM sudo_config WHERE key = $1`, key)
		return err
	}
	_, err := d.db.Exec(ctx, `
INSERT INTO sudo_config (key, value) VALUES ($1, $2)
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`,
		key, value)
	return err
}

// ── Blocked-users policy API ──────────────────────────────────────────────────


func toJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}
