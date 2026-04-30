package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"sudo-logger/internal/iolog"
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

	stopOnce sync.Once
	stopCh   chan struct{}
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

	d := &DistributedStore{
		cfg:    cfg,
		db:     pool,
		s3:     s3Client,
		stopCh: make(chan struct{}),
	}
	go d.runCleanupWorker(context.Background())
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
const currentSchemaVersion = 5

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

CREATE TABLE IF NOT EXISTS sudo_schema_version (version INT NOT NULL);
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

// s3FrameKey returns the S3 key for screen frame n of tsid.
func (d *DistributedStore) s3FrameKey(tsid string, n int) string {
	return fmt.Sprintf("%s%s/frames/%08d.jpg", d.cfg.S3Prefix, tsid, n)
}

// HasFrames implements ScreenFrameStore — cheap HeadObject on frame 0.
func (d *DistributedStore) HasFrames(ctx context.Context, tsid string) (bool, error) {
	_, err := d.s3.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(d.cfg.S3Bucket),
		Key:    aws.String(d.s3FrameKey(tsid, 0)),
	})
	if err != nil {
		return false, nil // not found or any error → no frames
	}
	return true, nil
}

// ListFrames lists screen frame metadata stored in S3 for tsid.
// Timestamps are read from the x-amz-meta-ts object metadata set by WriteScreenFrame.
func (d *DistributedStore) ListFrames(ctx context.Context, tsid string) ([]ScreenFrameInfo, error) {
	prefix := fmt.Sprintf("%s%s/frames/", d.cfg.S3Prefix, tsid)
	var frames []ScreenFrameInfo
	paginator := s3.NewListObjectsV2Paginator(d.s3, &s3.ListObjectsV2Input{
		Bucket: aws.String(d.cfg.S3Bucket),
		Prefix: aws.String(prefix),
	})
	idx := 0
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list frames: %w", err)
		}
		for _, obj := range page.Contents {
			// Fetch per-object metadata to retrieve the capture timestamp.
			var ts int64
			if head, herr := d.s3.HeadObject(ctx, &s3.HeadObjectInput{
				Bucket: aws.String(d.cfg.S3Bucket),
				Key:    obj.Key,
			}); herr == nil {
				if tsStr, ok := head.Metadata["ts"]; ok {
					ts, _ = strconv.ParseInt(tsStr, 10, 64)
				}
			}
			frames = append(frames, ScreenFrameInfo{
				Index: idx,
				Ts:    ts,
				Size:  int(aws.ToInt64(obj.Size)),
			})
			idx++
		}
	}
	return frames, nil
}

// OpenFrame returns a ReadCloser for screen frame n of tsid, fetched from S3.
func (d *DistributedStore) OpenFrame(ctx context.Context, tsid, _ string, n int) (io.ReadCloser, error) {
	out, err := d.s3.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(d.cfg.S3Bucket),
		Key:    aws.String(d.s3FrameKey(tsid, n)),
	})
	if err != nil {
		return nil, fmt.Errorf("get frame %d: %w", n, err)
	}
	return out.Body, nil
}

// bufferPath returns the local write-buffer path for a TSID.
func (d *DistributedStore) bufferPath(tsid string) string {
	return filepath.Join(d.cfg.BufferDir, filepath.FromSlash(tsid), "session.cast")
}

// ── SessionStore implementation ───────────────────────────────────────────────

// CreateSession implements SessionStore.
func (d *DistributedStore) CreateSession(ctx context.Context, meta iolog.SessionMeta, startTime time.Time) (SessionWriter, error) {
	// Let iolog.NewWriter create the buffer directory (with session-ID suffix for
	// uniqueness). We then derive tsid from the actual directory path so there
	// is a single source of truth for the naming scheme.
	w, err := iolog.NewWriter(d.cfg.BufferDir, meta, startTime)
	if err != nil {
		return nil, fmt.Errorf("create iolog writer: %w", err)
	}
	rel, err := filepath.Rel(d.cfg.BufferDir, w.Dir())
	if err != nil {
		_ = w.Close()
		return nil, fmt.Errorf("derive tsid from buffer path: %w", err)
	}
	tsid := filepath.ToSlash(rel)

	divStatus := meta.DivergenceStatus
	if divStatus == "" {
		divStatus = "unwitnessed"
	}
	_, err = d.db.Exec(ctx, `
INSERT INTO sudo_sessions
  (tsid, session_id, "user", host, runas, runas_uid, runas_gid,
   command, resolved_command, cwd, flags, start_time, in_progress,
   source, parent_session_id, has_io, divergence_status)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,TRUE,$13,$14,$15,$16)
ON CONFLICT (tsid) DO NOTHING`,
		tsid, meta.SessionID, meta.User, meta.Host,
		meta.RunasUser, meta.RunasUID, meta.RunasGID,
		meta.Command, meta.ResolvedCommand, meta.Cwd, meta.Flags,
		startTime.Unix(),
		meta.Source, meta.ParentSessionID, meta.HasIO, divStatus,
	)
	if err != nil {
		_ = w.Close()
		return nil, fmt.Errorf("insert session row: %w", err)
	}

	return &distributedWriter{w: w, tsid: tsid, d: d, startTime: startTime}, nil
}

// ListSessions implements SessionStore.
func (d *DistributedStore) ListSessions(ctx context.Context) ([]SessionRecord, error) {
	rows, err := d.db.Query(ctx, `
SELECT tsid, session_id, "user", host, runas, runas_uid, runas_gid,
       command, resolved_command, cwd, flags, start_time,
       COALESCE(duration, 0), COALESCE(exit_code, 0),
       incomplete, network_outage, in_progress,
       COALESCE(source, 'plugin'), COALESCE(parent_session_id, ''),
       COALESCE(has_io, TRUE), COALESCE(divergence_status, 'unwitnessed'),
       COALESCE(matched_session_id, '')
FROM sudo_sessions
ORDER BY start_time DESC`)
	if err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}
	defer rows.Close()

	var records []SessionRecord
	for rows.Next() {
		var r SessionRecord
		if err := rows.Scan(
			&r.TSID, &r.SessionID, &r.User, &r.Host, &r.Runas,
			&r.RunasUID, &r.RunasGID, &r.Command, &r.ResolvedCommand,
			&r.Cwd, &r.Flags, &r.StartTime, &r.Duration, &r.ExitCode,
			&r.Incomplete, &r.NetworkOutage, &r.InProgress,
			&r.Source, &r.ParentSessionID, &r.HasIO,
			&r.DivergenceStatus, &r.MatchedSessionID,
		); err != nil {
			return nil, fmt.Errorf("scan session row: %w", err)
		}
		records = append(records, r)
	}
	return records, rows.Err()
}

// ReadEvents implements SessionStore.
func (d *DistributedStore) ReadEvents(ctx context.Context, tsid string) ([]RawEvent, error) {
	rc, err := d.OpenCast(ctx, tsid)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return parseRawEvents(rc)
}

// OpenCast implements SessionStore.
// For in-progress sessions it reads from the local buffer; completed sessions
// are fetched from S3.
func (d *DistributedStore) OpenCast(ctx context.Context, tsid string) (io.ReadCloser, error) {
	// Check local buffer first (covers in-progress and recently completed sessions).
	bufPath := d.bufferPath(tsid)
	if f, err := os.Open(bufPath); err == nil {
		return f, nil
	}
	// Fetch from S3.
	out, err := d.s3.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(d.cfg.S3Bucket),
		Key:    aws.String(d.s3Key(tsid)),
	})
	if err != nil {
		// If the session is still in-progress the cast file has not been
		// uploaded to S3 yet (it lives on the log-server pod).  Return a
		// minimal empty cast so callers get an empty event list without error.
		var inProgress bool
		if dbErr := d.db.QueryRow(ctx,
			`SELECT in_progress FROM sudo_sessions WHERE tsid=$1`, tsid,
		).Scan(&inProgress); dbErr == nil && inProgress {
			header := `{"version":2,"width":80,"height":24}` + "\n"
			return io.NopCloser(strings.NewReader(header)), nil
		}
		return nil, fmt.Errorf("s3 get %s: %w", tsid, err)
	}
	return out.Body, nil
}

// GetRiskCache implements SessionStore.
func (d *DistributedStore) GetRiskCache(ctx context.Context, tsid, rulesHash string) (*RiskCache, error) {
	var rc RiskCache
	var reasons []byte
	err := d.db.QueryRow(ctx,
		`SELECT rules_hash, score, level, reasons FROM sudo_risk_cache WHERE tsid=$1`,
		tsid,
	).Scan(&rc.RulesHash, &rc.Score, &rc.Level, &reasons)
	if err != nil {
		return nil, nil // cache miss
	}
	if rc.RulesHash != rulesHash {
		return nil, nil // stale
	}
	if err := json.Unmarshal(reasons, &rc.Reasons); err != nil {
		return nil, nil
	}
	return &rc, nil
}

// SaveRiskCache implements SessionStore.
func (d *DistributedStore) SaveRiskCache(ctx context.Context, tsid, rulesHash string, score int, reasons []string) error {
	reasonsJSON, err := json.Marshal(reasons)
	if err != nil {
		return err
	}
	_, err = d.db.Exec(ctx, `
INSERT INTO sudo_risk_cache (tsid, rules_hash, score, level, reasons, cached_at)
VALUES ($1,$2,$3,$4,$5,NOW())
ON CONFLICT (tsid) DO UPDATE
  SET rules_hash=EXCLUDED.rules_hash,
      score=EXCLUDED.score,
      level=EXCLUDED.level,
      reasons=EXCLUDED.reasons,
      cached_at=NOW()`,
		tsid, rulesHash, score, RiskLevel(score), reasonsJSON,
	)
	return err
}

// MarkSessionNetworkOutage implements SessionStore.
// Updates the session row by session_id (not tsid) — the server receives
// SESSION_ABANDON on a new connection and only has the session_id at hand.
func (d *DistributedStore) MarkSessionNetworkOutage(ctx context.Context, sessionID string) error {
	_, err := d.db.Exec(ctx,
		`UPDATE sudo_sessions SET network_outage=TRUE, updated_at=NOW() WHERE session_id=$1`,
		sessionID)
	return err
}

// UpdateDivergenceStatus implements SessionStore.
func (d *DistributedStore) UpdateDivergenceStatus(ctx context.Context, tsid, status, matchedTSID string) error {
	_, err := d.db.Exec(ctx,
		`UPDATE sudo_sessions
		    SET divergence_status=$2,
		        matched_session_id=NULLIF($3,''),
		        updated_at=NOW()
		  WHERE tsid=$1`,
		tsid, status, matchedTSID)
	return err
}

// IsBlocked implements SessionStore.
func (d *DistributedStore) IsBlocked(ctx context.Context, user, host string) (bool, string, error) {
	var reason string
	err := d.db.QueryRow(ctx, `
SELECT COALESCE((SELECT value FROM sudo_config WHERE key='block_message'),'')
FROM sudo_blocked_users
WHERE username=$1 AND (host=$2 OR host IS NULL)
LIMIT 1`,
		user, host,
	).Scan(&reason)
	if err != nil {
		return false, "", nil // no match
	}
	return true, reason, nil
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

// WatchSessions implements SessionStore.
// Polls sudo_sessions every 5 s for newly completed sessions and sends their
// TSIDs to ch.
//
// In distributed deployments multiple replicas may run concurrently. A
// PostgreSQL session-level advisory lock (pg_try_advisory_lock) ensures only
// one replica forwards events. If the lock-holder pod dies, the DB connection
// closes and PostgreSQL releases the lock automatically; a waiting replica
// acquires it within 30 seconds.
func (d *DistributedStore) WatchSessions(ctx context.Context, ch chan<- string) {
	// Acquire a dedicated connection so the advisory lock stays on one
	// connection for the lifetime of this goroutine.
	conn, err := d.db.Acquire(ctx)
	if err != nil {
		log.Printf("store/distributed: WatchSessions: acquire conn: %v", err)
		return
	}
	defer conn.Release()

	// 0x5349454d = "SIEM" in ASCII — arbitrary but stable identifier.
	const siemLockID int64 = 0x5349454d

	// Try to acquire the session-level advisory lock. Retry every 30 s when
	// another replica already holds it; PostgreSQL releases the lock automatically
	// if the holding connection drops.
	for {
		var locked bool
		if err := conn.QueryRow(ctx,
			"SELECT pg_try_advisory_lock($1)", siemLockID).Scan(&locked); err != nil {
			log.Printf("store/distributed: WatchSessions: advisory lock: %v", err)
			return
		}
		if locked {
			break
		}
		log.Printf("store/distributed: WatchSessions: another replica holds the SIEM leader lock — retrying in 30 s")
		select {
		case <-ctx.Done():
			return
		case <-time.After(30 * time.Second):
		}
	}
	log.Printf("store/distributed: WatchSessions: acquired SIEM leader lock")

	// Use a DB-side timestamp for lastCheck so there is no skew between the
	// Go server clock and the PostgreSQL clock (updated_at is set by NOW()).
	var lastCheck time.Time
	if err := conn.QueryRow(ctx, `SELECT NOW()`).Scan(&lastCheck); err != nil {
		log.Printf("store/distributed: WatchSessions: initial timestamp: %v", err)
		lastCheck = time.Now()
	}
	log.Printf("store/distributed: WatchSessions: starting poll from %s", lastCheck.UTC().Format(time.RFC3339))

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Fetch the current DB time before querying so we do not miss
			// sessions that complete between the SELECT and the next tick.
			var pollUntil time.Time
			if err := conn.QueryRow(ctx, `SELECT NOW()`).Scan(&pollUntil); err != nil {
				log.Printf("store/distributed: watch poll timestamp: %v", err)
				continue
			}
			rows, err := conn.Query(ctx, `
SELECT tsid FROM sudo_sessions
WHERE updated_at > $1 AND updated_at <= $2 AND in_progress = FALSE
ORDER BY updated_at ASC`,
				lastCheck, pollUntil,
			)
			if err != nil {
				log.Printf("store/distributed: watch poll: %v", err)
				continue
			}
			var found int
			for rows.Next() {
				var tsid string
				if rows.Scan(&tsid) == nil {
					found++
					log.Printf("store/distributed: WatchSessions: session completed: %s", tsid)
					select {
					case ch <- tsid:
					default:
						log.Printf("store/distributed: WatchSessions: siemCh full, dropping %s", tsid)
					}
				}
			}
			rows.Close()
			if found > 0 {
				log.Printf("store/distributed: WatchSessions: forwarded %d session(s) to SIEM", found)
			}
			lastCheck = pollUntil
		}
	}
}

// RecordView implements SessionStore.
// Inserts a session-view event into sudo_access_log.
func (d *DistributedStore) RecordView(ctx context.Context, tsid, viewer, replayURL string) error {
	_, err := d.db.Exec(ctx,
		`INSERT INTO sudo_access_log (tsid, viewer, replay_url) VALUES ($1, $2, $3)`,
		tsid, viewer, replayURL,
	)
	return err
}

// ListAccessLog implements SessionStore.
// Returns entries from sudo_access_log, newest first, filtered by viewer.
func (d *DistributedStore) ListAccessLog(ctx context.Context, viewer string, limit int) ([]AccessLogEntry, error) {
	var rows interface{ Next() bool; Scan(...any) error; Close() }
	var err error
	if viewer != "" {
		rows, err = d.db.Query(ctx, `
SELECT tsid, viewer, COALESCE(replay_url,''), viewed_at
FROM sudo_access_log
WHERE viewer = $1
ORDER BY viewed_at DESC
LIMIT $2`, viewer, limit)
	} else {
		rows, err = d.db.Query(ctx, `
SELECT tsid, viewer, COALESCE(replay_url,''), viewed_at
FROM sudo_access_log
ORDER BY viewed_at DESC
LIMIT $1`, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []AccessLogEntry
	for rows.Next() {
		var e AccessLogEntry
		if err := rows.Scan(&e.TSID, &e.Viewer, &e.ReplayURL, &e.Time); err != nil {
			return nil, err
		}
		result = append(result, e)
	}
	if result == nil {
		result = []AccessLogEntry{}
	}
	return result, nil
}

// Close implements SessionStore.
func (d *DistributedStore) Close() error {
	d.stopOnce.Do(func() {
		close(d.stopCh)
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
	_, err := d.db.Exec(ctx, `
INSERT INTO sudo_config (key, value) VALUES ($1, $2)
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`,
		key, value)
	return err
}

// ── Blocked-users policy API ──────────────────────────────────────────────────

// GetBlockedPolicy reads all blocked-user rows and returns them as a BlockedPolicy.
// Multiple rows with the same username (different hosts) are merged into one entry.
func (d *DistributedStore) GetBlockedPolicy(ctx context.Context) (BlockedPolicy, error) {
	// Block message is stored separately in sudo_config.
	var blockMsg string
	rows, err := d.db.Query(ctx, `SELECT value FROM sudo_config WHERE key = 'block_message'`)
	if err == nil {
		if rows.Next() {
			_ = rows.Scan(&blockMsg)
		}
		rows.Close()
	}

	// Read all blocked users.
	urows, err := d.db.Query(ctx, `
SELECT username, host, reason, blocked_at
FROM sudo_blocked_users
ORDER BY username, host NULLS FIRST`)
	if err != nil {
		return BlockedPolicy{}, err
	}
	defer urows.Close()

	type row struct {
		username  string
		host      *string
		reason    *string
		blockedAt *int64
	}
	userMap := make(map[string]*BlockedUserEntry)
	var order []string
	for urows.Next() {
		var r row
		if err := urows.Scan(&r.username, &r.host, &r.reason, &r.blockedAt); err != nil {
			return BlockedPolicy{}, err
		}
		if _, exists := userMap[r.username]; !exists {
			reason := ""
			if r.reason != nil {
				reason = *r.reason
			}
			var at int64
			if r.blockedAt != nil {
				at = *r.blockedAt
			}
			userMap[r.username] = &BlockedUserEntry{
				Username:  r.username,
				Reason:    reason,
				BlockedAt: at,
			}
			order = append(order, r.username)
		}
		if r.host != nil && *r.host != "" {
			userMap[r.username].Hosts = append(userMap[r.username].Hosts, *r.host)
		}
	}
	if err := urows.Err(); err != nil {
		return BlockedPolicy{}, err
	}

	p := BlockedPolicy{BlockMessage: blockMsg}
	for _, u := range order {
		e := *userMap[u]
		if e.Hosts == nil {
			e.Hosts = []string{}
		}
		p.Users = append(p.Users, e)
	}
	if p.Users == nil {
		p.Users = []BlockedUserEntry{}
	}
	return p, nil
}

// SaveBlockedPolicy replaces the full blocked-users list in a single transaction.
func (d *DistributedStore) SaveBlockedPolicy(ctx context.Context, policy BlockedPolicy) error {
	tx, err := d.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `DELETE FROM sudo_blocked_users`); err != nil {
		return err
	}

	for _, u := range policy.Users {
		if len(u.Hosts) == 0 {
			// NULL host = blocked on all hosts.
			if _, err := tx.Exec(ctx,
				`INSERT INTO sudo_blocked_users (username, host, reason, blocked_at) VALUES ($1, NULL, $2, $3)`,
				u.Username, u.Reason, u.BlockedAt); err != nil {
				return err
			}
		} else {
			for _, h := range u.Hosts {
				if _, err := tx.Exec(ctx,
					`INSERT INTO sudo_blocked_users (username, host, reason, blocked_at) VALUES ($1, $2, $3, $4)`,
					u.Username, h, u.Reason, u.BlockedAt); err != nil {
					return err
				}
			}
		}
	}

	if _, err := tx.Exec(ctx, `
INSERT INTO sudo_config (key, value) VALUES ('block_message', $1)
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`,
		policy.BlockMessage); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// ── distributedWriter ─────────────────────────────────────────────────────────

type distributedWriter struct {
	w          *iolog.Writer
	tsid       string
	d          *DistributedStore
	startTime  time.Time
	frameCount int32 // atomically incremented per WriteScreenFrame call
}

func (dw *distributedWriter) WriteOutput(data []byte, ts int64) error {
	return dw.w.WriteOutput(data, ts)
}

func (dw *distributedWriter) WriteInput(data []byte, ts int64) error {
	return dw.w.WriteInput(data, ts)
}

// MarkActive is a no-op for distributed: the DB row is created with
// in_progress=TRUE in CreateSession.
func (dw *distributedWriter) MarkActive() error { return nil }

func (dw *distributedWriter) MarkIncomplete() error {
	_, err := dw.d.db.Exec(context.Background(),
		`UPDATE sudo_sessions SET incomplete=TRUE, in_progress=FALSE, updated_at=NOW() WHERE tsid=$1`,
		dw.tsid)
	return err
}

func (dw *distributedWriter) MarkNetworkOutage() error {
	_, err := dw.d.db.Exec(context.Background(),
		`UPDATE sudo_sessions SET incomplete=TRUE, network_outage=TRUE, in_progress=FALSE, updated_at=NOW() WHERE tsid=$1`,
		dw.tsid)
	return err
}

func (dw *distributedWriter) MarkDone() error {
	duration := time.Since(dw.startTime).Seconds()
	_, err := dw.d.db.Exec(context.Background(),
		`UPDATE sudo_sessions SET in_progress=FALSE, duration=$1, updated_at=NOW() WHERE tsid=$2`,
		duration, dw.tsid)
	return err
}

func (dw *distributedWriter) WriteExitCode(code int32) error {
	_, err := dw.d.db.Exec(context.Background(),
		`UPDATE sudo_sessions SET exit_code=$1, updated_at=NOW() WHERE tsid=$2`,
		code, dw.tsid)
	return err
}

// Close flushes the cast file, then triggers an async S3 upload.
func (dw *distributedWriter) Close() error {
	if err := dw.w.Close(); err != nil {
		return err
	}
	// Upload to S3 asynchronously.  On success the local buffer file is removed.
	go dw.uploadToS3()
	return nil
}

func (dw *distributedWriter) TSID() string { return dw.tsid }

// WriteScreenFrame uploads a single JPEG frame to S3.
// The frame index is tracked atomically so concurrent calls are safe.
func (dw *distributedWriter) WriteScreenFrame(data []byte, ts int64) error {
	n := int(atomic.AddInt32(&dw.frameCount, 1)) - 1
	key := dw.d.s3FrameKey(dw.tsid, n)
	size := int64(len(data))
	_, err := dw.d.s3.PutObject(context.Background(), &s3.PutObjectInput{
		Bucket:        aws.String(dw.d.cfg.S3Bucket),
		Key:           aws.String(key),
		Body:          bytes.NewReader(data),
		ContentLength: aws.Int64(size),
		ContentType:   aws.String("image/jpeg"),
		Metadata:      map[string]string{"ts": strconv.FormatInt(ts, 10)},
	})
	if err != nil {
		log.Printf("store/distributed: write frame %d for %s: %v", n, dw.tsid, err)
	}
	return err
}

// uploadToS3 uploads the local buffer file to S3 with up to 3 retries.
// Acquires s3UploadSem to bound the number of concurrent uploads.
func (dw *distributedWriter) uploadToS3() {
	s3UploadSem <- struct{}{}
	defer func() { <-s3UploadSem }()

	bufPath := dw.d.bufferPath(dw.tsid)
	const maxAttempts = 3

	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if attempt > 1 {
			time.Sleep(time.Duration(attempt) * 2 * time.Second)
		}
		if err := dw.doUpload(bufPath); err != nil {
			lastErr = err
			log.Printf("store/distributed: s3 upload %s attempt %d/%d: %v",
				dw.tsid, attempt, maxAttempts, err)
			continue
		}
		// Success — remove local buffer.
		if err := os.Remove(bufPath); err != nil && !os.IsNotExist(err) {
			log.Printf("store/distributed: remove buffer %s: %v", bufPath, err)
		}
		// Best-effort: remove empty parent directories.
		_ = os.Remove(filepath.Dir(bufPath))
		return
	}
	log.Printf("store/distributed: s3 upload %s failed after %d attempts: %v — "+
		"buffer file retained at %s for manual recovery",
		dw.tsid, maxAttempts, lastErr, bufPath)
}

func (dw *distributedWriter) doUpload(bufPath string) error {
	f, err := os.Open(bufPath)
	if err != nil {
		return fmt.Errorf("open buffer: %w", err)
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat buffer: %w", err)
	}

	_, err = dw.d.s3.PutObject(context.Background(), &s3.PutObjectInput{
		Bucket:        aws.String(dw.d.cfg.S3Bucket),
		Key:           aws.String(dw.d.s3Key(dw.tsid)),
		Body:          f,
		ContentLength: aws.Int64(fi.Size()),
		ContentType:   aws.String("application/octet-stream"),
	})
	return err
}
