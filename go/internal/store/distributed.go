package store

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/jackc/pgx/v5/pgxpool"

	"sudo-logger/internal/iolog"
)

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

// applySchema creates the required tables if they do not already exist.
func applySchema(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := pool.Exec(ctx, `
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

-- schema migration: add network_outage column to existing deployments
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
    tsid       TEXT NOT NULL,
    viewer     TEXT NOT NULL,
    replay_url TEXT,
    viewed_at  TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS sudo_access_log_viewer   ON sudo_access_log(viewer);
CREATE INDEX IF NOT EXISTS sudo_access_log_viewed_at ON sudo_access_log(viewed_at DESC);
`)
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

// ── SessionStore implementation ───────────────────────────────────────────────

// CreateSession implements SessionStore.
func (d *DistributedStore) CreateSession(ctx context.Context, meta iolog.SessionMeta, startTime time.Time) (SessionWriter, error) {
	ts := startTime.UTC().Format("20060102-150405")
	tsid := meta.User + "/" + meta.Host + "_" + ts

	bufPath := d.bufferPath(tsid)
	if err := os.MkdirAll(filepath.Dir(bufPath), 0o750); err != nil {
		return nil, fmt.Errorf("create buffer dir: %w", err)
	}

	w, err := iolog.NewWriter(d.cfg.BufferDir, meta, startTime)
	if err != nil {
		return nil, fmt.Errorf("create iolog writer: %w", err)
	}

	_, err = d.db.Exec(ctx, `
INSERT INTO sudo_sessions
  (tsid, session_id, "user", host, runas, runas_uid, runas_gid,
   command, resolved_command, cwd, flags, start_time, in_progress)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,TRUE)
ON CONFLICT (tsid) DO NOTHING`,
		tsid, meta.SessionID, meta.User, meta.Host,
		meta.RunasUser, meta.RunasUID, meta.RunasGID,
		meta.Command, meta.ResolvedCommand, meta.Cwd, meta.Flags,
		startTime.Unix(),
	)
	if err != nil {
		w.Close()
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
       incomplete, network_outage, in_progress
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
		tsid, rulesHash, score, riskLevel(score), reasonsJSON,
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
	var locked bool
	if err := conn.QueryRow(ctx,
		"SELECT pg_try_advisory_lock($1)", siemLockID).Scan(&locked); err != nil {
		log.Printf("store/distributed: WatchSessions: advisory lock query: %v", err)
		return
	}
	if !locked {
		log.Printf("store/distributed: WatchSessions: another replica holds the SIEM leader lock — retrying every 30 s")
		retryTicker := time.NewTicker(30 * time.Second)
		defer retryTicker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-retryTicker.C:
				if err := conn.QueryRow(ctx,
					"SELECT pg_try_advisory_lock($1)", siemLockID).Scan(&locked); err != nil {
					log.Printf("store/distributed: WatchSessions: advisory lock retry: %v", err)
					continue
				}
				if locked {
					goto acquired
				}
			}
		}
	}
acquired:
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
	rows, err := d.db.Query(ctx, `SELECT value FROM sudo_config WHERE key = $1`, key)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	if rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			return "", err
		}
		return value, nil
	}
	return "", rows.Err()
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
	w         *iolog.Writer
	tsid      string
	d         *DistributedStore
	startTime time.Time
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

// uploadToS3 uploads the local buffer file to S3 with up to 3 retries.
func (dw *distributedWriter) uploadToS3() {
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
