package store

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
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
    in_progress      BOOLEAN DEFAULT TRUE,
    created_at       TIMESTAMPTZ DEFAULT NOW(),
    updated_at       TIMESTAMPTZ DEFAULT NOW()
);

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

	return &distributedWriter{w: w, tsid: tsid, d: d}, nil
}

// ListSessions implements SessionStore.
func (d *DistributedStore) ListSessions(ctx context.Context) ([]SessionRecord, error) {
	rows, err := d.db.Query(ctx, `
SELECT tsid, session_id, "user", host, runas, runas_uid, runas_gid,
       command, resolved_command, cwd, flags, start_time,
       COALESCE(duration, 0), COALESCE(exit_code, 0),
       incomplete, in_progress
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
			&r.Incomplete, &r.InProgress,
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
func (d *DistributedStore) WatchSessions(ctx context.Context, ch chan<- string) {
	lastCheck := time.Now()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case t := <-ticker.C:
			rows, err := d.db.Query(ctx, `
SELECT tsid FROM sudo_sessions
WHERE updated_at > $1 AND in_progress = FALSE
ORDER BY updated_at ASC`,
				lastCheck,
			)
			if err != nil {
				log.Printf("store/distributed: watch poll: %v", err)
				lastCheck = t
				continue
			}
			for rows.Next() {
				var tsid string
				if rows.Scan(&tsid) == nil {
					select {
					case ch <- tsid:
					default:
					}
				}
			}
			rows.Close()
			lastCheck = t
		}
	}
}

// Close implements SessionStore.
func (d *DistributedStore) Close() error {
	d.stopOnce.Do(func() {
		close(d.stopCh)
		d.db.Close()
	})
	return nil
}

// ── distributedWriter ─────────────────────────────────────────────────────────

type distributedWriter struct {
	w    *iolog.Writer
	tsid string
	d    *DistributedStore
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

func (dw *distributedWriter) MarkDone() error {
	_, err := dw.d.db.Exec(context.Background(),
		`UPDATE sudo_sessions SET in_progress=FALSE, updated_at=NOW() WHERE tsid=$1`,
		dw.tsid)
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
