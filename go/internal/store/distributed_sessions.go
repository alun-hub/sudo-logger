package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"sudo-logger/internal/iolog"
	"sudo-logger/internal/protocol"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/jackc/pgx/v5"
)

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

	divStatus := meta.EffectiveDivergenceStatus()
	// Apply the same defaults as iolog.NewWriter so the stored values match
	// the cast file header (which defaults to 220x50 when sudo provides no PTY).
	ttyC := meta.Cols
	if ttyC <= 0 {
		ttyC = 220
	}
	ttyR := meta.Rows
	if ttyR <= 0 {
		ttyR = 50
	}
	tag, err := d.db.Exec(ctx, `
INSERT INTO sudo_sessions
  (tsid, session_id, "user", host, runas, runas_uid, runas_gid,
   command, resolved_command, cwd, flags, start_time, in_progress,
   source, parent_session_id, has_io, divergence_status, caller_process,
   tty_cols, tty_rows)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,TRUE,$13,$14,$15,$16,$17,$18,$19)
ON CONFLICT (tsid) DO NOTHING`,
		tsid, meta.SessionID, meta.User, meta.Host,
		meta.RunasUser, meta.RunasUID, meta.RunasGID,
		meta.Command, meta.ResolvedCommand, meta.Cwd, meta.Flags,
		startTime.Unix(),
		meta.Source, meta.ParentSessionID, meta.HasIO, divStatus, meta.CallerProcess,
		ttyC, ttyR,
	)
	if err != nil {
		_ = w.Close()
		return nil, fmt.Errorf("insert session row: %w", err)
	}
	if tag.RowsAffected() == 0 {
		// ON CONFLICT DO NOTHING means a row with this tsid already exists —
		// the cast file we just created would otherwise be attributed to
		// that other row's metadata. tsid includes a random suffix from
		// iolog.NewWriter, so this should never happen in practice; treat it
		// as a hard error rather than silently continuing.
		_ = w.Close()
		return nil, fmt.Errorf("insert session row: tsid %q already exists", tsid)
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
       COALESCE(matched_session_id, ''), COALESCE(caller_process, ''),
       COALESCE(NULLIF(tty_cols, 0), 220), COALESCE(NULLIF(tty_rows, 0), 50)
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
			&r.DivergenceStatus, &r.MatchedSessionID, &r.CallerProcess,
			&r.Cols, &r.Rows,
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

func (d *DistributedStore) RecordSandboxViolation(ctx context.Context, sid string, alert protocol.SandboxAlert) error {
	_, err := d.db.Exec(ctx,
		`UPDATE sudo_sessions SET sandbox_violation=TRUE, updated_at=NOW() WHERE session_id=$1`,
		sid)
	return err
}

func (d *DistributedStore) HasSandboxViolation(ctx context.Context, tsid string) (bool, error) {
	var violation bool
	err := d.db.QueryRow(ctx, `SELECT sandbox_violation FROM sudo_sessions WHERE tsid=$1`, tsid).Scan(&violation)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	return violation, nil
}


// DeleteSession implements SessionStore.
// Removes the S3 objects, then records the audit entry in sudo_deletion_log
// and deletes the database row in a single transaction — a session must
// never disappear from the DB without a matching audit record, so if the
// audit insert fails the row delete is rolled back too. Returns an error if
// the session is still in progress or does not exist.
func (d *DistributedStore) DeleteSession(ctx context.Context, tsid, reason, deletedBy string) error {
	var inProgress bool
	err := d.db.QueryRow(ctx, `SELECT in_progress FROM sudo_sessions WHERE tsid = $1`, tsid).Scan(&inProgress)
	if err != nil {
		return fmt.Errorf("session not found: %w", err)
	}
	if inProgress {
		return fmt.Errorf("session %q is still in progress", tsid)
	}

	d.deleteS3Session(ctx, tsid)

	tx, err := d.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin deletion transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx,
		`INSERT INTO sudo_deletion_log (tsid, reason, deleted_by) VALUES ($1, $2, $3)`,
		tsid, reason, deletedBy,
	); err != nil {
		return fmt.Errorf("deletion audit write: %w", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM sudo_sessions WHERE tsid = $1`, tsid); err != nil {
		return fmt.Errorf("delete session row: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit deletion: %w", err)
	}
	return nil
}

// ── User Management ──────────────────────────────────────────────────────


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
	var rows pgx.Rows
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
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if result == nil {
		result = []AccessLogEntry{}
	}
	return result, nil
}


type distributedWriter struct {
	w          *iolog.Writer
	tsid       string
	d          *DistributedStore
	startTime  time.Time
}

func (dw *distributedWriter) WriteOutput(data []byte, ts int64) error {
	return dw.w.WriteOutput(data, ts)
}

func (dw *distributedWriter) WriteInput(data []byte, ts int64) error {
	return dw.w.WriteInput(data, ts)
}

func (dw *distributedWriter) WriteResize(cols, rows int, ts int64) error {
	return dw.w.WriteResize(cols, rows, ts)
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

func (dw *distributedWriter) Flush() error {
	return dw.w.Flush()
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

// ── Sudoers snapshot API ──────────────────────────────────────────────────────
