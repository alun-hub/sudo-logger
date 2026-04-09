// migrate-sessions imports existing local session recordings into the
// distributed backend (S3 + PostgreSQL).
//
// Run once before switching log-server and replay-server to --storage=distributed.
// The migration is idempotent: re-running it is safe and skips already-imported
// sessions (INSERT ... ON CONFLICT DO NOTHING, PutObject is idempotent).
//
// Usage:
//
//	migrate-sessions \
//	  --logdir /var/log/sudoreplay \
//	  --db-url postgres://user@host/dbname \
//	  --s3-bucket my-bucket \
//	  [--s3-endpoint https://minio.internal:9000] \
//	  [--s3-path-style] \
//	  [--s3-access-key KEY --s3-secret-key SECRET]
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	flagLogDir     = flag.String("logdir", "/var/log/sudoreplay", "Source log directory")
	flagDBURL      = flag.String("db-url", "", "PostgreSQL DSN (required)")
	flagS3Bucket   = flag.String("s3-bucket", "", "S3 bucket (required)")
	flagS3Region   = flag.String("s3-region", "us-east-1", "S3 region")
	flagS3Prefix   = flag.String("s3-prefix", "sessions/", "S3 key prefix")
	flagS3Endpoint = flag.String("s3-endpoint", "", "S3-compatible endpoint URL")
	flagS3PathStyle = flag.Bool("s3-path-style", false, "Use path-style S3 URLs (MinIO/StorageGRID)")
	flagS3AccessKey = flag.String("s3-access-key", "", "Static S3 access key")
	flagS3SecretKey = flag.String("s3-secret-key", "", "Static S3 secret key")
	flagDryRun     = flag.Bool("dry-run", false, "Print what would be migrated without writing anything")
	flagWorkers    = flag.Int("workers", 4, "Number of concurrent upload workers")
)

func main() {
	flag.Parse()

	if *flagDBURL == "" {
		log.Fatal("--db-url is required")
	}
	if *flagS3Bucket == "" {
		log.Fatal("--s3-bucket is required")
	}

	ctx := context.Background()

	// ── PostgreSQL ────────────────────────────────────────────────────────────
	var pool *pgxpool.Pool
	if !*flagDryRun {
		var err error
		pool, err = pgxpool.New(ctx, *flagDBURL)
		if err != nil {
			log.Fatalf("open postgres: %v", err)
		}
		defer pool.Close()
		if err := pool.Ping(ctx); err != nil {
			log.Fatalf("postgres ping: %v", err)
		}
		if err := ensureSchema(ctx, pool); err != nil {
			log.Fatalf("schema: %v", err)
		}
	}

	// ── S3 client ─────────────────────────────────────────────────────────────
	var s3Client *s3.Client
	if !*flagDryRun {
		var err error
		s3Client, err = buildS3Client(ctx)
		if err != nil {
			log.Fatalf("build s3 client: %v", err)
		}
	}

	// ── Walk and migrate ──────────────────────────────────────────────────────
	type work struct {
		sessDir string
		tsid    string
	}
	jobs := make(chan work, 64)

	// Producer: walk the log directory.
	go func() {
		defer close(jobs)
		userEntries, err := os.ReadDir(*flagLogDir)
		if err != nil {
			log.Printf("read logdir: %v", err)
			return
		}
		for _, userEntry := range userEntries {
			if !userEntry.IsDir() {
				continue
			}
			userDir := filepath.Join(*flagLogDir, userEntry.Name())
			sessEntries, err := os.ReadDir(userDir)
			if err != nil {
				continue
			}
			for _, sessEntry := range sessEntries {
				if !sessEntry.IsDir() {
					continue
				}
				sessDir := filepath.Join(userDir, sessEntry.Name())
				if _, err := os.Stat(filepath.Join(sessDir, "session.cast")); err != nil {
					continue
				}
				tsid := userEntry.Name() + "/" + sessEntry.Name()
				jobs <- work{sessDir, tsid}
			}
		}
	}()

	// Consumers: migrate each session.
	type result struct{ ok, skip, fail int }
	results := make(chan result, *flagWorkers)
	for i := 0; i < *flagWorkers; i++ {
		go func() {
			var r result
			for j := range jobs {
				switch migrateSession(ctx, pool, s3Client, j.sessDir, j.tsid) {
				case "ok":
					r.ok++
				case "skip":
					r.skip++
				default:
					r.fail++
				}
			}
			results <- r
		}()
	}

	var total result
	for i := 0; i < *flagWorkers; i++ {
		r := <-results
		total.ok += r.ok
		total.skip += r.skip
		total.fail += r.fail
	}
	log.Printf("migration complete: imported=%d skipped=%d failed=%d",
		total.ok, total.skip, total.fail)
}

// migrateSession migrates one session.  Returns "ok", "skip", or "fail".
func migrateSession(ctx context.Context, pool *pgxpool.Pool, s3c *s3.Client, sessDir, tsid string) string {
	hdr, err := readCastHeader(sessDir)
	if err != nil {
		log.Printf("skip %s: %v", tsid, err)
		return "fail"
	}

	if *flagDryRun {
		fmt.Printf("[dry-run] would migrate %s (user=%s host=%s cmd=%s)\n",
			tsid, hdr.User, hdr.Host, hdr.Command)
		return "ok"
	}

	// Determine session state from marker files.
	incomplete := fileExists(filepath.Join(sessDir, "INCOMPLETE"))
	inProgress := fileExists(filepath.Join(sessDir, "ACTIVE"))
	exitCode := int32(0)
	if data, err := os.ReadFile(filepath.Join(sessDir, "exit_code")); err == nil {
		if v, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 32); err == nil {
			exitCode = int32(v)
		}
	}

	// ── Insert metadata row ───────────────────────────────────────────────────
	tag, err := pool.Exec(ctx, `
INSERT INTO sudo_sessions
  (tsid, session_id, "user", host, runas, runas_uid, runas_gid,
   command, resolved_command, cwd, flags,
   start_time, exit_code, incomplete, in_progress)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
ON CONFLICT (tsid) DO NOTHING`,
		tsid, hdr.SessionID, hdr.User, hdr.Host,
		hdr.RunasUser, hdr.RunasUID, hdr.RunasGID,
		hdr.Command, hdr.ResolvedCommand, hdr.Cwd, hdr.Flags,
		hdr.Timestamp, exitCode, incomplete, inProgress,
	)
	if err != nil {
		log.Printf("fail %s (db insert): %v", tsid, err)
		return "fail"
	}
	if tag.RowsAffected() == 0 {
		// Row already existed — session was previously migrated.
		return "skip"
	}

	// ── Upload cast file to S3 ────────────────────────────────────────────────
	castPath := filepath.Join(sessDir, "session.cast")
	f, err := os.Open(castPath)
	if err != nil {
		log.Printf("fail %s (open cast): %v", tsid, err)
		return "fail"
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		log.Printf("fail %s (stat cast): %v", tsid, err)
		return "fail"
	}

	key := *flagS3Prefix + tsid + "/session.cast"
	_, err = s3c.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(*flagS3Bucket),
		Key:           aws.String(key),
		Body:          f,
		ContentLength: aws.Int64(fi.Size()),
		ContentType:   aws.String("application/octet-stream"),
	})
	if err != nil {
		log.Printf("fail %s (s3 upload): %v", tsid, err)
		return "fail"
	}

	// ── Migrate risk cache if present ─────────────────────────────────────────
	if riskData, err := os.ReadFile(filepath.Join(sessDir, "risk.json")); err == nil {
		var rc struct {
			RulesHash string   `json:"rules_hash"`
			Score     int      `json:"score"`
			Level     string   `json:"level"`
			Reasons   []string `json:"reasons"`
		}
		if json.Unmarshal(riskData, &rc) == nil {
			reasonsJSON, _ := json.Marshal(rc.Reasons)
			_, _ = pool.Exec(ctx, `
INSERT INTO sudo_risk_cache (tsid, rules_hash, score, level, reasons, cached_at)
VALUES ($1,$2,$3,$4,$5,$6)
ON CONFLICT (tsid) DO NOTHING`,
				tsid, rc.RulesHash, rc.Score, rc.Level, reasonsJSON, time.Now(),
			)
		}
	}

	log.Printf("ok %s", tsid)
	return "ok"
}

// readCastHeader parses the first line of session.cast.
func readCastHeader(sessDir string) (*castHeader, error) {
	f, err := os.Open(filepath.Join(sessDir, "session.cast"))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 64*1024)
	if !scanner.Scan() {
		return nil, fmt.Errorf("empty cast file")
	}
	var hdr castHeader
	if err := json.Unmarshal(scanner.Bytes(), &hdr); err != nil {
		return nil, fmt.Errorf("parse header: %w", err)
	}
	return &hdr, nil
}

type castHeader struct {
	Timestamp       int64  `json:"timestamp"`
	SessionID       string `json:"session_id"`
	User            string `json:"user"`
	Host            string `json:"host"`
	RunasUser       string `json:"runas_user"`
	RunasUID        int    `json:"runas_uid"`
	RunasGID        int    `json:"runas_gid"`
	Cwd             string `json:"cwd"`
	Command         string `json:"command"`
	ResolvedCommand string `json:"resolved_command"`
	Flags           string `json:"flags"`
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func ensureSchema(ctx context.Context, pool *pgxpool.Pool) error {
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
    blocked_at  BIGINT,
    PRIMARY KEY (username, COALESCE(host, ''))
);
CREATE TABLE IF NOT EXISTS sudo_config (
    key   TEXT PRIMARY KEY,
    value TEXT
);`)
	return err
}

func buildS3Client(ctx context.Context) (*s3.Client, error) {
	var opts []func(*awsconfig.LoadOptions) error
	opts = append(opts, awsconfig.WithRegion(*flagS3Region))
	if *flagS3AccessKey != "" && *flagS3SecretKey != "" {
		opts = append(opts, awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(*flagS3AccessKey, *flagS3SecretKey, ""),
		))
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, err
	}
	s3Opts := []func(*s3.Options){}
	if *flagS3Endpoint != "" {
		s3Opts = append(s3Opts, func(o *s3.Options) {
			o.BaseEndpoint = aws.String(*flagS3Endpoint)
			o.UsePathStyle = *flagS3PathStyle
		})
	}
	return s3.NewFromConfig(awsCfg, s3Opts...), nil
}
