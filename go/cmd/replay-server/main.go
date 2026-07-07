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
	"context"
	"crypto/tls"
	"embed"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
	_ "time/tzdata" // embed IANA timezone data so TZ env var works in minimal containers

	"sudo-logger/internal/siem"
	"sudo-logger/internal/store"
	"sudo-logger/internal/version"
)

//go:embed static
var staticFiles embed.FS



// sessionStore is the active storage backend, initialised in main().
var sessionStore store.SessionStore





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

// invalidate forces the next get() to rebuild from the store. Also clears
// sessionsCache (handlers_session.go) — a separate cache over the same
// underlying ListSessions data used by /api/sudoers/hosts and ownership
// checks — so a config change doesn't leave that endpoint serving stale
// data for up to its own TTL after this cache was invalidated.
func (c *sessionCache) invalidate() {
	c.mu.Lock()
	c.built = false
	c.mu.Unlock()

	sessionsCache.mu.Lock()
	sessionsCache.expiry = time.Time{}
	sessionsCache.mu.Unlock()
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









func main() {
	flag.Parse()

	if *flagVersion {
		fmt.Printf("sudo-replay-server %s\n", version.Version)
		os.Exit(0)
	}

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

	// -htpasswd is an explicitly-set, non-default path, so a load failure
	// here is a real misconfiguration — fail loudly rather than silently
	// starting with an auth mode the admin thinks is active but isn't.
	if *flagHTPasswd != "" { // pragma: allowlist secret
		if err := loadHTPasswd(*flagHTPasswd); err != nil {
			log.Fatalf("load htpasswd file %s: %v", *flagHTPasswd, err)
		}
	}

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
	registerRoutes(mux)

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

	// Signal handling: SIGTERM/SIGINT triggers graceful shutdown; SIGHUP
	// reloads the htpasswd file (documented in -htpasswd's flag description).
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	go func() {
		for sig := range sigCh {
			if sig == syscall.SIGHUP {
				if *flagHTPasswd != "" { // pragma: allowlist secret
					if err := loadHTPasswd(*flagHTPasswd); err != nil {
						log.Printf("htpasswd: reload failed, keeping previous user set: %v", err)
					}
				}
				continue
			}
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
		log.Printf("sudo-replay-server %s listening on %s (TLS), logdir=%s", version.Version, *flagListen, *flagLogDir)
		serveErr = httpSrv.ListenAndServeTLS(*flagTLSCert, *flagTLSKey)
	} else {
		log.Printf("sudo-replay-server %s listening on %s, logdir=%s", version.Version, *flagListen, *flagLogDir)
		serveErr = httpSrv.ListenAndServe()
	}
	if serveErr != nil && serveErr != http.ErrServerClosed {
		log.Fatalf("listen: %v", serveErr)
	}
	log.Printf("sudo-replay-server: shutdown complete")
}
