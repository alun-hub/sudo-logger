// sudo-logserver: remote TLS server that receives sudo session recordings
// from sudo-logger-agent instances, writes sudo I/O log directories compatible
// with sudoreplay(8), and sends ed25519-signed ACKs back to the agent.
//
// Sessions are stored under -logdir/<user>/<host>_<timestamp>/
// and replayed with: sudoreplay -d <logdir> <session-dir>
package main

import (
	"crypto/ed25519"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	_ "time/tzdata" // embed IANA timezone data so TZ env var works in minimal containers

	"sudo-logger/internal/config"
	"sudo-logger/internal/store"
	"sudo-logger/internal/version"
)

// validName matches safe directory name components: alphanumeric plus .-_
// Maximum 64 characters. Rejects empty strings, dots-only, and path separators.
var validName = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,64}$`)

// nonIDChar matches characters not allowed in a session ID.
var nonIDChar = regexp.MustCompile(`[^a-zA-Z0-9._-]`)

// validSessionID is a looser check for the full session ID, which includes
// host, user, PID, nanosecond timestamp and a random hex suffix — and is
// therefore longer than a single name component (up to 255 chars).
var validSessionID = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,255}$`)

// approvalStorePath returns the YAML persistence path for the approval store,
// derived from the policy file path so both live in the same directory.
func approvalStorePath(policyPath string) string {
	return filepath.Join(filepath.Dir(policyPath), "approval-store.yaml")
}

func sanitizeName(s string) (string, error) {
	if !validName.MatchString(s) {
		return "", fmt.Errorf("invalid characters or length in name: %q", s)
	}
	return s, nil
}



type server struct {
	signKey      ed25519.PrivateKey
	sessionStore store.SessionStore
	approvalMgr  *ApprovalManager

	mu       sync.Mutex
	sessions map[string]*session

	// Prometheus counters — monotonically increasing since process start.
	sessionsTotal      atomic.Int64
	sessionsIncomplete atomic.Int64
}

type session struct {
	id        string
	user      string
	host      string
	runas     string
	cwd       string
	command   string
	startTime time.Time
	writer    store.SessionWriter
	lastSeq   uint64
	// freezeCandidate is set when SESSION_FREEZING is received for this session,
	// meaning the agent declared the network dead.  When the TCP connection
	// subsequently drops, MarkNetworkOutage is used instead of MarkIncomplete.
	freezeCandidate bool
}

func main() {
	flag.Parse()

	if *flagVersion {
		fmt.Printf("sudo-logserver %s\n", version.Version)
		os.Exit(0)
	}

	signKey, err := loadEd25519PrivKey(*flagSignKey)
	if err != nil {
		log.Fatalf("load signing key: %v", err)
	}

	tlsCfg, err := buildTLSConfig()
	if err != nil {
		log.Fatalf("build TLS config: %v", err)
	}

	if *flagStorage == "local" {
		if err := os.MkdirAll(*flagLogDir, 0750); err != nil {
			log.Fatalf("create log dir: %v", err)
		}
	}

	sessionStore, err := store.New(store.Config{
		Backend:              *flagStorage,
		LogDir:               *flagLogDir,
		BlockedUsersPath:        *flagBlockedUsers,
		WhitelistedUsersPath:    *flagWhitelistedUsers,
		SandboxConfigPath:    *flagSandbox,
		SandboxTemplatesPath: *flagSandboxTemplates,
		ApprovalStorePath:    approvalStorePath(*flagApprovalPolicy),
		ApprovalPolicyPath:   *flagApprovalPolicy,
		S3Bucket:             *flagS3Bucket,
		S3Region:         *flagS3Region,
		S3Prefix:         *flagS3Prefix,
		S3Endpoint:       *flagS3Endpoint,
		S3PathStyle:      *flagS3PathStyle,
		S3AccessKey:      *flagS3AccessKey,
		S3SecretKey:      *flagS3SecretKey,
		DBURL:            *flagDBURL,
		BufferDir:        *flagBufferDir,
	})
	if err != nil {
		log.Fatalf("init storage: %v", err)
	}
	defer sessionStore.Close()

	ln, err := tls.Listen("tcp", *flagListen, tlsCfg)
	if err != nil {
		log.Fatalf("listen %s: %v", *flagListen, err)
	}
	defer ln.Close()

	var approvalMgr *ApprovalManager
	if approvalBackend, ok := sessionStore.(store.ApprovalStore); ok {
		approvalMgr = newApprovalManager(*flagApprovalPolicy, approvalBackend)
	} else {
		log.Printf("approval: storage backend does not support ApprovalStore — JIT approval disabled")
	}
	srv := &server{
		signKey:      signKey,
		sessionStore: sessionStore,
		approvalMgr:  approvalMgr,
		sessions:     make(map[string]*session),
	}

	// Optional plain-HTTP server for health probes and Prometheus metrics.
	// Disabled by default (flag empty); enabled in K8s via --health-listen=:9877.
	if *flagHealthListen != "" {
		healthMux := http.NewServeMux()
		healthMux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
			fmt.Fprintln(w, "ok")
		})
		approvalToken, err := config.ResolveSecret(*flagApprovalToken, *flagApprovalTokenFile, "SUDO_LOGGER_APPROVAL_TOKEN")
		if err != nil {
			log.Fatalf("approval token: %v", err)
		}
		srv.approvalMgr.RegisterApprovalAPI(healthMux, approvalToken)

		// DELETE /api/sessions/<tsid> — permanent GDPR/audit deletion.
		// Only registered when an approval token is configured; no token = endpoint disabled.
		if approvalToken == "" {
			log.Printf("approval token not configured; DELETE /api/sessions/ endpoint disabled")
		} else {
			wantAuth := []byte("Bearer " + approvalToken)
			healthMux.HandleFunc("/api/sessions/", func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodDelete {
					http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
					return
				}
				if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), wantAuth) != 1 {
					http.Error(w, "unauthorized", http.StatusUnauthorized)
					return
				}
				tsid := strings.TrimPrefix(r.URL.Path, "/api/sessions/")
				if tsid == "" {
					http.Error(w, "missing tsid", http.StatusBadRequest)
					return
				}
				var body struct {
					Reason string `json:"reason"`
				}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Reason) == "" {
					http.Error(w, "body must be JSON with non-empty \"reason\"", http.StatusBadRequest)
					return
				}
				if err := srv.sessionStore.DeleteSession(r.Context(), tsid, body.Reason, "api"); err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				log.Printf(`{"time":%q,"event":"session_deleted","tsid":%q,"reason":%q,"deleted_by":"api"}`,
					time.Now().UTC().Format(time.RFC3339), tsid, body.Reason)
				w.WriteHeader(http.StatusNoContent)
			})
		}

		healthMux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
			srv.mu.Lock()
			active := len(srv.sessions)
			srv.mu.Unlock()
			w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
			fmt.Fprintf(w, "# HELP sudologger_sessions_active Sessions currently being recorded.\n")
			fmt.Fprintf(w, "# TYPE sudologger_sessions_active gauge\n")
			fmt.Fprintf(w, "sudologger_sessions_active %d\n", active)
			fmt.Fprintf(w, "# HELP sudologger_sessions_total Sessions closed since last restart.\n")
			fmt.Fprintf(w, "# TYPE sudologger_sessions_total counter\n")
			fmt.Fprintf(w, "sudologger_sessions_total %d\n", srv.sessionsTotal.Load())
			fmt.Fprintf(w, "# HELP sudologger_sessions_incomplete_total Sessions that ended without SESSION_END since last restart.\n")
			fmt.Fprintf(w, "# TYPE sudologger_sessions_incomplete_total counter\n")
			fmt.Fprintf(w, "sudologger_sessions_incomplete_total %d\n", srv.sessionsIncomplete.Load())
		})
		go func() {
			if err := http.ListenAndServe(*flagHealthListen, healthMux); err != nil {
				log.Printf("health/metrics listener: %v", err)
			}
		}()
		log.Printf("health/metrics listening on %s", *flagHealthListen)
	}

	log.Printf("sudo-logserver %s listening on %s, storage=%s logdir=%s", version.Version, *flagListen, *flagStorage, *flagLogDir)

	// Graceful shutdown: close the TLS listener on SIGTERM/SIGINT so that
	// ln.Accept() returns an error and the loop exits. Then wait up to 30 s
	// for in-flight sessions to complete before the process exits.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		sig := <-quit
		log.Printf("sudo-logserver: received %v — stopping listener", sig)
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			// A closed listener returns a permanent error; exit cleanly.
			log.Printf("sudo-logserver: listener closed: %v", err)
			break
		}
		go srv.handleConn(conn.(*tls.Conn))
	}

	// Drain: wait for active sessions to finish, up to 30 s.
	const drainTimeout = 30 * time.Second
	deadline := time.Now().Add(drainTimeout)
	for time.Now().Before(deadline) {
		srv.mu.Lock()
		active := len(srv.sessions)
		srv.mu.Unlock()
		if active == 0 {
			break
		}
		log.Printf("sudo-logserver: draining %d active session(s)...", active)
		time.Sleep(500 * time.Millisecond)
	}
	log.Printf("sudo-logserver: shutdown complete")
}

func sanitizeForLog(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return '_'
		}
		return r
	}, s)
}
