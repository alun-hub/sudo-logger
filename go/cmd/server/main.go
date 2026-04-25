// sudo-logserver: remote TLS server that receives sudo session recordings
// from sudo-shipper instances, writes sudo I/O log directories compatible
// with sudoreplay(8), and sends ed25519-signed ACKs back to the shipper.
//
// Sessions are stored under -logdir/<user>/<host>_<timestamp>/
// and replayed with: sudoreplay -d <logdir> <session-dir>
package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"sudo-logger/internal/iolog"
	"sudo-logger/internal/protocol"
	"sudo-logger/internal/store"
)

// validName matches safe directory name components: alphanumeric plus .-_
// Maximum 64 characters. Rejects empty strings, dots-only, and path separators.
var validName = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,64}$`)

// validSessionID is a looser check for the full session ID, which includes
// host, user, PID, nanosecond timestamp and a random hex suffix — and is
// therefore longer than a single name component (up to 255 chars).
var validSessionID = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,255}$`)

func sanitizeName(s string) (string, error) {
	if !validName.MatchString(s) {
		return "", fmt.Errorf("invalid characters or length in name: %q", s)
	}
	return s, nil
}

var (
	flagListen         = flag.String("listen", ":9876", "Listen address (TLS)")
	flagLogDir         = flag.String("logdir", "/var/log/sudoreplay", "Base directory for session logs")
	flagCert           = flag.String("cert", "/etc/sudo-logger/server.crt", "Server TLS certificate")
	flagKey            = flag.String("key", "/etc/sudo-logger/server.key", "Server TLS key")
	flagCA             = flag.String("ca", "/etc/sudo-logger/ca.crt", "CA certificate (for client auth)")
	flagSignKey        = flag.String("signkey", "/etc/sudo-logger/ack-sign.key", "ed25519 private key for ACK signing (PEM)")
	flagStrictCertHost = flag.Bool("strict-cert-host", false,
		"Reject sessions where the claimed host does not match the client certificate CN/SAN. "+
			"Requires per-machine client certificates. Off by default to support shared-cert setups.")
	flagBlockedUsers = flag.String("blocked-users", "/etc/sudo-logger/blocked-users.yaml",
		"Blocked users config file (managed by sudo-replay GUI; reloaded every 30 s)")

	// Storage backend flags.
	// NOTE: these flags are intentionally duplicated in cmd/replay-server/main.go.
	// If you change a default or description here, update that file too.
	flagStorage      = flag.String("storage", "local", "Storage backend: local|distributed")
	flagS3Bucket     = flag.String("s3-bucket", "", "S3 bucket name (distributed storage)")
	flagS3Region     = flag.String("s3-region", "us-east-1", "S3 region (distributed storage)")
	flagS3Prefix     = flag.String("s3-prefix", "sessions/", "S3 key prefix (distributed storage)")
	flagS3Endpoint   = flag.String("s3-endpoint", "", "S3-compatible endpoint URL, e.g. https://minio.internal:9000")
	flagS3PathStyle  = flag.Bool("s3-path-style", false, "Use path-style S3 URLs (required for MinIO/StorageGRID)")
	flagS3AccessKey  = flag.String("s3-access-key", "", "Static S3 access key (leave empty to use IAM/env)")
	flagS3SecretKey  = flag.String("s3-secret-key", "", "Static S3 secret key (leave empty to use IAM/env)")
	flagDBURL        = flag.String("db-url", "", "PostgreSQL DSN (distributed storage)")
	flagBufferDir    = flag.String("buffer-dir", "/var/lib/sudo-logger/buffer", "Local write-buffer dir for S3 uploads")
	flagHealthListen = flag.String("health-listen", "", "Plain HTTP address for /healthz and /metrics (e.g. :9877); disabled when empty")
)

type server struct {
	signKey      ed25519.PrivateKey
	sessionStore store.SessionStore

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
	// meaning the shipper declared the network dead.  When the TCP connection
	// subsequently drops, MarkNetworkOutage is used instead of MarkIncomplete.
	freezeCandidate bool
}

func main() {
	flag.Parse()

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
		Backend:          *flagStorage,
		LogDir:           *flagLogDir,
		BlockedUsersPath: *flagBlockedUsers,
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
	if err != nil {
		log.Fatalf("init storage: %v", err)
	}
	defer sessionStore.Close()

	ln, err := tls.Listen("tcp", *flagListen, tlsCfg)
	if err != nil {
		log.Fatalf("listen %s: %v", *flagListen, err)
	}
	defer ln.Close()

	srv := &server{
		signKey:      signKey,
		sessionStore: sessionStore,
		sessions:     make(map[string]*session),
	}

	// Optional plain-HTTP server for health probes and Prometheus metrics.
	// Disabled by default (flag empty); enabled in K8s via --health-listen=:9877.
	if *flagHealthListen != "" {
		healthMux := http.NewServeMux()
		healthMux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
			fmt.Fprintln(w, "ok")
		})
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

	log.Printf("sudo-logserver listening on %s, storage=%s logdir=%s", *flagListen, *flagStorage, *flagLogDir)

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

func (srv *server) handleConn(conn *tls.Conn) {
	defer conn.Close()

	remote := conn.RemoteAddr().String()
	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)

	var sess *session

	// ── Async ACK Coalescer ───────────────────────────────────────────────
	// Prevents TCP flow control deadlocks by decoupling reads from writes.
	// Under high I/O, this naturally coalesces thousands of ACKs into one.
	var (
		sendMu           sync.Mutex
		sendCond         = sync.NewCond(&sendMu)
		pendingSeq       uint64
		pendingHeartbeat bool
		senderClosed     bool
		sessionID        string
	)

	// ── Async Disk Writer ────────────────────────────────────────────────
	// Shock absorber for high I/O bursts. Decouples network from storage.
	type diskTask struct {
		msgType uint8
		payload []byte
	}
	diskQueue := make(chan diskTask, 10000)
	var diskWg sync.WaitGroup
	diskWg.Add(1)

	go func() {
		defer diskWg.Done()
		for task := range diskQueue {
			chunk, err := protocol.ParseChunk(task.payload)
			if err != nil {
				log.Printf("[%s] disk-writer parse chunk: %v", sessionID, err)
				continue
			}

			// Perform actual disk/S3 I/O
			if sess != nil {
				switch chunk.Stream {
				case protocol.StreamTtyOut, protocol.StreamStdout, protocol.StreamStderr:
					if err := sess.writer.WriteOutput(chunk.Data, chunk.Timestamp); err != nil {
						log.Printf("[%s] write output: %v", sessionID, err)
					}
				case protocol.StreamTtyIn, protocol.StreamStdin:
					if err := sess.writer.WriteInput(chunk.Data, chunk.Timestamp); err != nil {
						log.Printf("[%s] write input: %v", sessionID, err)
					}
				case protocol.StreamScreen:
					if sfw, ok := sess.writer.(store.ScreenFrameWriter); ok {
						if err := sfw.WriteScreenFrame(chunk.Data, chunk.Timestamp); err != nil {
							log.Printf("[%s] write screen frame: %v", sessionID, err)
						}
					}
				}
				sess.lastSeq = chunk.Seq
			}

			// ONLY NOW that data is on disk, we signal the ACK coalescer
			sendMu.Lock()
			pendingSeq = chunk.Seq
			sendCond.Signal()
			sendMu.Unlock()
		}
	}()

	go func() {
		for {
			sendMu.Lock()
			for pendingSeq == 0 && !pendingHeartbeat && !senderClosed {
				sendCond.Wait()
			}
			if senderClosed {
				sendMu.Unlock()
				return
			}
			seq := pendingSeq
			pendingSeq = 0
			hb := pendingHeartbeat
			pendingHeartbeat = false
			sid := sessionID
			sendMu.Unlock()

			if seq > 0 {
				ackPayload := srv.buildACK(sid, seq)
				if err := protocol.WriteMessage(w, protocol.MsgAck, ackPayload); err != nil {
					log.Printf("[%s] write ack (async): %v", sid, err)
					return
				}
			}
			if hb {
				if err := protocol.WriteMessage(w, protocol.MsgHeartbeatAck, nil); err != nil {
					log.Printf("[%s] write hb ack (async): %v", sid, err)
					return
				}
			}
		}
	}()

	defer func() {
		// Signal and wait for disk writer to finish
		close(diskQueue)
		diskWg.Wait()

		sendMu.Lock()
		senderClosed = true
		sendCond.Signal()
		sendMu.Unlock()
	}()
	// ──────────────────────────────────────────────────────────────────────

	for {
		msgType, plen, err := protocol.ReadHeader(r)
		if err != nil {
			if sess != nil {
				if sess.freezeCandidate {
					log.Printf("[%s] %s connection lost after SESSION_FREEZING — marking network outage",
						sess.id, remote)
					_ = sess.writer.MarkNetworkOutage()
				} else {
					log.Printf("SECURITY: [%s] %s dropped connection without session_end — session may be incomplete (shipper killed?): %v",
						sess.id, remote, err)
					_ = sess.writer.MarkIncomplete()
				}
				srv.sessionsIncomplete.Add(1)
				srv.closeSession(sess)
			}
			return
		}

		// SESSION_START is JSON metadata — apply a tighter size limit to prevent
		// a malicious (mTLS-authenticated) shipper from triggering a 1 MB allocation.
		if msgType == protocol.MsgSessionStart && plen > protocol.MaxSessionStartPayload {
			log.Printf("SECURITY: SESSION_START payload too large from %s: %d bytes (max %d) — dropping connection",
				remote, plen, protocol.MaxSessionStartPayload)
			return
		}
		payload, err := protocol.ReadPayload(r, plen)
		if err != nil {
			log.Printf("read payload from %s: %v", remote, err)
			return
		}

		switch msgType {
		case protocol.MsgSessionStart:
			start, err := protocol.ParseSessionStart(payload)
			if err != nil {
				log.Printf("parse session start from %s: %v", remote, err)
				return
			}
			// Verify the claimed host matches the presenting TLS certificate.
			// With shared client certificates (default setup) this is advisory only
			// and logs a warning.  Enable -strict-cert-host to reject mismatches
			// when each machine has its own certificate (stronger isolation).
			certs := conn.ConnectionState().PeerCertificates
			if len(certs) > 0 && !certMatchesHost(certs[0], start.Host) {
				if *flagStrictCertHost {
					log.Printf("SECURITY: %s claimed host=%q but cert CN=%q DNSNames=%v — closing",
						remote, start.Host, certs[0].Subject.CommonName, certs[0].DNSNames)
					return
				}
				log.Printf("WARNING: %s claimed host=%q but cert CN=%q DNSNames=%v (use -strict-cert-host to enforce)",
					remote, start.Host, certs[0].Subject.CommonName, certs[0].DNSNames)
			}

			// ── Block policy check BEFORE creating the session directory ──────
			// Checking first avoids leaving an empty session.cast on disk for
			// every denied attempt (which clutters the replay index).
			if blocked, msg, _ := srv.sessionStore.IsBlocked(context.Background(), start.User, start.Host); blocked {
				log.Printf("SECURITY: [%s] user=%s host=%s denied by block policy",
					start.SessionID, start.User, start.Host)
				_ = protocol.WriteMessage(w, protocol.MsgSessionDenied, []byte(msg))
				return
			}

			sess, err = srv.openSession(start)
			if err != nil {
				log.Printf("open session %s: %v", start.SessionID, err)
				return
			}
			log.Printf("[%s] start user=%s host=%s runas=%s uid=%d cmd=%q resolved=%q cwd=%s tsid=%s",
				sess.id, sess.user, sess.host, sess.runas, start.RunasUID,
				sess.command, start.ResolvedCommand, sess.cwd, sess.writer.TSID())

			if err := protocol.WriteMessage(w, protocol.MsgServerReady, nil); err != nil {
				log.Printf("[%s] write SERVER_READY: %v", start.SessionID, err)
				srv.closeSession(sess)
				sess = nil
				return
			}

			sendMu.Lock()
			sessionID = start.SessionID
			sendMu.Unlock()

		case protocol.MsgChunk:
			if sess == nil {
				log.Printf("chunk before session_start from %s", remote)
				return
			}

			// Non-blocking handoff to disk writer.
			// We block if the queue is truly full to maintain consistency,
			// but 10,000 slots should handle most practical bursts.
			diskQueue <- diskTask{msgType, payload}

		case protocol.MsgHeartbeat:
			sendMu.Lock()
			pendingHeartbeat = true
			sendCond.Signal()
			sendMu.Unlock()

		case protocol.MsgSessionEnd:
			end, err := protocol.ParseSessionEnd(payload)
			if err != nil {
				log.Printf("parse session_end: %v", err)
			}
			if sess != nil {
				if end != nil {
					_ = sess.writer.WriteExitCode(end.ExitCode)
					log.Printf("[%s] end user=%s exit=%d seq=%d duration=%s",
						sess.id, sess.user, end.ExitCode, end.FinalSeq,
						time.Since(sess.startTime).Round(time.Second))
				}
				srv.closeSession(sess)
			}
			return

		case protocol.MsgSessionFreezing:
			// Sent by the shipper on a NEW connection at markDead() time (~800 ms
			// after network loss), while the server is likely still reachable.
			// If the session is still active, set freezeCandidate so the TCP-drop
			// handler calls MarkNetworkOutage instead of MarkIncomplete.
			// If the session is already closed (TCP died before this message
			// arrived), upgrade the stored termination reason directly.
			sid := string(payload)
			log.Printf("SESSION_FREEZING from %s session_id=%s", remote, sid)
			srv.mu.Lock()
			activeSess := srv.sessions[sid]
			srv.mu.Unlock()
			if activeSess != nil {
				activeSess.freezeCandidate = true
			} else {
				if err := srv.sessionStore.MarkSessionNetworkOutage(context.Background(), sid); err != nil {
					log.Printf("mark network-outage session_id=%s: %v", sid, err)
				}
			}
			return

		case protocol.MsgSessionAbandon:
			// Fallback: sent by the shipper on a NEW connection after freeze-timeout
			// fires (5 min), only if network has recovered.  Upgrades the stored
			// termination reason in case SESSION_FREEZING was not received earlier.
			if sess != nil {
				log.Printf("[%s] SESSION_ABANDON on active connection — ignoring", sess.id)
				return
			}
			sid := string(payload)
			log.Printf("SESSION_ABANDON from %s session_id=%s", remote, sid)
			if err := srv.sessionStore.MarkSessionNetworkOutage(context.Background(), sid); err != nil {
				log.Printf("mark network-outage session_id=%s: %v", sid, err)
			}
			return

		default:
			log.Printf("unknown msg 0x%02x len=%d from %s", msgType, plen, remote)
		}
	}
}

func (srv *server) openSession(start *protocol.SessionStart) (*session, error) {
	if !validSessionID.MatchString(start.SessionID) {
		return nil, fmt.Errorf("invalid session_id: %q", start.SessionID)
	}
	user, err := sanitizeName(start.User)
	if err != nil {
		return nil, fmt.Errorf("invalid user field: %w", err)
	}
	host, err := sanitizeName(start.Host)
	if err != nil {
		return nil, fmt.Errorf("invalid host field: %w", err)
	}

	startTime := time.Unix(start.Ts, 0)

	runasUser := start.RunasUser
	if runasUser == "" {
		runasUser = "root"
	}
	cwd := start.Cwd
	if cwd == "" {
		cwd = "/"
	}

	w, err := srv.sessionStore.CreateSession(
		context.Background(),
		iolog.SessionMeta{
			SessionID:       start.SessionID,
			User:            user,
			Host:            host,
			RunasUser:       runasUser,
			RunasUID:        start.RunasUID,
			RunasGID:        start.RunasGID,
			Cwd:             cwd,
			Command:         start.Command,
			ResolvedCommand: start.ResolvedCommand,
			Flags:           start.Flags,
			Rows:            start.Rows,
			Cols:            start.Cols,
		},
		startTime,
	)
	if err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}

	// Mark the session as active so the replay server can distinguish
	// "currently recording" from "ended cleanly" or "ended abruptly (INCOMPLETE)".
	// Removed by closeSession() regardless of how the session ends.
	_ = w.MarkActive()

	sess := &session{
		id:        start.SessionID,
		user:      start.User,
		host:      start.Host,
		runas:     runasUser,
		cwd:       cwd,
		command:   start.Command,
		startTime: startTime,
		writer:    w,
	}

	srv.mu.Lock()
	if _, exists := srv.sessions[sess.id]; exists {
		srv.mu.Unlock()
		w.Close()
		return nil, fmt.Errorf("duplicate session id: %s", start.SessionID)
	}
	srv.sessions[sess.id] = sess
	srv.mu.Unlock()

	return sess, nil
}

func (srv *server) closeSession(sess *session) {
	if sess == nil {
		return
	}
	_ = sess.writer.MarkDone()
	if err := sess.writer.Close(); err != nil {
		log.Printf("[%s] close writer: %v", sess.id, err)
	}
	srv.mu.Lock()
	delete(srv.sessions, sess.id)
	srv.mu.Unlock()
	srv.sessionsTotal.Add(1)
}

func (srv *server) buildACK(sessionID string, seq uint64) []byte {
	ts := time.Now().UnixNano()
	msg := protocol.AckSignMessage(sessionID, seq, ts)
	sigSlice := ed25519.Sign(srv.signKey, msg)
	var sig [64]byte
	copy(sig[:], sigSlice)
	return protocol.EncodeAck(seq, ts, sig)
}

// certMatchesHost returns true if the TLS client certificate was issued for
// the given host name.  It checks DNS SANs first (per RFC 6125) then falls
// back to the Common Name.  A short hostname matches a fully-qualified cert
// name: host "gnarg" matches CN/SAN "gnarg.example.com".
func certMatchesHost(cert *x509.Certificate, host string) bool {
	h := strings.ToLower(host)
	for _, san := range cert.DNSNames {
		s := strings.ToLower(san)
		if s == h || strings.HasPrefix(s, h+".") {
			return true
		}
	}
	cn := strings.ToLower(cert.Subject.CommonName)
	return cn == h || strings.HasPrefix(cn, h+".")
}

// loadEd25519PrivKey reads a PEM-encoded PKCS8 ed25519 private key.
func loadEd25519PrivKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", path)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	ed, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key in %s is not ed25519", path)
	}
	return ed, nil
}

func buildTLSConfig() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(*flagCert, *flagKey)
	if err != nil {
		return nil, fmt.Errorf("load server cert: %w", err)
	}

	caPEM, err := os.ReadFile(*flagCA)
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("parse CA cert")
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}, nil
}
