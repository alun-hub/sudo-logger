// sudo-logserver: remote TLS server that receives sudo session recordings
// from sudo-shipper instances, writes sudo I/O log directories compatible
// with sudoreplay(8), and sends ed25519-signed ACKs back to the shipper.
//
// Sessions are stored under -logdir/<user>/<host>_<timestamp>/
// and replayed with: sudoreplay -d <logdir> <session-dir>
package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"sudo-logger/internal/iolog"
	"sudo-logger/internal/protocol"
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
)

type server struct {
	signKey ed25519.PrivateKey
	logDir  string

	mu       sync.Mutex
	sessions map[string]*session
}

type session struct {
	id        string
	user      string
	host      string
	runas     string
	cwd       string
	command   string
	startTime time.Time
	writer    *iolog.Writer
	lastSeq   uint64
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

	if err := os.MkdirAll(*flagLogDir, 0750); err != nil {
		log.Fatalf("create log dir: %v", err)
	}

	ln, err := tls.Listen("tcp", *flagListen, tlsCfg)
	if err != nil {
		log.Fatalf("listen %s: %v", *flagListen, err)
	}
	defer ln.Close()

	srv := &server{
		signKey: signKey,
		logDir:  *flagLogDir,
		sessions: make(map[string]*session),
	}

	log.Printf("sudo-logserver listening on %s, writing to %s", *flagListen, *flagLogDir)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go srv.handleConn(conn.(*tls.Conn))
	}
}

func (srv *server) handleConn(conn *tls.Conn) {
	defer conn.Close()

	remote := conn.RemoteAddr().String()
	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)

	var sess *session

	for {
		msgType, plen, err := protocol.ReadHeader(r)
		if err != nil {
			if sess != nil {
				log.Printf("SECURITY: [%s] %s dropped connection without session_end — session may be incomplete (shipper killed?): %v",
					sess.id, remote, err)
				_ = os.WriteFile(sess.writer.Dir()+"/INCOMPLETE",
					[]byte("connection lost without session_end\n"), 0640)
				srv.closeSession(sess)
			}
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
			sess, err = srv.openSession(start)
			if err != nil {
				log.Printf("open session %s: %v", start.SessionID, err)
				return
			}
			log.Printf("[%s] start user=%s host=%s runas=%s uid=%d cmd=%q resolved=%q cwd=%s dir=%s",
				sess.id, sess.user, sess.host, sess.runas, start.RunasUID,
				sess.command, start.ResolvedCommand, sess.cwd, sess.writer.Dir())

		case protocol.MsgChunk:
			if sess == nil {
				log.Printf("chunk before session_start from %s", remote)
				return
			}
			chunk, err := protocol.ParseChunk(payload)
			if err != nil {
				log.Printf("[%s] parse chunk: %v", sess.id, err)
				return
			}

			switch chunk.Stream {
			case protocol.StreamTtyOut, protocol.StreamStdout, protocol.StreamStderr:
				if err := sess.writer.WriteOutput(chunk.Data, chunk.Timestamp); err != nil {
					log.Printf("[%s] write output: %v", sess.id, err)
				}
			case protocol.StreamTtyIn, protocol.StreamStdin:
				if err := sess.writer.WriteInput(chunk.Data, chunk.Timestamp); err != nil {
					log.Printf("[%s] write input: %v", sess.id, err)
				}
			}

			sess.lastSeq = chunk.Seq

			ackPayload := srv.buildACK(sess.id, chunk.Seq)
			if err := protocol.WriteMessage(w, protocol.MsgAck, ackPayload); err != nil {
				log.Printf("[%s] write ack: %v", sess.id, err)
				return
			}

		case protocol.MsgHeartbeat:
			if err := protocol.WriteMessage(w, protocol.MsgHeartbeatAck, nil); err != nil {
				return
			}

		case protocol.MsgSessionEnd:
			end, err := protocol.ParseSessionEnd(payload)
			if err != nil {
				log.Printf("parse session_end: %v", err)
			}
			if sess != nil {
				if end != nil {
					_ = os.WriteFile(sess.writer.Dir()+"/exit_code",
						[]byte(strconv.Itoa(int(end.ExitCode))), 0640)
					log.Printf("[%s] end user=%s exit=%d seq=%d duration=%s",
						sess.id, sess.user, end.ExitCode, end.FinalSeq,
						time.Since(sess.startTime).Round(time.Second))
				}
				srv.closeSession(sess)
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

	w, err := iolog.NewWriter(
		srv.logDir,
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
		return nil, fmt.Errorf("create iolog: %w", err)
	}

	// Mark the session as active so the replay server can distinguish
	// "currently recording" from "ended cleanly" or "ended abruptly (INCOMPLETE)".
	// Removed by closeSession() regardless of how the session ends.
	_ = os.WriteFile(w.Dir()+"/ACTIVE", []byte("session in progress\n"), 0640)

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
	_ = os.Remove(sess.writer.Dir() + "/ACTIVE")
	if err := sess.writer.Close(); err != nil {
		log.Printf("[%s] close writer: %v", sess.id, err)
	}
	srv.mu.Lock()
	delete(srv.sessions, sess.id)
	srv.mu.Unlock()
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
