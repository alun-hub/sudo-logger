// sudo-logserver: remote TLS server that receives sudo session recordings
// from sudo-shipper instances, writes sudo I/O log directories compatible
// with sudoreplay(8), and sends HMAC-signed ACKs back to the shipper.
//
// Sessions are stored under -logdir/<user>/<host>_<timestamp>/
// and replayed with: sudoreplay -d <logdir> <session-dir>
package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
	"regexp"
	"sync"
	"time"

	"sudo-logger/internal/iolog"
	"sudo-logger/internal/protocol"
)

// validName matches safe directory name components: alphanumeric plus .-_
// Maximum 64 characters. Rejects empty strings, dots-only, and path separators.
var validName = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,64}$`)

func sanitizeName(s string) (string, error) {
	if !validName.MatchString(s) {
		return "", fmt.Errorf("invalid characters or length in name: %q", s)
	}
	return s, nil
}

var (
	flagListen = flag.String("listen", ":9876", "Listen address (TLS)")
	flagLogDir = flag.String("logdir", "/var/log/sudoreplay", "Base directory for session logs")
	flagCert   = flag.String("cert", "/etc/sudo-logger/server.crt", "Server TLS certificate")
	flagKey    = flag.String("key", "/etc/sudo-logger/server.key", "Server TLS key")
	flagCA     = flag.String("ca", "/etc/sudo-logger/ca.crt", "CA certificate (for client auth)")
	flagSignKey = flag.String("signkey", "/etc/sudo-logger/ack-sign.key", "ed25519 private key for ACK signing (PEM)")
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
				log.Printf("[%s] %s disconnected: %v", sess.id, remote, err)
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
			sess, err = srv.openSession(start)
			if err != nil {
				log.Printf("open session %s: %v", start.SessionID, err)
				return
			}
			log.Printf("[%s] start user=%s host=%s cmd=%s dir=%s",
				sess.id, sess.user, sess.host, sess.command, sess.writer.Dir())

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
			case protocol.StreamTtyOut, protocol.StreamStdout:
				if err := sess.writer.WriteOutput(chunk.Data, chunk.Timestamp); err != nil {
					log.Printf("[%s] write output: %v", sess.id, err)
				}
			case protocol.StreamTtyIn, protocol.StreamStdin:
				if err := sess.writer.WriteInput(chunk.Data, chunk.Timestamp); err != nil {
					log.Printf("[%s] write input: %v", sess.id, err)
				}
			}

			sess.lastSeq = chunk.Seq

			ackPayload := srv.buildACK(chunk.Seq)
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
	user, err := sanitizeName(start.User)
	if err != nil {
		return nil, fmt.Errorf("invalid user field: %w", err)
	}
	host, err := sanitizeName(start.Host)
	if err != nil {
		return nil, fmt.Errorf("invalid host field: %w", err)
	}

	startTime := time.Unix(start.Ts, 0)

	w, err := iolog.NewWriter(
		srv.logDir,
		user,
		host,
		"root",        // runas — always root for now
		"unknown",     // tty — not yet sent by plugin
		start.Command,
		startTime,
	)
	if err != nil {
		return nil, fmt.Errorf("create iolog: %w", err)
	}

	sess := &session{
		id:        start.SessionID,
		user:      start.User,
		host:      start.Host,
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
	if err := sess.writer.Close(); err != nil {
		log.Printf("[%s] close writer: %v", sess.id, err)
	}
	srv.mu.Lock()
	delete(srv.sessions, sess.id)
	srv.mu.Unlock()
}

func (srv *server) buildACK(seq uint64) []byte {
	ts := time.Now().UnixNano()

	var msg [16]byte
	binary.BigEndian.PutUint64(msg[0:], seq)
	binary.BigEndian.PutUint64(msg[8:], uint64(ts))
	sigSlice := ed25519.Sign(srv.signKey, msg[:])

	var sig [64]byte
	copy(sig[:], sigSlice)
	return protocol.EncodeAck(seq, ts, sig)
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
