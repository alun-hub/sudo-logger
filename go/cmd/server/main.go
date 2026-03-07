// sudo-logserver: remote TLS server that receives sudo session recordings
// from sudo-shipper instances, writes sudo I/O log directories compatible
// with sudoreplay(8), and sends HMAC-signed ACKs back to the shipper.
//
// Sessions are stored under -logdir/<user>/<host>_<timestamp>/
// and replayed with: sudoreplay -d <logdir> <session-dir>
package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"sudo-logger/internal/iolog"
	"sudo-logger/internal/protocol"
)

var (
	flagListen = flag.String("listen", ":9876", "Listen address (TLS)")
	flagLogDir = flag.String("logdir", "/var/log/sudoreplay", "Base directory for session logs")
	flagCert   = flag.String("cert", "/etc/sudo-logger/server.crt", "Server TLS certificate")
	flagKey    = flag.String("key", "/etc/sudo-logger/server.key", "Server TLS key")
	flagCA     = flag.String("ca", "/etc/sudo-logger/ca.crt", "CA certificate (for client auth)")
	flagHMAC   = flag.String("hmackey", "/etc/sudo-logger/hmac.key", "HMAC key file")
)

type server struct {
	hmacKey []byte
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

	hmacKey, err := os.ReadFile(*flagHMAC)
	if err != nil {
		log.Fatalf("read hmac key: %v", err)
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
		hmacKey:  hmacKey,
		logDir:   *flagLogDir,
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

		case protocol.MsgSessionEnd:
			end, err := protocol.ParseSessionEnd(payload)
			if err != nil {
				log.Printf("parse session_end: %v", err)
			}
			if sess != nil {
				log.Printf("[%s] end user=%s exit=%d seq=%d duration=%s",
					sess.id, sess.user, end.ExitCode, end.FinalSeq,
					time.Since(sess.startTime).Round(time.Second))
				srv.closeSession(sess)
			}
			return

		default:
			log.Printf("unknown msg 0x%02x len=%d from %s", msgType, plen, remote)
		}
	}
}

func (srv *server) openSession(start *protocol.SessionStart) (*session, error) {
	startTime := time.Unix(start.Ts, 0)

	w, err := iolog.NewWriter(
		srv.logDir,
		start.User,
		start.Host,
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
	srv.sessions[sess.id] = sess
	srv.mu.Unlock()

	return sess, nil
}

func (srv *server) closeSession(sess *session) {
	if sess == nil {
		return
	}
	sess.writer.Close()
	srv.mu.Lock()
	delete(srv.sessions, sess.id)
	srv.mu.Unlock()
}

func (srv *server) buildACK(seq uint64) []byte {
	ts := time.Now().UnixNano()

	mac := hmac.New(sha256.New, srv.hmacKey)
	var buf [16]byte
	binary.BigEndian.PutUint64(buf[0:], seq)
	binary.BigEndian.PutUint64(buf[8:], uint64(ts))
	mac.Write(buf[:])

	var h [32]byte
	copy(h[:], mac.Sum(nil))
	return protocol.EncodeAck(seq, ts, h)
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
