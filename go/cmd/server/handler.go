package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"sudo-logger/internal/iolog"
	"sudo-logger/internal/protocol"
)

func (srv *server) handleConn(conn *tls.Conn) {
	sConn := &sessionConn{
		srv:       srv,
		conn:      conn,
		remote:    conn.RemoteAddr().String(),
		r:         bufio.NewReader(conn),
		w:         bufio.NewWriter(conn),
		diskQueue: make(chan diskTask, 50000),
		diskDone:  make(chan struct{}),
	}
	sConn.sendCond = sync.NewCond(&sConn.sendMu)
	sConn.run()
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

	meta := iolog.SessionMeta{
		SessionID:        start.SessionID,
		User:             user,
		Host:             host,
		RunasUser:        runasUser,
		RunasUID:         start.RunasUID,
		RunasGID:         start.RunasGID,
		Cwd:              cwd,
		Command:          start.Command,
		ResolvedCommand:  start.ResolvedCommand,
		Flags:            start.Flags,
		Rows:             start.Rows,
		Cols:             start.Cols,
		Source:           start.Source,
		ParentSessionID:  start.ParentSessionID,
		HasIO:            start.HasIO,
		DivergenceStatus: start.DivergenceStatus,
		CallerProcess:    start.CallerProcess,
	}
	meta.DivergenceStatus = meta.EffectiveDivergenceStatus()
	w, err := srv.sessionStore.CreateSession(context.Background(), meta, startTime)
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

// agentFetchableConfigKey reports whether key is one an agent may legitimately
// request via MsgFetchConfig. This is the only allowlist enforced on that
// message type — anything not listed here (e.g. approval-policy.yaml,
// jit-policy, siem.yaml) must never be handed to a peer over the wire.
func agentFetchableConfigKey(key string) bool {
	switch key {
	case "sandbox.yaml", "redaction_config":
		return true
	}
	return strings.HasPrefix(key, "sudoers/")
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
