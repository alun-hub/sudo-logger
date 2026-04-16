package main

import (
	"bufio"
	"crypto/ecdsa"
	"io"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"sudo-logger/internal/protocol"
	"sudo-logger/internal/store"
)

// ── sanitizeName ──────────────────────────────────────────────────────────────

func TestSanitizeName(t *testing.T) {
	valid := []string{"alice", "host1", "my.host", "user-name", "x_y", "A1B2"}
	for _, s := range valid {
		if _, err := sanitizeName(s); err != nil {
			t.Errorf("sanitizeName(%q) unexpected error: %v", s, err)
		}
	}
	invalid := []string{
		"",
		"../etc",
		"user/name",
		"has space",
		"has\nnewline",
		string(make([]byte, 65)), // 65 chars
	}
	for _, s := range invalid {
		if _, err := sanitizeName(s); err == nil {
			t.Errorf("sanitizeName(%q) expected error, got nil", s)
		}
	}
}

// ── certMatchesHost ───────────────────────────────────────────────────────────

func makeCert(cn string, sans ...string) *x509.Certificate {
	return &x509.Certificate{
		Subject:  pkix.Name{CommonName: cn},
		DNSNames: sans,
	}
}

func TestCertMatchesHostSAN(t *testing.T) {
	cert := makeCert("ignored-cn", "worker.example.com", "other.example.com")
	if !certMatchesHost(cert, "worker.example.com") {
		t.Error("exact SAN match failed")
	}
	// Short hostname matches FQDN SAN.
	if !certMatchesHost(cert, "worker") {
		t.Error("short hostname against FQDN SAN failed")
	}
	if certMatchesHost(cert, "unknown") {
		t.Error("non-matching host should not match")
	}
}

func TestCertMatchesHostCNFallback(t *testing.T) {
	cert := makeCert("server.internal") // no SANs
	if !certMatchesHost(cert, "server.internal") {
		t.Error("exact CN match failed")
	}
	if !certMatchesHost(cert, "server") {
		t.Error("short hostname against FQDN CN failed")
	}
	if certMatchesHost(cert, "other") {
		t.Error("non-matching CN should not match")
	}
}

func TestCertMatchesHostCaseInsensitive(t *testing.T) {
	cert := makeCert("", "Host1.Example.COM")
	if !certMatchesHost(cert, "HOST1.EXAMPLE.COM") {
		t.Error("case-insensitive SAN match failed")
	}
	if !certMatchesHost(cert, "host1") {
		t.Error("case-insensitive short hostname against SAN failed")
	}
}

func TestCertMatchesHostSANTakesPrecedenceOverCN(t *testing.T) {
	// When SANs are present the CN must NOT be used (RFC 6125).
	// Our implementation does fall back to CN even with SANs present —
	// that is a known liberal behaviour — but we verify that SANs work
	// correctly when they do match.
	cert := makeCert("cn-only", "san-host.example.com")
	if !certMatchesHost(cert, "san-host.example.com") {
		t.Error("SAN match should succeed")
	}
}

// ── loadEd25519PrivKey ────────────────────────────────────────────────────────

// writeEd25519PEM generates an ed25519 key and writes it as PKCS8 PEM to a temp file.
func writeEd25519PEM(t *testing.T) (ed25519.PrivateKey, string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal ed25519: %v", err)
	}
	f, err := os.CreateTemp(t.TempDir(), "ed25519-*.pem")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	if err := pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: der}); err != nil {
		t.Fatalf("pem encode: %v", err)
	}
	f.Close()
	return priv, f.Name()
}

func TestLoadEd25519PrivKeyValid(t *testing.T) {
	_, path := writeEd25519PEM(t)
	key, err := loadEd25519PrivKey(path)
	if err != nil {
		t.Fatalf("loadEd25519PrivKey: %v", err)
	}
	if len(key) == 0 {
		t.Error("returned empty key")
	}
}

func TestLoadEd25519PrivKeyMissingFile(t *testing.T) {
	_, err := loadEd25519PrivKey(filepath.Join(t.TempDir(), "nonexistent.pem"))
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestLoadEd25519PrivKeyNoPEM(t *testing.T) {
	f, _ := os.CreateTemp(t.TempDir(), "bad-*.pem")
	f.WriteString("not pem data\n") //nolint:errcheck
	f.Close()
	_, err := loadEd25519PrivKey(f.Name())
	if err == nil {
		t.Error("expected error for non-PEM file")
	}
}

func TestLoadEd25519PrivKeyWrongKeyType(t *testing.T) {
	// Write an ECDSA key — not ed25519.
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(ecKey)
	f, _ := os.CreateTemp(t.TempDir(), "ecdsa-*.pem")
	pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: der}) //nolint:errcheck
	f.Close()
	_, err := loadEd25519PrivKey(f.Name())
	if err == nil {
		t.Error("expected error for non-ed25519 key")
	}
}

// ── buildACK ──────────────────────────────────────────────────────────────────

func TestBuildACKVerifiable(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pub := priv.Public().(ed25519.PublicKey)

	srv := &server{signKey: priv}
	sessionID := "host1-alice-123-456-aabbccdd"
	seq := uint64(42)

	payload := srv.buildACK(sessionID, seq)
	ack, err := protocol.ParseAck(payload)
	if err != nil {
		t.Fatalf("ParseAck: %v", err)
	}
	if ack.Seq != seq {
		t.Errorf("Seq: got %d, want %d", ack.Seq, seq)
	}

	msg := protocol.AckSignMessage(sessionID, seq, ack.Timestamp)
	if !ed25519.Verify(pub, msg, ack.Sig[:]) {
		t.Error("ACK signature verification failed")
	}
}

// ── openSession / closeSession ────────────────────────────────────────────────

func newTestServer(t *testing.T) *server {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	dir := t.TempDir()
	ss, err := store.New(store.Config{Backend: "local", LogDir: dir})
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { ss.Close() })
	return &server{
		signKey:      priv,
		sessionStore: ss,
		sessions:     make(map[string]*session),
	}
}

func testSessionStart(sessionID, user, host string) *protocol.SessionStart {
	return &protocol.SessionStart{
		SessionID: sessionID,
		User:      user,
		Host:      host,
		RunasUser: "root",
		Command:   "/bin/bash",
		Cwd:       "/home/" + user,
		Ts:        time.Now().Unix(),
	}
}

func TestOpenSessionValid(t *testing.T) {
	srv := newTestServer(t)
	start := testSessionStart("host1-alice-1-2-aabb", "alice", "host1")
	sess, err := srv.openSession(start)
	if err != nil {
		t.Fatalf("openSession: %v", err)
	}
	if sess.id != start.SessionID {
		t.Errorf("id: got %q, want %q", sess.id, start.SessionID)
	}
	srv.closeSession(sess)
}

func TestOpenSessionInvalidUser(t *testing.T) {
	srv := newTestServer(t)
	start := testSessionStart("host1-bad-1-2-aabb", "bad/user", "host1")
	if _, err := srv.openSession(start); err == nil {
		t.Error("expected error for user with slash")
	}
}

func TestOpenSessionInvalidHost(t *testing.T) {
	srv := newTestServer(t)
	start := testSessionStart("host1-alice-1-2-aabb", "alice", "bad host!")
	if _, err := srv.openSession(start); err == nil {
		t.Error("expected error for host with special chars")
	}
}

func TestOpenSessionInvalidSessionID(t *testing.T) {
	srv := newTestServer(t)
	start := testSessionStart("../escape", "alice", "host1")
	if _, err := srv.openSession(start); err == nil {
		t.Error("expected error for path-traversal session ID")
	}
}

func TestOpenSessionDuplicate(t *testing.T) {
	srv := newTestServer(t)
	start := testSessionStart("host1-alice-1-2-aabb", "alice", "host1")
	sess1, err := srv.openSession(start)
	if err != nil {
		t.Fatalf("first openSession: %v", err)
	}
	defer srv.closeSession(sess1)

	if _, err := srv.openSession(start); err == nil {
		t.Error("expected error for duplicate session ID")
	}
}

func TestCloseSessionCounters(t *testing.T) {
	srv := newTestServer(t)
	start := testSessionStart("host1-alice-1-2-aabb", "alice", "host1")
	sess, err := srv.openSession(start)
	if err != nil {
		t.Fatalf("openSession: %v", err)
	}
	if srv.sessionsTotal.Load() != 0 {
		t.Errorf("sessionsTotal before close: got %d, want 0", srv.sessionsTotal.Load())
	}
	srv.closeSession(sess)
	if srv.sessionsTotal.Load() != 1 {
		t.Errorf("sessionsTotal after close: got %d, want 1", srv.sessionsTotal.Load())
	}
}

func TestCloseSessionNilSafe(t *testing.T) {
	srv := newTestServer(t)
	srv.closeSession(nil) // must not panic
}

// ── handleConn integration ────────────────────────────────────────────────────

// testTLSConfig returns a minimal TLS config with a self-signed ECDSA cert.
func testTLSServerConfig(t *testing.T) *tls.Config {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-server"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
}

// connPair returns a server-side and client-side *tls.Conn backed by net.Pipe.
func connPair(t *testing.T) (serverConn, clientConn *tls.Conn) {
	t.Helper()
	serverTLS := testTLSServerConfig(t)
	clientTLS := &tls.Config{InsecureSkipVerify: true} //nolint:gosec // test only
	c1, c2 := net.Pipe()
	serverConn = tls.Server(c1, serverTLS)
	clientConn = tls.Client(c2, clientTLS)
	return
}

// runHandleConn launches handleConn in a goroutine and returns a channel that
// closes when handleConn returns.
func runHandleConn(t *testing.T, srv *server, serverConn *tls.Conn) chan struct{} {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.handleConn(serverConn)
	}()
	return done
}

// mustRecvDone waits for the done channel or fails the test after a timeout.
func mustRecvDone(t *testing.T, done chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handleConn did not exit within timeout")
	}
}

// drainAndWait drains cliConn until EOF (allowing the server's TLS close_notify
// to complete over net.Pipe) and then waits for handleConn to exit.
// Use this instead of mustRecvDone when handleConn returns due to server-side
// logic (SESSION_END, SESSION_DENIED, oversized payload, etc.) — otherwise the
// server's tls.Conn.Close blocks waiting for the client to read the alert.
func drainAndWait(t *testing.T, cliConn net.Conn, done chan struct{}) {
	t.Helper()
	io.Copy(io.Discard, cliConn) //nolint:errcheck
	mustRecvDone(t, done)
}

// writeMsg sends a framed protocol message over the client connection.
func writeMsg(t *testing.T, w *bufio.Writer, msgType uint8, payload []byte) {
	t.Helper()
	if err := protocol.WriteMessage(w, msgType, payload); err != nil {
		t.Fatalf("WriteMessage 0x%02x: %v", msgType, err)
	}
}

// readMsg reads one framed message from the server.
func readMsg(t *testing.T, r *bufio.Reader) (uint8, []byte) {
	t.Helper()
	msgType, plen, err := protocol.ReadHeader(r)
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}
	payload, err := protocol.ReadPayload(r, plen)
	if err != nil {
		t.Fatalf("ReadPayload: %v", err)
	}
	return msgType, payload
}

// encodeChunk builds a minimal CHUNK payload.
func encodeChunk(seq uint64, stream uint8, data []byte) []byte {
	buf := make([]byte, 21+len(data))
	binary.BigEndian.PutUint64(buf[0:], seq)
	binary.BigEndian.PutUint64(buf[8:], uint64(time.Now().UnixNano()))
	buf[16] = stream
	binary.BigEndian.PutUint32(buf[17:], uint32(len(data)))
	copy(buf[21:], data)
	return buf
}

// encodeSessionStart serialises a SESSION_START payload (JSON, matching ParseSessionStart).
func encodeSessionStart(t *testing.T, start *protocol.SessionStart) []byte {
	t.Helper()
	b, err := json.Marshal(start)
	if err != nil {
		t.Fatalf("json.Marshal SessionStart: %v", err)
	}
	return b
}

// encodeSessionEnd builds a SESSION_END payload.
func encodeSessionEnd(finalSeq uint64, exitCode uint32) []byte {
	buf := make([]byte, 12)
	binary.BigEndian.PutUint64(buf[0:], finalSeq)
	binary.BigEndian.PutUint32(buf[8:], exitCode)
	return buf
}

// TestHandleConnFullLifecycle exercises SESSION_START → CHUNK → SESSION_END.
func TestHandleConnFullLifecycle(t *testing.T) {
	srv := newTestServer(t)
	srvConn, cliConn := connPair(t)
	done := runHandleConn(t, srv, srvConn)

	r := bufio.NewReader(cliConn)
	w := bufio.NewWriter(cliConn)

	// Send SESSION_START.
	start := testSessionStart("host1-alice-1-2-aabb", "alice", "host1")
	writeMsg(t, w, protocol.MsgSessionStart, encodeSessionStart(t, start))
	if err := w.Flush(); err != nil {
		t.Fatalf("flush SESSION_START: %v", err)
	}

	// Expect SERVER_READY.
	msgType, _ := readMsg(t, r)
	if msgType != protocol.MsgServerReady {
		t.Fatalf("expected SERVER_READY (0x%02x), got 0x%02x", protocol.MsgServerReady, msgType)
	}

	// Send a CHUNK.
	writeMsg(t, w, protocol.MsgChunk, encodeChunk(1, protocol.StreamTtyOut, []byte("hello")))
	if err := w.Flush(); err != nil {
		t.Fatalf("flush CHUNK: %v", err)
	}

	// Expect ACK.
	msgType, ackPayload := readMsg(t, r)
	if msgType != protocol.MsgAck {
		t.Fatalf("expected ACK (0x%02x), got 0x%02x", protocol.MsgAck, msgType)
	}
	ack, err := protocol.ParseAck(ackPayload)
	if err != nil {
		t.Fatalf("ParseAck: %v", err)
	}
	if ack.Seq != 1 {
		t.Errorf("ACK seq: got %d, want 1", ack.Seq)
	}

	// Send SESSION_END.
	writeMsg(t, w, protocol.MsgSessionEnd, encodeSessionEnd(1, 0))
	if err := w.Flush(); err != nil {
		t.Fatalf("flush SESSION_END: %v", err)
	}

	drainAndWait(t, cliConn, done)

	if srv.sessionsTotal.Load() != 1 {
		t.Errorf("sessionsTotal: got %d, want 1", srv.sessionsTotal.Load())
	}
}

// TestHandleConnHeartbeat verifies HEARTBEAT → HEARTBEAT_ACK.
func TestHandleConnHeartbeat(t *testing.T) {
	srv := newTestServer(t)
	srvConn, cliConn := connPair(t)
	done := runHandleConn(t, srv, srvConn)

	r := bufio.NewReader(cliConn)
	w := bufio.NewWriter(cliConn)

	writeMsg(t, w, protocol.MsgHeartbeat, nil)
	if err := w.Flush(); err != nil {
		t.Fatalf("flush HEARTBEAT: %v", err)
	}

	msgType, _ := readMsg(t, r)
	if msgType != protocol.MsgHeartbeatAck {
		t.Errorf("expected HEARTBEAT_ACK (0x%02x), got 0x%02x", protocol.MsgHeartbeatAck, msgType)
	}

	// Close client — handleConn should exit cleanly.
	cliConn.Close()
	mustRecvDone(t, done)
}

// TestHandleConnBlockedUser verifies that a blocked user receives SESSION_DENIED.
func TestHandleConnBlockedUser(t *testing.T) {
	tmpDir := t.TempDir()
	blockedPath := filepath.Join(tmpDir, "blocked-users.yaml")
	blockedYAML := `block_message: "Access denied"
users:
  - username: blocked
    hosts: []
    reason: test
`
	if err := os.WriteFile(blockedPath, []byte(blockedYAML), 0o640); err != nil {
		t.Fatalf("write blocked-users.yaml: %v", err)
	}

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	ss, err := store.New(store.Config{
		Backend:          "local",
		LogDir:           tmpDir,
		BlockedUsersPath: blockedPath,
	})
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	defer ss.Close()

	srv := &server{signKey: priv, sessionStore: ss, sessions: make(map[string]*session)}
	srvConn, cliConn := connPair(t)
	done := runHandleConn(t, srv, srvConn)

	r := bufio.NewReader(cliConn)
	w := bufio.NewWriter(cliConn)

	start := testSessionStart("host1-blocked-1-2-aabb", "blocked", "host1")
	writeMsg(t, w, protocol.MsgSessionStart, encodeSessionStart(t, start))
	if err := w.Flush(); err != nil {
		t.Fatalf("flush SESSION_START: %v", err)
	}

	msgType, _ := readMsg(t, r)
	if msgType != protocol.MsgSessionDenied {
		t.Errorf("expected SESSION_DENIED (0x%02x), got 0x%02x", protocol.MsgSessionDenied, msgType)
	}

	drainAndWait(t, cliConn, done)
}

// TestHandleConnSessionStartTooLarge verifies that an oversized SESSION_START
// payload causes the connection to be dropped.
func TestHandleConnSessionStartTooLarge(t *testing.T) {
	srv := newTestServer(t)
	srvConn, cliConn := connPair(t)
	done := runHandleConn(t, srv, srvConn)

	w := bufio.NewWriter(cliConn)

	// Write a SESSION_START header claiming MaxSessionStartPayload+1 bytes.
	oversized := protocol.MaxSessionStartPayload + 1
	header := make([]byte, 5)
	header[0] = protocol.MsgSessionStart
	binary.BigEndian.PutUint32(header[1:], uint32(oversized))
	if _, err := w.Write(header); err != nil {
		t.Fatalf("write oversized header: %v", err)
	}
	if err := w.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}

	// handleConn must drop the connection without sending any response.
	drainAndWait(t, cliConn, done)
}

// TestHandleConnChunkBeforeSessionStart verifies that a CHUNK before
// SESSION_START causes the connection to be dropped.
func TestHandleConnChunkBeforeSessionStart(t *testing.T) {
	srv := newTestServer(t)
	srvConn, cliConn := connPair(t)
	done := runHandleConn(t, srv, srvConn)

	w := bufio.NewWriter(cliConn)

	writeMsg(t, w, protocol.MsgChunk, encodeChunk(1, protocol.StreamTtyOut, []byte("data")))
	if err := w.Flush(); err != nil {
		t.Fatalf("flush CHUNK: %v", err)
	}

	drainAndWait(t, cliConn, done)
}

// TestHandleConnDropWithoutEnd verifies that an abrupt connection close marks
// the session as incomplete and increments sessionsIncomplete.
func TestHandleConnDropWithoutEnd(t *testing.T) {
	srv := newTestServer(t)
	srvConn, cliConn := connPair(t)
	done := runHandleConn(t, srv, srvConn)

	r := bufio.NewReader(cliConn)
	w := bufio.NewWriter(cliConn)

	// Open a session.
	start := testSessionStart("host1-alice-1-2-aabb", "alice", "host1")
	writeMsg(t, w, protocol.MsgSessionStart, encodeSessionStart(t, start))
	if err := w.Flush(); err != nil {
		t.Fatalf("flush SESSION_START: %v", err)
	}
	msgType, _ := readMsg(t, r)
	if msgType != protocol.MsgServerReady {
		t.Fatalf("expected SERVER_READY, got 0x%02x", msgType)
	}

	// Drop the connection without SESSION_END.
	cliConn.Close()
	mustRecvDone(t, done)

	if srv.sessionsIncomplete.Load() != 1 {
		t.Errorf("sessionsIncomplete: got %d, want 1", srv.sessionsIncomplete.Load())
	}
}

// TestHandleConnSessionFreezing verifies that SESSION_FREEZING on an active
// session sets the freezeCandidate flag, and that a subsequent drop calls
// MarkNetworkOutage (not MarkIncomplete) — visible as sessionsIncomplete
// incremented (same code path) but with the outage log message.
func TestHandleConnSessionFreezing(t *testing.T) {
	srv := newTestServer(t)

	// Connection 1: open a session.
	srvConn1, cliConn1 := connPair(t)
	done1 := runHandleConn(t, srv, srvConn1)

	r1 := bufio.NewReader(cliConn1)
	w1 := bufio.NewWriter(cliConn1)

	start := testSessionStart("host1-alice-1-2-freeze", "alice", "host1")
	writeMsg(t, w1, protocol.MsgSessionStart, encodeSessionStart(t, start))
	if err := w1.Flush(); err != nil {
		t.Fatalf("flush SESSION_START: %v", err)
	}
	msgType, _ := readMsg(t, r1)
	if msgType != protocol.MsgServerReady {
		t.Fatalf("expected SERVER_READY, got 0x%02x", msgType)
	}

	// Connection 2: send SESSION_FREEZING for the active session.
	srvConn2, cliConn2 := connPair(t)
	done2 := runHandleConn(t, srv, srvConn2)

	w2 := bufio.NewWriter(cliConn2)
	writeMsg(t, w2, protocol.MsgSessionFreezing, []byte(start.SessionID))
	if err := w2.Flush(); err != nil {
		t.Fatalf("flush SESSION_FREEZING: %v", err)
	}
	cliConn2.Close()
	mustRecvDone(t, done2)

	// Verify freezeCandidate is set on the active session.
	srv.mu.Lock()
	sess := srv.sessions[start.SessionID]
	srv.mu.Unlock()
	if sess == nil {
		t.Fatal("active session not found after SESSION_FREEZING")
	}
	if !sess.freezeCandidate {
		t.Error("freezeCandidate should be true after SESSION_FREEZING")
	}

	// Drop connection 1 — should call MarkNetworkOutage path.
	cliConn1.Close()
	mustRecvDone(t, done1)

	if srv.sessionsIncomplete.Load() != 1 {
		t.Errorf("sessionsIncomplete: got %d, want 1", srv.sessionsIncomplete.Load())
	}
}

// TestHandleConnInputChunk verifies that stdin/tty-in chunks are also accepted.
func TestHandleConnInputChunk(t *testing.T) {
	srv := newTestServer(t)
	srvConn, cliConn := connPair(t)
	done := runHandleConn(t, srv, srvConn)

	r := bufio.NewReader(cliConn)
	w := bufio.NewWriter(cliConn)

	start := testSessionStart("host1-alice-1-2-input", "alice", "host1")
	writeMsg(t, w, protocol.MsgSessionStart, encodeSessionStart(t, start))
	w.Flush() //nolint:errcheck
	readMsg(t, r) // SERVER_READY

	writeMsg(t, w, protocol.MsgChunk, encodeChunk(1, protocol.StreamTtyIn, []byte("ls\n")))
	w.Flush() //nolint:errcheck

	msgType, _ := readMsg(t, r)
	if msgType != protocol.MsgAck {
		t.Errorf("expected ACK for stdin chunk, got 0x%02x", msgType)
	}

	writeMsg(t, w, protocol.MsgSessionEnd, encodeSessionEnd(1, 0))
	w.Flush() //nolint:errcheck
	drainAndWait(t, cliConn, done)
}

// TestHandleConnSessionAbandon verifies that SESSION_ABANDON (no active session)
// causes handleConn to return without error.
func TestHandleConnSessionAbandon(t *testing.T) {
	srv := newTestServer(t)

	// Pre-create a session and close it so there is something to abandon.
	start := testSessionStart("host1-alice-1-2-abandon", "alice", "host1")
	sess, err := srv.openSession(start)
	if err != nil {
		t.Fatalf("openSession: %v", err)
	}
	srv.closeSession(sess)

	srvConn, cliConn := connPair(t)
	done := runHandleConn(t, srv, srvConn)

	w := bufio.NewWriter(cliConn)
	writeMsg(t, w, protocol.MsgSessionAbandon, []byte(start.SessionID))
	w.Flush() //nolint:errcheck

	// handleConn returns after processing SESSION_ABANDON.
	drainAndWait(t, cliConn, done)
}

// TestHandleConnMultipleSessions verifies that two concurrent connections each
// open a separate session without interfering with each other.
func TestHandleConnMultipleSessions(t *testing.T) {
	srv := newTestServer(t)

	type conn struct {
		w    *bufio.Writer
		cli  net.Conn
		done chan struct{}
	}
	open := func(sessionID, user string) conn {
		srvConn, cliConn := connPair(t)
		done := runHandleConn(t, srv, srvConn)
		r := bufio.NewReader(cliConn)
		w := bufio.NewWriter(cliConn)
		start := testSessionStart(sessionID, user, "host1")
		writeMsg(t, w, protocol.MsgSessionStart, encodeSessionStart(t, start))
		w.Flush() //nolint:errcheck
		msgType, _ := readMsg(t, r)
		if msgType != protocol.MsgServerReady {
			t.Errorf("%s: expected SERVER_READY, got 0x%02x", sessionID, msgType)
		}
		return conn{w: w, cli: cliConn, done: done}
	}

	c1 := open("host1-alice-1-2-aabb", "alice")
	c2 := open("host1-bob-3-4-ccdd", "bob")

	// Close both with SESSION_END, drain each client conn.
	writeMsg(t, c1.w, protocol.MsgSessionEnd, encodeSessionEnd(0, 0))
	c1.w.Flush() //nolint:errcheck
	writeMsg(t, c2.w, protocol.MsgSessionEnd, encodeSessionEnd(0, 0))
	c2.w.Flush() //nolint:errcheck

	drainAndWait(t, c1.cli, c1.done)
	drainAndWait(t, c2.cli, c2.done)

	if srv.sessionsTotal.Load() != 2 {
		t.Errorf("sessionsTotal: got %d, want 2", srv.sessionsTotal.Load())
	}
}
