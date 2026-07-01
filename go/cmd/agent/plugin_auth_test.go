package main

// Tests for the plugin socket's access control (isSudoConn) and the
// divergence-alert send path (trySendDivergenceAlert / sendDivergenceAlert).

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"testing"
	"time"

	"sudo-logger/internal/protocol"
)

// ── isSudoConn ────────────────────────────────────────────────────────────────

func TestIsSudoConn_InsecureTestBypass(t *testing.T) {
	t.Setenv("SUDO_LOGGER_INSECURE_TEST", "1")
	// Any connection (even a non-Unix one) is accepted when the bypass is set.
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	if !isSudoConn(c1) {
		t.Error("isSudoConn should return true when SUDO_LOGGER_INSECURE_TEST=1")
	}
}

func TestIsSudoConn_NonUnixConnRejected(t *testing.T) {
	// Without the bypass, a non-*net.UnixConn (e.g. net.Pipe) can never
	// satisfy the type assertion and must be rejected.
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	if isSudoConn(c1) {
		t.Error("isSudoConn should reject a non-Unix connection")
	}
}

func TestIsSudoConn_RealUnixSocketNonRootPeer(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root — isSudoConn would legitimately return true")
	}
	dir := t.TempDir()
	sockPath := dir + "/test.sock"
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	acceptCh := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			acceptCh <- c
		}
	}()

	client, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	server := <-acceptCh
	defer server.Close()

	// The connecting peer is this same non-root test process — isSudoConn
	// must reject it since SO_PEERCRED UID != 0.
	if isSudoConn(server) {
		t.Error("isSudoConn should reject a peer connection from a non-root UID")
	}
}

// ── trySendDivergenceAlert / sendDivergenceAlert ─────────────────────────────

// minimalTLSDivergenceServer accepts one TLS connection, reads a single
// protocol message, and reports what it received on the returned channel.
// The returned CA pool trusts exactly the cert this server presents.
func minimalTLSDivergenceServer(t *testing.T) (addr string, caPool *x509.CertPool, received chan uint8, cleanup func()) {
	t.Helper()
	tlsCert, pool := generateTestCert(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{tlsCert}})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	msgCh := make(chan uint8, 1)
	stop := make(chan struct{})
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		r := bufio.NewReader(conn)
		mType, plen, err := protocol.ReadHeader(r)
		if err != nil {
			return
		}
		if _, err := protocol.ReadPayload(r, plen); err != nil {
			return
		}
		select {
		case msgCh <- mType:
		case <-stop:
		}
	}()
	return ln.Addr().String(), pool, msgCh, func() {
		close(stop)
		ln.Close()
	}
}

func TestTrySendDivergenceAlert_Success(t *testing.T) {
	addr, caPool, msgCh, cleanup := minimalTLSDivergenceServer(t)
	defer cleanup()

	origServer, origTLS := cfg.Server, tlsCfg
	cfg.Server = addr
	tlsCfg = testClientTLS(caPool)
	t.Cleanup(func() { cfg.Server, tlsCfg = origServer, origTLS })

	if err := trySendDivergenceAlert([]byte(`{"user":"alice"}`)); err != nil {
		t.Fatalf("trySendDivergenceAlert: %v", err)
	}

	select {
	case mType := <-msgCh:
		if mType != protocol.MsgDivergenceAlert {
			t.Errorf("server received message type %d, want %d (MsgDivergenceAlert)", mType, protocol.MsgDivergenceAlert)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for server to receive the message")
	}
}

func TestTrySendDivergenceAlert_DialFailure(t *testing.T) {
	_, caPool := generateTestCert(t)
	origServer, origTLS := cfg.Server, tlsCfg
	// Port 1 on loopback is reliably closed/unroutable — fails fast.
	cfg.Server = "127.0.0.1:1"
	tlsCfg = testClientTLS(caPool)
	t.Cleanup(func() { cfg.Server, tlsCfg = origServer, origTLS })

	if err := trySendDivergenceAlert([]byte(`{}`)); err == nil {
		t.Error("expected an error when the server is unreachable")
	}
}

func TestSendDivergenceAlert_SucceedsOnFirstAttempt(t *testing.T) {
	// Only exercises the immediate-success path — sendDivergenceAlert's
	// retry loop uses real time.Sleep with a 5s+ initial delay, which would
	// make a failure-path test far too slow to run as a unit test.
	addr, caPool, msgCh, cleanup := minimalTLSDivergenceServer(t)
	defer cleanup()

	origServer, origTLS := cfg.Server, tlsCfg
	cfg.Server = addr
	tlsCfg = testClientTLS(caPool)
	t.Cleanup(func() { cfg.Server, tlsCfg = origServer, origTLS })

	done := make(chan struct{})
	go func() {
		sendDivergenceAlert("alice", "host1", "bash", time.Now())
		close(done)
	}()

	select {
	case <-msgCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for server to receive the divergence alert")
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("sendDivergenceAlert did not return promptly after a successful send")
	}
}
