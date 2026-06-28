package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"math/big"
	"net"
	"os"
	osSignal "os/signal"
	"syscall"
	"testing"
	"time"

	"sudo-logger/internal/protocol"
)

// generateTestCert creates a self-signed certificate for the mock server.
func generateTestCert(t *testing.T) tls.Certificate {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:         true,
		BasicConstraintsValid: true,
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}
}

func setupMockServer(t *testing.T) (net.Addr, ed25519.PrivateKey, func()) {
	cert := generateTestCert(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}

	_, privSign, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate signing key: %v", err)
	}

	stop := make(chan struct{})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-stop:
					return
				default:
					continue
				}
			}
			go func(c net.Conn) {
				defer c.Close()
				r := bufio.NewReader(c)
				w := bufio.NewWriter(c)

				// Basic mock server logic: expect SESSION_START, send SERVER_READY
				mType, plen, err := protocol.ReadHeader(r)
				if err != nil {
					return
				}
				payload, _ := protocol.ReadPayload(r, plen)
				if mType == protocol.MsgSessionStart {
					var start protocol.SessionStart
					json.Unmarshal(payload, &start)

					// If user is "blocked", send MsgSessionDenied
					if start.User == "blocked" {
						protocol.WriteMessage(w, protocol.MsgSessionDenied, []byte("policy-block"))
						return
					}

					protocol.WriteMessage(w, protocol.MsgServerReady, nil)

					// Now listen for chunks and send ACKs
					for {
						mType, plen, err = protocol.ReadHeader(r)
						if err != nil {
							return
						}
						payload, _ = protocol.ReadPayload(r, plen)
						switch mType {
						case protocol.MsgChunk:
							chunk, _ := protocol.ParseChunk(payload)
							ts := time.Now().UnixNano()
							msg := protocol.AckSignMessage(start.SessionID, chunk.Seq, ts)
							sig := ed25519.Sign(privSign, msg)
							var sigArr [64]byte
							copy(sigArr[:], sig)
							ack := protocol.EncodeAck(chunk.Seq, ts, sigArr)
							protocol.WriteMessage(w, protocol.MsgAck, ack)
						case protocol.MsgSessionEnd:
							return
						case protocol.MsgHeartbeat:
							protocol.WriteMessage(w, protocol.MsgHeartbeatAck, nil)
						}
					}
				}
			}(conn)
		}
	}()

	return ln.Addr(), privSign, func() {
		close(stop)
		ln.Close()
	}
}

func TestHandlePluginConn_Success(t *testing.T) {
	addr, privSign, cleanup := setupMockServer(t)
	defer cleanup()

	cfg = defaultConfig()
	cfg.Server = addr.String()
	cfg.Ebpf = false // Disable eBPF for this test
	cfg.FreezeTimeout = 0
	cfg.IdleTimeout = 0
	cgroupBase = "" // Disable cgroups
	tlsCfg = &tls.Config{InsecureSkipVerify: true}
	verifyKey = privSign.Public().(ed25519.PublicKey)
	div = newDivergenceTracker("test-host", nil)

	// Use net.Pipe to simulate the plugin socket
	pluginSide, agentSide := net.Pipe()

	done := make(chan struct{})
	go func() {
		handlePluginConn(agentSide)
		close(done)
	}()

	pr := bufio.NewReader(pluginSide)
	pw := bufio.NewWriter(pluginSide)

	// 1. Send SESSION_START
	sessionID := "test-session-success"
	start := protocol.SessionStart{
		SessionID: sessionID,
		User:      "alice",
		Host:      "test-host",
		Pid:       os.Getpid(),
		Command:   "ls -l",
		Ts:        time.Now().Unix(),
	}
	startB, _ := json.Marshal(start)
	protocol.WriteMessage(pw, protocol.MsgSessionStart, startB)
	pw.Flush()

	// 2. Expect MsgSessionReady
	mType, _, err := protocol.ReadHeader(pr)
	if err != nil || mType != protocol.MsgSessionReady {
		t.Fatalf("Expected MsgSessionReady (0x12), got 0x%02x: %v", mType, err)
	}

	// 3. Send a Chunk
	chunkData := []byte("hello world")
	chunkPayload := protocol.EncodeChunk(1, time.Now().UnixNano(), protocol.StreamTtyOut, chunkData)
	protocol.WriteMessage(pw, protocol.MsgChunk, chunkPayload)
	pw.Flush()

	// 4. Expect MsgAckResponse (after sending MsgAckQuery)
	protocol.WriteMessage(pw, protocol.MsgAckQuery, nil)
	pw.Flush()
	mType, _, err = protocol.ReadHeader(pr)
	if err != nil || mType != protocol.MsgAckResponse {
		t.Fatalf("Expected MsgAckResponse (0x14), got 0x%02x: %v", mType, err)
	}

	// 5. Send SESSION_END
	endPayload := make([]byte, 12)
	binary.BigEndian.PutUint64(endPayload[0:], 1)
	binary.BigEndian.PutUint32(endPayload[8:], 0)
	protocol.WriteMessage(pw, protocol.MsgSessionEnd, endPayload)
	pw.Flush()

	// Close plugin side to signal EOF
	pluginSide.Close()

	// Wait for agent to finish
	select {
	case <-done:
	case <-time.After(5 * time.Second): // handlePluginConn has a 2s sleep at the end
		t.Fatal("Timeout waiting for handlePluginConn to exit")
	}
	time.Sleep(100 * time.Millisecond) // let deferred goroutines from handlePluginConn settle
}

func TestHandlePluginConn_Denied(t *testing.T) {
	addr, _, cleanup := setupMockServer(t)
	defer cleanup()

	cfg = defaultConfig()
	cfg.Server = addr.String()
	cfg.Ebpf = false
	cfg.FreezeTimeout = 0
	cfg.IdleTimeout = 0
	cgroupBase = ""
	tlsCfg = &tls.Config{InsecureSkipVerify: true}
	div = newDivergenceTracker("test-host", nil)

	pluginSide, agentSide := net.Pipe()

	done := make(chan struct{})
	go func() {
		handlePluginConn(agentSide)
		close(done)
	}()

	pr := bufio.NewReader(pluginSide)
	pw := bufio.NewWriter(pluginSide)

	start := protocol.SessionStart{
		SessionID: "blocked-session",
		User:      "blocked", // Trigger denial in mock server
		Host:      "test-host",
		Pid:       os.Getpid(),
		Command:   "ls -l",
		Ts:        time.Now().Unix(),
	}
	startB, _ := json.Marshal(start)
	protocol.WriteMessage(pw, protocol.MsgSessionStart, startB)
	pw.Flush()

	mType, _, err := protocol.ReadHeader(pr)
	if err != nil || mType != protocol.MsgSessionDenied {
		t.Fatalf("Expected MsgSessionDenied (0x11), got 0x%02x: %v", mType, err)
	}

	pluginSide.Close()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Timeout waiting for handlePluginConn to exit")
	}
	time.Sleep(100 * time.Millisecond) // let deferred goroutines from handlePluginConn settle
}

func TestHandlePluginConn_IdleTimeout(t *testing.T) {
	addr, _, cleanup := setupMockServer(t)
	defer cleanup()

	// Mock global state
	origCfg := cfg
	origTlsCfg := tlsCfg
	origCgroupBase := cgroupBase
	defer func() {
		cfg = origCfg
		tlsCfg = origTlsCfg
		cgroupBase = origCgroupBase
	}()

	cfg = defaultConfig()
	cfg.Server = addr.String()
	cfg.Ebpf = false
	cfg.FreezeTimeout = 0
	cfg.IdleTimeout = 100 * time.Millisecond // Short timeout for testing
	cgroupBase = ""
	tlsCfg = &tls.Config{InsecureSkipVerify: true}
	div = newDivergenceTracker("test-host", nil)

	pluginSide, agentSide := net.Pipe()

	done := make(chan struct{})
	go func() {
		handlePluginConn(agentSide)
		close(done)
	}()

	pr := bufio.NewReader(pluginSide)
	pw := bufio.NewWriter(pluginSide)

	// Ignore SIGHUP so we don't kill the test process itself
	osSignal.Ignore(syscall.SIGHUP)
	defer osSignal.Reset(syscall.SIGHUP)

	start := protocol.SessionStart{
		SessionID: "idle-session",
		User:      "alice",
		Host:      "test-host",
		Pid:       os.Getpid(),
		Command:   "ls -l",
		Ts:        time.Now().Unix(),
	}
	startB, _ := json.Marshal(start)
	protocol.WriteMessage(pw, protocol.MsgSessionStart, startB)
	pw.Flush()

	// Expect MsgSessionReady
	protocol.ReadHeader(pr)

	// Now wait for idle timeout. The agent should close the connection.
	select {
	case <-done:
		// Success: connection closed by agent due to idle timeout
	case <-time.After(5 * time.Second):
		t.Fatal("Timeout: agent did not close idle session")
	}
}
