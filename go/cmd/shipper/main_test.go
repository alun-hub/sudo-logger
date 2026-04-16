package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"testing"

	"sudo-logger/internal/protocol"
)

// ── truncate ──────────────────────────────────────────────────────────────────

func TestTruncate(t *testing.T) {
	tests := []struct {
		s    string
		n    int
		want string
	}{
		{"hello", 10, "hello"},
		{"hello", 5, "hello"},
		{"hello world", 5, "hello…"},
		{"", 5, ""},
		{"abc", 0, "…"},
	}
	for _, tc := range tests {
		got := truncate(tc.s, tc.n)
		if got != tc.want {
			t.Errorf("truncate(%q, %d) = %q, want %q", tc.s, tc.n, got, tc.want)
		}
	}
}

// ── loadEd25519PubKey ─────────────────────────────────────────────────────────

func TestLoadEd25519PubKey(t *testing.T) {
	pub, _, err := generateTestKeyPair(t)
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}

	// Marshal public key to PKIX PEM
	pkix, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	f, err := os.CreateTemp(t.TempDir(), "ack-verify-*.key")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	if err := pem.Encode(f, &pem.Block{Type: "PUBLIC KEY", Bytes: pkix}); err != nil {
		t.Fatalf("pem encode: %v", err)
	}
	f.Close()

	got, err := loadEd25519PubKey(f.Name())
	if err != nil {
		t.Fatalf("loadEd25519PubKey: %v", err)
	}
	if !got.Equal(pub) {
		t.Error("loaded key does not match original")
	}
}

func TestLoadEd25519PubKey_MissingFile(t *testing.T) {
	_, err := loadEd25519PubKey("/nonexistent/path/key.pem")
	if err == nil {
		t.Error("expected error for missing file, got nil")
	}
}

func TestLoadEd25519PubKey_NotEd25519(t *testing.T) {
	// Write a PEM block with garbage bytes so ParsePKIXPublicKey fails
	f, err := os.CreateTemp(t.TempDir(), "bad-key-*.pem")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	pem.Encode(f, &pem.Block{Type: "PUBLIC KEY", Bytes: []byte("notakey")}) //nolint:errcheck
	f.Close()

	_, err = loadEd25519PubKey(f.Name())
	if err == nil {
		t.Error("expected error for invalid key bytes, got nil")
	}
}

// ── verifyAckSig ─────────────────────────────────────────────────────────────

func TestVerifyAckSig_Valid(t *testing.T) {
	pub, priv, err := generateTestKeyPair(t)
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}
	verifyKey = pub

	sessionID := "testuser/host_20240101-120000"
	ack := buildSignedAck(t, priv, sessionID, 42, 1234567890)

	if !verifyAckSig(ack, sessionID) {
		t.Error("valid ACK was rejected")
	}
}

func TestVerifyAckSig_WrongSessionID(t *testing.T) {
	pub, priv, err := generateTestKeyPair(t)
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}
	verifyKey = pub

	// ACK signed for session A, verified against session B
	ack := buildSignedAck(t, priv, "session-A", 1, 100)
	if verifyAckSig(ack, "session-B") {
		t.Error("ACK signed for session-A should not verify for session-B")
	}
}

func TestVerifyAckSig_WrongSeq(t *testing.T) {
	pub, priv, err := generateTestKeyPair(t)
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}
	verifyKey = pub

	sessionID := "testuser/host_20240101-120000"
	ack := buildSignedAck(t, priv, sessionID, 7, 100)

	// Tamper with the sequence number
	ack.Seq = 8
	if verifyAckSig(ack, sessionID) {
		t.Error("ACK with tampered seq should not verify")
	}
}

func TestVerifyAckSig_ForgedSignature(t *testing.T) {
	pub, _, err := generateTestKeyPair(t)
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}
	verifyKey = pub

	// Sign with a *different* private key
	_, otherPriv, err := generateTestKeyPair(t)
	if err != nil {
		t.Fatalf("generate second keypair: %v", err)
	}

	sessionID := "testuser/host_20240101-120000"
	ack := buildSignedAck(t, otherPriv, sessionID, 1, 100)
	if verifyAckSig(ack, sessionID) {
		t.Error("ACK signed with wrong key should not verify")
	}
}

// ── registerCg / unregisterCg ─────────────────────────────────────────────────

func TestRegisterUnregisterCg_Nil(t *testing.T) {
	// Neither function should panic on nil
	registerCg(nil)
	unregisterCg(nil)
}

func TestRegisterUnregisterCg(t *testing.T) {
	// Save and restore global state
	orig := activeCgs
	activeCgs = nil
	t.Cleanup(func() { activeCgs = orig })

	cg1 := &cgroupSession{path: "/fake/1"}
	cg2 := &cgroupSession{path: "/fake/2"}

	registerCg(cg1)
	registerCg(cg2)

	activeCgsMu.Lock()
	if len(activeCgs) != 2 {
		activeCgsMu.Unlock()
		t.Fatalf("expected 2 active cgroups, got %d", len(activeCgs))
	}
	activeCgsMu.Unlock()

	unregisterCg(cg1)

	activeCgsMu.Lock()
	if len(activeCgs) != 1 || activeCgs[0] != cg2 {
		activeCgsMu.Unlock()
		t.Errorf("expected only cg2 to remain after unregistering cg1")
		return
	}
	activeCgsMu.Unlock()

	unregisterCg(cg2)

	activeCgsMu.Lock()
	if len(activeCgs) != 0 {
		activeCgsMu.Unlock()
		t.Errorf("expected empty active cgroups, got %d", len(activeCgs))
		return
	}
	activeCgsMu.Unlock()
}

func TestUnregisterCg_NotRegistered(t *testing.T) {
	orig := activeCgs
	activeCgs = nil
	t.Cleanup(func() { activeCgs = orig })

	cg := &cgroupSession{path: "/fake/x"}
	registerCg(cg)

	// Unregister a cg that was never registered — should not panic or corrupt slice
	other := &cgroupSession{path: "/fake/other"}
	unregisterCg(other)

	activeCgsMu.Lock()
	n := len(activeCgs)
	activeCgsMu.Unlock()
	if n != 1 {
		t.Errorf("expected 1 active cgroup after spurious unregister, got %d", n)
	}
}

// ── validCgroupName ───────────────────────────────────────────────────────────

func TestValidCgroupName(t *testing.T) {
	valid := []string{
		"alice",
		"alice_host_20240101-120000",
		"A1.b-c_d",
		"a",
	}
	for _, s := range valid {
		if !validCgroupName.MatchString(s) {
			t.Errorf("expected %q to be valid", s)
		}
	}

	invalid := []string{
		"",
		"../etc/passwd",
		"foo/bar",
		"foo bar",
		"foo\x00bar",
		"foo@bar",
	}
	for _, s := range invalid {
		if validCgroupName.MatchString(s) {
			t.Errorf("expected %q to be invalid", s)
		}
	}
}

// ── isSudoConn ────────────────────────────────────────────────────────────────

// isSudoConn requires a real Unix socket and root credentials to test fully;
// those paths are covered by the system test. Here we verify the defensive
// branch: a non-UnixConn must be rejected without panic.

func TestIsSudoConnNonUnix(t *testing.T) {
	// net.TCPConn is not a *net.UnixConn — must return false.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	done := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		done <- c
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	server := <-done
	defer server.Close()

	if isSudoConn(server) {
		t.Error("isSudoConn returned true for a TCP connection")
	}
}

// ── loadEd25519PubKey ─────────────────────────────────────────────────────────

func writeEd25519PubKeyPEM(t *testing.T, pub ed25519.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	f, err := os.CreateTemp(t.TempDir(), "ed25519-pub-*.pem")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	pem.Encode(f, &pem.Block{Type: "PUBLIC KEY", Bytes: der}) //nolint:errcheck
	f.Close()
	return f.Name()
}

func TestLoadEd25519PubKeyValid(t *testing.T) {
	pub, _, err := generateTestKeyPair(t)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	path := writeEd25519PubKeyPEM(t, pub)
	got, err := loadEd25519PubKey(path)
	if err != nil {
		t.Fatalf("loadEd25519PubKey: %v", err)
	}
	if !got.Equal(pub) {
		t.Error("loaded public key does not match original")
	}
}

func TestLoadEd25519PubKeyMissingFile(t *testing.T) {
	_, err := loadEd25519PubKey(t.TempDir() + "/nonexistent.pem")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestLoadEd25519PubKeyNoPEM(t *testing.T) {
	f, _ := os.CreateTemp(t.TempDir(), "bad-*.pem")
	f.WriteString("not pem\n") //nolint:errcheck
	f.Close()
	_, err := loadEd25519PubKey(f.Name())
	if err == nil {
		t.Error("expected error for non-PEM file")
	}
}

func TestLoadEd25519PubKeyWrongKeyType(t *testing.T) {
	// Write an ECDSA public key — not ed25519.
	ecPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&ecPriv.PublicKey)
	f, _ := os.CreateTemp(t.TempDir(), "ecdsa-pub-*.pem")
	pem.Encode(f, &pem.Block{Type: "PUBLIC KEY", Bytes: der}) //nolint:errcheck
	f.Close()
	_, err := loadEd25519PubKey(f.Name())
	if err == nil {
		t.Error("expected error for non-ed25519 public key")
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func generateTestKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	return pub, priv, err
}

func buildSignedAck(t *testing.T, priv ed25519.PrivateKey, sessionID string, seq uint64, ts int64) *protocol.Ack {
	t.Helper()
	msg := protocol.AckSignMessage(sessionID, seq, ts)
	sig := ed25519.Sign(priv, msg)

	ack := &protocol.Ack{
		Seq:       seq,
		Timestamp: ts,
	}
	copy(ack.Sig[:], sig)
	return ack
}
