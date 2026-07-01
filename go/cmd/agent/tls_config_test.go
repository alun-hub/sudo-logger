package main

// Tests for tls.go: buildTLSConfig and loadEd25519PubKey. Mirrors the
// already-tested cmd/server loadEd25519PrivKey test shape.

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ── buildTLSConfig ────────────────────────────────────────────────────────────

func writeAgentCertFiles(t *testing.T) (certPath, keyPath, caPath string) {
	t.Helper()
	dir := t.TempDir()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-agent"},
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
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}

	certPath = filepath.Join(dir, "client.crt")
	keyPath = filepath.Join(dir, "client.key")
	caPath = filepath.Join(dir, "ca.crt")

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	if err := os.WriteFile(caPath, certPEM, 0o600); err != nil {
		t.Fatalf("write ca: %v", err)
	}
	return certPath, keyPath, caPath
}

func TestBuildTLSConfig_Valid(t *testing.T) {
	cert, key, ca := writeAgentCertFiles(t)
	got, err := buildTLSConfig(agentConfig{Cert: cert, Key: key, CA: ca})
	if err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}
	if len(got.Certificates) != 1 {
		t.Errorf("Certificates = %d, want 1", len(got.Certificates))
	}
	if got.RootCAs == nil {
		t.Error("RootCAs pool should be populated")
	}
	if got.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion = %v, want TLS 1.3", got.MinVersion)
	}
}

func TestBuildTLSConfig_MissingCert(t *testing.T) {
	_, key, ca := writeAgentCertFiles(t)
	if _, err := buildTLSConfig(agentConfig{Cert: "/nonexistent/client.crt", Key: key, CA: ca}); err == nil {
		t.Error("expected an error for a missing cert file")
	}
}

func TestBuildTLSConfig_MissingCA(t *testing.T) {
	cert, key, _ := writeAgentCertFiles(t)
	if _, err := buildTLSConfig(agentConfig{Cert: cert, Key: key, CA: "/nonexistent/ca.crt"}); err == nil {
		t.Error("expected an error for a missing CA file")
	}
}

func TestBuildTLSConfig_InvalidCAPEM(t *testing.T) {
	cert, key, _ := writeAgentCertFiles(t)
	dir := t.TempDir()
	badCA := filepath.Join(dir, "bad-ca.crt")
	if err := os.WriteFile(badCA, []byte("not a pem file"), 0o600); err != nil {
		t.Fatalf("write bad CA: %v", err)
	}
	if _, err := buildTLSConfig(agentConfig{Cert: cert, Key: key, CA: badCA}); err == nil {
		t.Error("expected an error for an invalid CA PEM file")
	}
}

// ── loadEd25519PubKey ─────────────────────────────────────────────────────────

func writeEd25519PubPEM(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal pubkey: %v", err)
	}
	path := filepath.Join(t.TempDir(), "verify.pem")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create file: %v", err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: "PUBLIC KEY", Bytes: der}); err != nil {
		t.Fatalf("pem encode: %v", err)
	}
	return path
}

func TestLoadEd25519PubKeyValid(t *testing.T) {
	path := writeEd25519PubPEM(t)
	key, err := loadEd25519PubKey(path)
	if err != nil {
		t.Fatalf("loadEd25519PubKey: %v", err)
	}
	if len(key) == 0 {
		t.Error("returned empty key")
	}
}

func TestLoadEd25519PubKeyMissingFile(t *testing.T) {
	_, err := loadEd25519PubKey(filepath.Join(t.TempDir(), "nonexistent.pem"))
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestLoadEd25519PubKeyNoPEM(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.pem")
	if err := os.WriteFile(path, []byte("not pem data\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := loadEd25519PubKey(path); err == nil {
		t.Error("expected error for non-PEM file")
	}
}

func TestLoadEd25519PubKeyWrongKeyType(t *testing.T) {
	// Write an ECDSA public key — not ed25519.
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ecdsa: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	path := filepath.Join(t.TempDir(), "ecdsa-pub.pem")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := pem.Encode(f, &pem.Block{Type: "PUBLIC KEY", Bytes: der}); err != nil {
		t.Fatalf("pem encode: %v", err)
	}
	f.Close()

	if _, err := loadEd25519PubKey(path); err == nil {
		t.Error("expected error for non-ed25519 key")
	}
}
