package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// testCA generates a self-signed CA and a server certificate/key signed by
// it, with the given SAN, all in memory. Returns PEM-encoded CA cert and a
// tls.Certificate ready to use in an httptest.Server.
func testCA(t *testing.T, serverSAN string) (caPEM []byte, serverCert tls.Certificate) {
	t.Helper()

	caPub, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, caPub, caPriv)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}

	srvPub, srvPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}
	srvTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: serverSAN},
		DNSNames:     []string{serverSAN},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, caCert, srvPub, caPriv)
	if err != nil {
		t.Fatalf("create server cert: %v", err)
	}
	srvCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srvDER})
	srvKeyDER, err := x509.MarshalPKCS8PrivateKey(srvPriv)
	if err != nil {
		t.Fatalf("marshal server key: %v", err)
	}
	srvKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: srvKeyDER})

	serverCert, err = tls.X509KeyPair(srvCertPEM, srvKeyPEM)
	if err != nil {
		t.Fatalf("build tls.Certificate: %v", err)
	}
	return caPEM, serverCert
}

func TestBuildAdminHTTPClient_FailsClosedOnMissingFlags(t *testing.T) {
	if _, err := buildAdminHTTPClient("", "some-name"); err == nil {
		t.Error("empty CA path: want error, got nil")
	}
	if _, err := buildAdminHTTPClient("/some/ca.crt", ""); err == nil {
		t.Error("empty TLS name: want error, got nil")
	}
	if _, err := buildAdminHTTPClient("", ""); err == nil {
		t.Error("both empty: want error, got nil")
	}
}

func TestBuildAdminHTTPClient_FailsOnUnreadableCA(t *testing.T) {
	if _, err := buildAdminHTTPClient("/nonexistent/ca.crt", "some-name"); err == nil {
		t.Error("nonexistent CA file: want error, got nil")
	}
}

func TestBuildAdminHTTPClient_FailsOnInvalidPEM(t *testing.T) {
	dir := t.TempDir()
	badCA := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(badCA, []byte("not a pem file"), 0o600); err != nil {
		t.Fatalf("write bad CA file: %v", err)
	}
	if _, err := buildAdminHTTPClient(badCA, "some-name"); err == nil {
		t.Error("invalid PEM content: want error, got nil")
	}
}

// TestBuildAdminHTTPClient_AcceptsCorrectNameRejectsWrongName is the core
// regression test for H1's TLS-on-admin-API fix: with a real self-signed CA
// and server cert (SAN "gnarg.alun.se"), a client built with the correct
// -logserver-admin-tls-name must succeed, and a client built with the wrong
// name must be rejected -- confirming the ServerName override is actually
// enforced by standard crypto/tls verification, not silently skipped.
func TestBuildAdminHTTPClient_AcceptsCorrectNameRejectsWrongName(t *testing.T) {
	const realSAN = "gnarg.alun.se"
	caPEM, serverCert := testCA(t, realSAN)

	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatalf("write CA file: %v", err)
	}

	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	ts.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}}
	ts.StartTLS()
	defer ts.Close()

	// Correct ServerName: dial the test server's real listen address, but
	// verify against the hostname the cert was actually issued for -- the
	// same SNI-override pattern used against the internal Service DNS name
	// in the real deployment.
	goodClient, err := buildAdminHTTPClient(caPath, realSAN)
	if err != nil {
		t.Fatalf("buildAdminHTTPClient: %v", err)
	}
	resp, err := goodClient.Get(ts.URL)
	if err != nil {
		t.Fatalf("request with correct tls-name failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("got status %d, want 200", resp.StatusCode)
	}

	// Wrong ServerName: same CA (chain verification would pass), but the
	// hostname check must still reject it.
	badClient, err := buildAdminHTTPClient(caPath, "not-the-real-hostname.example.com")
	if err != nil {
		t.Fatalf("buildAdminHTTPClient: %v", err)
	}
	if _, err := badClient.Get(ts.URL); err == nil {
		t.Error("request with wrong tls-name succeeded, want a TLS verification error")
	}
}
