package main

// Tests for the approval REST API surface: RegisterApprovalAPI's bearer-token
// auth wrapper, buildTLSConfig, matchGlob, handleConfig, handleList,
// handleJITPolicy, and postSlack's HMAC request signing.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sudo-logger/internal/policy"
	"sudo-logger/internal/store"
)

// ── matchGlob ─────────────────────────────────────────────────────────────────

func TestMatchGlob(t *testing.T) {
	tests := []struct {
		pattern, s string
		want       bool
	}{
		{"*", "anything", true},
		{"host1", "host1", true},
		{"host1", "host2", false},
		{"host*", "host1", true},
		{"host*", "other", false},
		{"*-prod", "web-prod", true},
		{"*-prod", "web-dev", false},
		{"web-*-prod", "web-eu-prod", true},
		{"web-*-prod", "web-eu-dev", false},
	}
	for _, tt := range tests {
		if got := matchGlob(tt.pattern, tt.s); got != tt.want {
			t.Errorf("matchGlob(%q, %q) = %v, want %v", tt.pattern, tt.s, got, tt.want)
		}
	}
}

// ── RegisterApprovalAPI bearer-token auth ────────────────────────────────────

func TestRegisterApprovalAPI_ValidToken(t *testing.T) {
	m := &ApprovalManager{backend: &listingApprovalStore{}}
	mux := http.NewServeMux()
	m.RegisterApprovalAPI(mux, "s3cr3t-token")

	req := httptest.NewRequest(http.MethodGet, "/api/approvals", nil)
	req.Header.Set("Authorization", "Bearer s3cr3t-token")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("valid token: got %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
}

func TestRegisterApprovalAPI_MissingToken(t *testing.T) {
	m := &ApprovalManager{backend: &mockApprovalStore{}}
	mux := http.NewServeMux()
	m.RegisterApprovalAPI(mux, "s3cr3t-token")

	req := httptest.NewRequest(http.MethodGet, "/api/approvals", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("missing token: got %d, want 401", rr.Code)
	}
}

func TestRegisterApprovalAPI_WrongToken(t *testing.T) {
	m := &ApprovalManager{backend: &mockApprovalStore{}}
	mux := http.NewServeMux()
	m.RegisterApprovalAPI(mux, "s3cr3t-token")

	req := httptest.NewRequest(http.MethodGet, "/api/approvals", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("wrong token: got %d, want 401", rr.Code)
	}
}

func TestRegisterApprovalAPI_EmptyTokenDisablesAPI(t *testing.T) {
	m := &ApprovalManager{backend: &mockApprovalStore{}}
	mux := http.NewServeMux()
	m.RegisterApprovalAPI(mux, "")

	// Only the callback endpoint should be registered; /api/approvals must
	// 404 since it was never mounted.
	req := httptest.NewRequest(http.MethodGet, "/api/approvals", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("empty token: /api/approvals got %d, want 404 (not registered)", rr.Code)
	}
}

// ── buildTLSConfig ────────────────────────────────────────────────────────────

// writeTestCertFiles generates a self-signed ECDSA cert/key pair and writes
// PEM-encoded cert, key, and CA (the same cert, reused as its own CA for
// test purposes) files into a fresh temp dir.
func writeTestCertFiles(t *testing.T) (certPath, keyPath, caPath string) {
	t.Helper()
	dir := t.TempDir()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
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
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}

	certPath = filepath.Join(dir, "server.crt")
	keyPath = filepath.Join(dir, "server.key")
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

func withTLSFlags(t *testing.T, cert, key, ca string) {
	t.Helper()
	origCert, origKey, origCA := *flagCert, *flagKey, *flagCA
	*flagCert, *flagKey, *flagCA = cert, key, ca
	t.Cleanup(func() { *flagCert, *flagKey, *flagCA = origCert, origKey, origCA })
}

func TestBuildTLSConfig_Valid(t *testing.T) {
	cert, key, ca := writeTestCertFiles(t)
	withTLSFlags(t, cert, key, ca)

	cfg, err := buildTLSConfig()
	if err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}
	if len(cfg.Certificates) != 1 {
		t.Errorf("Certificates = %d, want 1", len(cfg.Certificates))
	}
	if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("ClientAuth = %v, want RequireAndVerifyClientCert", cfg.ClientAuth)
	}
	if cfg.ClientCAs == nil {
		t.Error("ClientCAs pool should be populated")
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion = %v, want TLS 1.3", cfg.MinVersion)
	}
}

func TestBuildTLSConfig_MissingCertFile(t *testing.T) {
	_, key, ca := writeTestCertFiles(t)
	withTLSFlags(t, "/nonexistent/server.crt", key, ca)

	if _, err := buildTLSConfig(); err == nil {
		t.Error("expected an error for a missing cert file")
	}
}

func TestBuildTLSConfig_MissingCAFile(t *testing.T) {
	cert, key, _ := writeTestCertFiles(t)
	withTLSFlags(t, cert, key, "/nonexistent/ca.crt")

	if _, err := buildTLSConfig(); err == nil {
		t.Error("expected an error for a missing CA file")
	}
}

func TestBuildTLSConfig_InvalidCAPEM(t *testing.T) {
	cert, key, _ := writeTestCertFiles(t)
	dir := t.TempDir()
	badCA := filepath.Join(dir, "bad-ca.crt")
	if err := os.WriteFile(badCA, []byte("not a pem file"), 0o600); err != nil {
		t.Fatalf("write bad CA: %v", err)
	}
	withTLSFlags(t, cert, key, badCA)

	if _, err := buildTLSConfig(); err == nil {
		t.Error("expected an error for an invalid CA PEM file")
	}
}

// ── handleConfig ──────────────────────────────────────────────────────────────

func TestApprovalHandleConfig_GetDefault(t *testing.T) {
	m := &ApprovalManager{backend: &mockApprovalStore{}}
	req := httptest.NewRequest(http.MethodGet, "/api/approval-config", nil)
	rr := httptest.NewRecorder()
	m.handleConfig(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("GET config: got %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if _, ok := resp["config"]; !ok {
		t.Error("response missing 'config' key")
	}
}

func TestApprovalHandleConfig_PutValid(t *testing.T) {
	backend := &mockApprovalStore{}
	m := &ApprovalManager{backend: backend}

	body := `{"config":{"enabled":true,"default_window":"15m","pending_ttl":"1h","exempt":[],"notifications":{}}}`
	req := httptest.NewRequest(http.MethodPut, "/api/approval-config", strings.NewReader(body))
	rr := httptest.NewRecorder()
	m.handleConfig(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("PUT valid config: got %d, want 204; body: %s", rr.Code, rr.Body.String())
	}
	if backend.configs["approval-policy.yaml"] == "" {
		t.Error("PUT did not persist the policy via SetConfig")
	}
}

func TestApprovalHandleConfig_PutInvalidDuration(t *testing.T) {
	m := &ApprovalManager{backend: &mockApprovalStore{}}
	body := `{"config":{"enabled":true,"default_window":"not-a-duration"}}`
	req := httptest.NewRequest(http.MethodPut, "/api/approval-config", strings.NewReader(body))
	rr := httptest.NewRecorder()
	m.handleConfig(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("invalid duration: got %d, want 400", rr.Code)
	}
}

func TestApprovalHandleConfig_WebhookSecretMaskedOnGet(t *testing.T) {
	m := &ApprovalManager{backend: &mockApprovalStore{}}
	m.mu.Lock()
	m.policy.Notifications.WebhookSecret = "real-secret" // pragma: allowlist secret
	m.mu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/api/approval-config", nil)
	rr := httptest.NewRecorder()
	m.handleConfig(rr, req)

	if strings.Contains(rr.Body.String(), "real-secret") {
		t.Error("GET /api/approval-config leaked the real webhook secret")
	}
	if !strings.Contains(rr.Body.String(), "***") {
		t.Error("GET /api/approval-config should return the masked sentinel for a configured secret")
	}
}

func TestApprovalHandleConfig_WrongMethod(t *testing.T) {
	m := &ApprovalManager{backend: &mockApprovalStore{}}
	req := httptest.NewRequest(http.MethodDelete, "/api/approval-config", nil)
	rr := httptest.NewRecorder()
	m.handleConfig(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("DELETE: got %d, want 405", rr.Code)
	}
}

// ── handleList ────────────────────────────────────────────────────────────────

type listingApprovalStore struct {
	mockApprovalStore
	pending []store.ApprovalRequest
}

func (s *listingApprovalStore) ListApprovalRequests(_ context.Context) ([]store.ApprovalRequest, error) {
	return s.pending, nil
}

func TestApprovalHandleList(t *testing.T) {
	backend := &listingApprovalStore{pending: []store.ApprovalRequest{
		{ID: "ABC123", User: "alice", Host: "host1"},
	}}
	m := &ApprovalManager{backend: backend}

	req := httptest.NewRequest(http.MethodGet, "/api/approvals", nil)
	rr := httptest.NewRecorder()
	m.handleList(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("handleList: got %d, want 200", rr.Code)
	}
	var out []map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("handleList returned %d entries, want 1", len(out))
	}
	if out[0]["status"] != "pending" {
		t.Errorf("entry status = %v, want %q", out[0]["status"], "pending")
	}
	if out[0]["id"] != "ABC123" {
		t.Errorf("entry id = %v, want %q", out[0]["id"], "ABC123")
	}
}

// ── handleJITPolicy ───────────────────────────────────────────────────────────

func TestApprovalHandleJITPolicy_GetDefault(t *testing.T) {
	m := &ApprovalManager{backend: &mockApprovalStore{}}
	req := httptest.NewRequest(http.MethodGet, "/api/jit-policy", nil)
	rr := httptest.NewRecorder()
	m.handleJITPolicy(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("GET jit-policy: got %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
}

func TestApprovalHandleJITPolicy_PutValid(t *testing.T) {
	m := &ApprovalManager{backend: &mockApprovalStore{}}
	p := policy.DefaultPolicy()
	body, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal policy: %v", err)
	}
	req := httptest.NewRequest(http.MethodPut, "/api/jit-policy", strings.NewReader(string(body)))
	rr := httptest.NewRecorder()
	m.handleJITPolicy(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("PUT valid policy: got %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
}

func TestApprovalHandleJITPolicy_PutInvalidAction(t *testing.T) {
	m := &ApprovalManager{backend: &mockApprovalStore{}}
	body := `{"default_action":"bogus","rules":[{"id":"r1","action":"not-a-real-action"}]}`
	req := httptest.NewRequest(http.MethodPut, "/api/jit-policy", strings.NewReader(body))
	rr := httptest.NewRecorder()
	m.handleJITPolicy(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("invalid policy: got %d, want 400; body: %s", rr.Code, rr.Body.String())
	}
}

// ── postSlack HMAC signing ────────────────────────────────────────────────────

func TestPostSlack_SignsWithHMAC(t *testing.T) {
	secret := "webhook-secret-value" // pragma: allowlist secret
	var gotBody []byte
	var gotSig string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		gotSig = r.Header.Get("X-Sudo-Logger-Signature")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	m := &ApprovalManager{backend: &mockApprovalStore{}}
	cfg := approvalNotifyCfg{WebhookURL: srv.URL, WebhookSecret: secret}
	m.postSlack(cfg, "", "test message", "#00ff00", nil, "", nil)

	if gotSig == "" {
		t.Fatal("webhook request did not include X-Sudo-Logger-Signature")
	}
	wantMAC := hmac.New(sha256.New, []byte(secret))
	wantMAC.Write(gotBody)
	want := "sha256=" + hex.EncodeToString(wantMAC.Sum(nil))
	if gotSig != want {
		t.Errorf("signature = %q, want %q (recomputed from received body)", gotSig, want)
	}
}

func TestPostSlack_NoWebhookURLIsNoop(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	defer srv.Close()

	m := &ApprovalManager{backend: &mockApprovalStore{}}
	m.postSlack(approvalNotifyCfg{}, "", "text", "#000000", nil, "", nil)

	if called {
		t.Error("postSlack should not make a request when WebhookURL is empty")
	}
}
