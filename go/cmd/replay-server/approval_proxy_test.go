package main

// Tests for proxyToLogServer (go/cmd/replay-server/approval_proxy.go).

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProxyToLogServer_ForwardsAuthAndDecidedBy(t *testing.T) {
	var gotAuth, gotDecidedBy, gotMethod, gotQuery string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotDecidedBy = r.Header.Get("X-Sudo-Logger-Decided-By")
		gotMethod = r.Method
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer backend.Close()

	// Incoming browser request tries to spoof the decided-by header — must
	// not be forwarded; only the trusted decidedBy parameter should be.
	req := httptest.NewRequest(http.MethodPost, "/api/approvals/req-1/decide?foo=bar", nil)
	req.Header.Set("X-Sudo-Logger-Decided-By", "attacker-spoofed")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	proxyToLogServer(rr, req, backend.URL+"/api/approvals/req-1/decide", "shared-token", "real-admin")

	if gotMethod != http.MethodPost {
		t.Errorf("backend saw method = %q, want POST", gotMethod)
	}
	if gotQuery != "foo=bar" {
		t.Errorf("backend saw query = %q, want foo=bar", gotQuery)
	}
	if gotAuth != "Bearer shared-token" {
		t.Errorf("backend saw Authorization = %q, want Bearer shared-token", gotAuth)
	}
	if gotDecidedBy != "real-admin" {
		t.Errorf("backend saw X-Sudo-Logger-Decided-By = %q, want real-admin (not the spoofed value)", gotDecidedBy)
	}
	if rr.Code != http.StatusCreated {
		t.Errorf("proxied status = %d, want 201", rr.Code)
	}
	if rr.Body.String() != `{"ok":true}` {
		t.Errorf("proxied body = %q, want {\"ok\":true}", rr.Body.String())
	}
}

func TestProxyToLogServer_OmitsDecidedByWhenAnonymous(t *testing.T) {
	var sawHeader bool
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawHeader = r.Header.Get("X-Sudo-Logger-Decided-By") != ""
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	req := httptest.NewRequest(http.MethodGet, "/api/approvals", nil)
	rr := httptest.NewRecorder()
	proxyToLogServer(rr, req, backend.URL+"/api/approvals", "", "-")

	if sawHeader {
		t.Error("proxyToLogServer should not set X-Sudo-Logger-Decided-By for the \"-\" (unauthenticated) identity")
	}
}

func TestProxyToLogServer_BadGatewayOnUnreachableTarget(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/approvals", nil)
	rr := httptest.NewRecorder()
	proxyToLogServer(rr, req, "http://127.0.0.1:1/unreachable", "token", "admin")
	if rr.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rr.Code)
	}
}
