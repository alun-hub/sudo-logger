package main

// Tests for handleGetSiemConfig and sendSiemEvent (handlers_admin_siem.go).
// validateTLSPaths and the cert-upload handler already have dedicated tests
// in handlers_siem_cert_test.go.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandleGetSiemConfig_Empty(t *testing.T) {
	initTestStore(t)
	rr := httptest.NewRecorder()
	handleGetSiemConfig(rr, httptest.NewRequest(http.MethodGet, "/api/siem-config", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
	}
	var got struct {
		Config struct {
			Enabled bool `json:"enabled"`
		} `json:"config"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Config.Enabled {
		t.Error("handleGetSiemConfig (unconfigured) should default to disabled")
	}
}

func TestHandleGetSiemConfig_AfterSetConfig(t *testing.T) {
	initTestStore(t)
	yaml := "enabled: true\ntransport: https\nendpoint: https://siem.example/ingest\n"
	if err := sessionStore.SetConfig(t.Context(), "siem.yaml", yaml); err != nil {
		t.Fatalf("SetConfig: %v", err)
	}

	rr := httptest.NewRecorder()
	handleGetSiemConfig(rr, httptest.NewRequest(http.MethodGet, "/api/siem-config", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
	}
	var got struct {
		Config struct {
			Enabled bool `json:"enabled"`
		} `json:"config"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !got.Config.Enabled {
		t.Error("handleGetSiemConfig should reflect the persisted config, not siem.Get()'s cached state")
	}
}

// ── sendSiemEvent ────────────────────────────────────────────────────────────
// siem.Send() no-ops when SIEM forwarding is disabled (the default in these
// tests), so these exercise sendSiemEvent's own session-lookup logic safely,
// without any real network call.

func TestSendSiemEvent_MissingSession(t *testing.T) {
	initTestStore(t)
	// Must not panic when the tsid can't be found post-completion.
	sendSiemEvent("nobody/nowhere_20260101-000000")
}

func TestSendSiemEvent_KnownSession(t *testing.T) {
	dir := seedSessionStore(t)
	seedHTTPSession(t, dir, "alice", "host1", "ls")
	// Must not panic when the session is found; siem.Send is a no-op here
	// since SIEM forwarding defaults to disabled.
	sendSiemEvent("alice/host1_20260415-120000")
}
