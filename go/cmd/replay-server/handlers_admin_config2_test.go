package main

// Tests for the remaining previously-uncovered handlers in
// handlers_admin_config.go: handleReport, handleGetRules, handleGetRetention,
// handleGetRedactionConfig, handlePutRedactionConfig, handleGetSandbox,
// handlePutSandbox, handleGetSandboxTemplates, handlePutSandboxTemplates,
// handleGetSudoersHosts, handleGetSudoersSnapshots.
//
// buildReport, stripSudoersHeader, extractManagedSudoers, summarizeLineDiff,
// and validateSudoers already have dedicated direct tests elsewhere
// (handlers_report_test.go, handlers_sudoers_test.go) — these tests focus on
// the handler wrapper itself: permission gating, request/response shape, and
// the store round-trip.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"sudo-logger/internal/protocol"
)

// sudoersSnap builds a minimal protocol.SudoersSnapshot for a host, deriving
// SHA256 from the content so it matches what a real agent upload would send.
func sudoersSnap(host, content string) *protocol.SudoersSnapshot {
	sum := sha256.Sum256([]byte(content))
	return &protocol.SudoersSnapshot{
		Host:    host,
		Content: content,
		SHA256:  hex.EncodeToString(sum[:]),
	}
}

func TestHandleReport_Smoke(t *testing.T) {
	initTestStore(t) // bootstrap mode: require() no-ops regardless of context perms
	rr := httptest.NewRecorder()
	handleReport(rr, httptest.NewRequest(http.MethodGet, "/api/report", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
	}
	var got ReportData
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Anomalies == nil || got.PerUser == nil {
		t.Errorf("handleReport response = %+v, want non-nil Anomalies/PerUser slices", got)
	}
}

func TestHandleReport_RejectsNonGet(t *testing.T) {
	initTestStore(t)
	rr := httptest.NewRecorder()
	handleReport(rr, httptest.NewRequest(http.MethodPost, "/api/report", nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rr.Code)
	}
}

func TestHandleGetRules_EmptyThenAfterPut(t *testing.T) {
	initTestStore(t)
	rr := httptest.NewRecorder()
	handleGetRules(rr, httptest.NewRequest(http.MethodGet, "/api/rules", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
	}
	var got struct {
		Rules []Rule `json:"rules"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got.Rules) != 0 {
		t.Errorf("handleGetRules (empty) = %+v, want none", got.Rules)
	}

	putBody := `{"rules":[{"id":"r1","score":10,"reason":"test rule","command":{"contains_any":["visudo"]}}]}`
	rrPut := httptest.NewRecorder()
	handlePutRules(rrPut, httptest.NewRequest(http.MethodPut, "/api/rules", strings.NewReader(putBody)))
	if rrPut.Code != http.StatusOK {
		t.Fatalf("PUT status = %d, body=%s", rrPut.Code, rrPut.Body.String())
	}

	rrGet2 := httptest.NewRecorder()
	handleGetRules(rrGet2, httptest.NewRequest(http.MethodGet, "/api/rules", nil))
	var got2 struct {
		Rules []Rule `json:"rules"`
	}
	if err := json.Unmarshal(rrGet2.Body.Bytes(), &got2); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got2.Rules) != 1 || got2.Rules[0].ID != "r1" {
		t.Errorf("handleGetRules after PUT = %+v, want one r1 rule", got2.Rules)
	}
}

func TestHandleRetention_RoundTrip(t *testing.T) {
	initTestStore(t)
	rr := httptest.NewRecorder()
	handleGetRetention(rr, httptest.NewRequest(http.MethodGet, "/api/retention", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("GET status = %d, body=%s", rr.Code, rr.Body.String())
	}

	putBody := `{"enabled":true,"days":30}`
	rrPut := httptest.NewRecorder()
	handlePutRetention(rrPut, httptest.NewRequest(http.MethodPut, "/api/retention", strings.NewReader(putBody)))
	if rrPut.Code != http.StatusOK {
		t.Fatalf("PUT status = %d, body=%s", rrPut.Code, rrPut.Body.String())
	}

	rrGet2 := httptest.NewRecorder()
	handleGetRetention(rrGet2, httptest.NewRequest(http.MethodGet, "/api/retention", nil))
	var got struct {
		Enabled bool `json:"enabled"`
		Days    int  `json:"days"`
	}
	if err := json.Unmarshal(rrGet2.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !got.Enabled || got.Days != 30 {
		t.Errorf("handleGetRetention after PUT = %+v, want enabled=true days=30", got)
	}
}

func TestHandleRedactionConfig_RoundTrip(t *testing.T) {
	initTestStore(t)
	rr := httptest.NewRecorder()
	handleGetRedactionConfig(rr, httptest.NewRequest(http.MethodGet, "/api/redaction-config", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("GET status = %d, body=%s", rr.Code, rr.Body.String())
	}
	var got struct {
		CustomPatterns []string `json:"custom_patterns"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got.CustomPatterns) != 0 {
		t.Errorf("handleGetRedactionConfig (empty) = %+v, want none", got.CustomPatterns)
	}

	putBody := `{"custom_patterns":["sk-[a-zA-Z0-9]{20,}"]}`
	rrPut := httptest.NewRecorder()
	handlePutRedactionConfig(rrPut, httptest.NewRequest(http.MethodPut, "/api/redaction-config", strings.NewReader(putBody)))
	if rrPut.Code != http.StatusOK {
		t.Fatalf("PUT status = %d, body=%s", rrPut.Code, rrPut.Body.String())
	}

	rrGet2 := httptest.NewRecorder()
	handleGetRedactionConfig(rrGet2, httptest.NewRequest(http.MethodGet, "/api/redaction-config", nil))
	var got2 struct {
		CustomPatterns []string `json:"custom_patterns"`
	}
	if err := json.Unmarshal(rrGet2.Body.Bytes(), &got2); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got2.CustomPatterns) != 1 {
		t.Errorf("handleGetRedactionConfig after PUT = %+v, want one pattern", got2.CustomPatterns)
	}
}

func TestHandlePutRedactionConfig_RejectsInvalidRegex(t *testing.T) {
	initTestStore(t)
	rr := httptest.NewRecorder()
	body := `{"custom_patterns":["(unterminated"]}`
	handlePutRedactionConfig(rr, httptest.NewRequest(http.MethodPut, "/api/redaction-config", strings.NewReader(body)))
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

func TestHandleSandbox_RoundTrip(t *testing.T) {
	initTestStore(t) // bootstrap mode also satisfies requireStepUp for the PUT
	rr := httptest.NewRecorder()
	handleGetSandbox(rr, httptest.NewRequest(http.MethodGet, "/api/sandbox", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("GET status = %d, body=%s", rr.Code, rr.Body.String())
	}

	putBody := `{"content":"enabled: true\nprotect:\n  files:\n    - /etc/shadow\n"}`
	rrPut := httptest.NewRecorder()
	handlePutSandbox(rrPut, httptest.NewRequest(http.MethodPut, "/api/sandbox", strings.NewReader(putBody)))
	if rrPut.Code != http.StatusOK {
		t.Fatalf("PUT status = %d, body=%s", rrPut.Code, rrPut.Body.String())
	}

	rrGet2 := httptest.NewRecorder()
	handleGetSandbox(rrGet2, httptest.NewRequest(http.MethodGet, "/api/sandbox", nil))
	var got struct {
		Content string `json:"content"`
	}
	if err := json.Unmarshal(rrGet2.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !strings.Contains(got.Content, "/etc/shadow") {
		t.Errorf("handleGetSandbox after PUT = %+v, want content containing /etc/shadow", got)
	}
}

func TestHandlePutSandbox_RejectsInvalidSchema(t *testing.T) {
	initTestStore(t)
	rr := httptest.NewRecorder()
	body := `{"content":"not_a_real_field: true\n"}`
	handlePutSandbox(rr, httptest.NewRequest(http.MethodPut, "/api/sandbox", strings.NewReader(body)))
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400, body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandleSandboxTemplates_RoundTrip(t *testing.T) {
	initTestStore(t)
	rr := httptest.NewRecorder()
	handleGetSandboxTemplates(rr, httptest.NewRequest(http.MethodGet, "/api/sandbox-templates", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("GET (empty) status = %d, body=%s", rr.Code, rr.Body.String())
	}
	if strings.TrimSpace(rr.Body.String()) != "{}" {
		t.Errorf("handleGetSandboxTemplates (empty) = %q, want {}", rr.Body.String())
	}

	putBody := `{"strict":"enabled: true\n"}`
	rrPut := httptest.NewRecorder()
	handlePutSandboxTemplates(rrPut, httptest.NewRequest(http.MethodPut, "/api/sandbox-templates", strings.NewReader(putBody)))
	if rrPut.Code != http.StatusOK {
		t.Fatalf("PUT status = %d, body=%s", rrPut.Code, rrPut.Body.String())
	}

	rrGet2 := httptest.NewRecorder()
	handleGetSandboxTemplates(rrGet2, httptest.NewRequest(http.MethodGet, "/api/sandbox-templates", nil))
	var got map[string]string
	if err := json.Unmarshal(rrGet2.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got["strict"] == "" {
		t.Errorf("handleGetSandboxTemplates after PUT = %+v, want a strict template", got)
	}
}

func TestHandlePutSandboxTemplates_RejectsInvalidTemplate(t *testing.T) {
	initTestStore(t)
	rr := httptest.NewRecorder()
	body := `{"bad":"not_a_real_field: true\n"}`
	handlePutSandboxTemplates(rr, httptest.NewRequest(http.MethodPut, "/api/sandbox-templates", strings.NewReader(body)))
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400, body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandleGetSudoersHosts_MergesSnapshotAndSessionHosts(t *testing.T) {
	initTestStore(t)

	// A host with a sudoers snapshot but no session.
	if err := sessionStore.SaveSudoersSnapshot(t.Context(), sudoersSnap("snap-host", "root ALL=(ALL) ALL\n")); err != nil {
		t.Fatalf("SaveSudoersSnapshot: %v", err)
	}

	rr := httptest.NewRecorder()
	handleGetSudoersHosts(rr, httptest.NewRequest(http.MethodGet, "/api/sudoers/hosts", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
	}
	var got []struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	found := false
	for _, h := range got {
		if h.Name == "snap-host" {
			found = true
		}
	}
	if !found {
		t.Errorf("handleGetSudoersHosts = %+v, want snap-host present", got)
	}
}

func TestHandleGetSudoersSnapshots(t *testing.T) {
	initTestStore(t)
	if err := sessionStore.SaveSudoersSnapshot(t.Context(), sudoersSnap("host1", "root ALL=(ALL) ALL\n")); err != nil {
		t.Fatalf("SaveSudoersSnapshot: %v", err)
	}

	rr := httptest.NewRecorder()
	handleGetSudoersSnapshots(rr, httptest.NewRequest(http.MethodGet, "/api/sudoers/snapshots?host=host1", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
	}
	var got struct {
		Host      string `json:"host"`
		Snapshots []struct {
			SHA256 string `json:"sha256"`
		} `json:"snapshots"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Host != "host1" || len(got.Snapshots) != 1 {
		t.Errorf("handleGetSudoersSnapshots = %+v, want one snapshot for host1", got)
	}
}

func TestHandleGetSudoersSnapshots_RequiresHost(t *testing.T) {
	initTestStore(t)
	rr := httptest.NewRecorder()
	handleGetSudoersSnapshots(rr, httptest.NewRequest(http.MethodGet, "/api/sudoers/snapshots", nil))
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}
