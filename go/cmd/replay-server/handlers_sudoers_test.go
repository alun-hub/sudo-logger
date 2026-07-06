package main

// Tests for the sudoers config pipeline: stripSudoersHeader,
// extractManagedSudoers, sha256Sum, validateSudoers (real visudo),
// handlePutSudoersConfig/handleDeleteSudoersConfig/handleGetSudoersConfig.

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// ── stripSudoersHeader ───────────────────────────────────────────────────────

func TestStripSudoersHeader(t *testing.T) {
	in := "# Managed by sudo-logger — do not edit by hand\n" +
		"# Generated: 2026-01-01\n" +
		"# --- /etc/sudoers.d/sudo-logger-managed ---\n" +
		"\n" +
		"alice ALL=(ALL) NOPASSWD: ALL\n" +
		"bob   ALL = (ALL:ALL)  ALL\n"
	got := stripSudoersHeader(in)
	want := "alice ALL=NOPASSWD:ALL\nbob ALL=ALL"
	if got != want {
		t.Errorf("stripSudoersHeader:\n got  %q\n want %q", got, want)
	}
}

func TestStripSudoersHeader_NoHeaderLines(t *testing.T) {
	in := "alice ALL=(ALL) ALL\n"
	got := stripSudoersHeader(in)
	want := "alice ALL=ALL"
	if got != want {
		t.Errorf("stripSudoersHeader: got %q, want %q", got, want)
	}
}

func TestStripSudoersHeader_Empty(t *testing.T) {
	if got := stripSudoersHeader(""); got != "" {
		t.Errorf("stripSudoersHeader(\"\") = %q, want empty", got)
	}
}

// ── extractManagedSudoers ────────────────────────────────────────────────────

func TestExtractManagedSudoers_MarkerPresent(t *testing.T) {
	full := "# some preamble\n" +
		"# --- /etc/sudoers.d/sudo-logger-managed ---\n" +
		"alice ALL=(ALL) ALL\n" +
		"# --- /etc/sudoers.d/other-file ---\n" +
		"bob ALL=(ALL) ALL\n"
	got := extractManagedSudoers(full)
	want := "alice ALL=ALL"
	if got != want {
		t.Errorf("extractManagedSudoers:\n got  %q\n want %q", got, want)
	}
}

func TestExtractManagedSudoers_MarkerAbsent(t *testing.T) {
	if got := extractManagedSudoers("no marker in here at all"); got != "" {
		t.Errorf("extractManagedSudoers without marker = %q, want empty", got)
	}
}

func TestExtractManagedSudoers_MarkerAtEOF(t *testing.T) {
	full := "# --- /etc/sudoers.d/sudo-logger-managed ---\nalice ALL=(ALL) ALL\n"
	got := extractManagedSudoers(full)
	want := "alice ALL=ALL"
	if got != want {
		t.Errorf("extractManagedSudoers at EOF:\n got  %q\n want %q", got, want)
	}
}

// TestExtractManagedSudoers_InjectedMarker documents current behavior when
// the content itself contains a marker-like string: extraction stops at the
// first occurrence, so a managed block cannot smuggle a fake "next file"
// boundary to hide content from the sync check — it just gets truncated.
func TestExtractManagedSudoers_InjectedMarker(t *testing.T) {
	full := "# --- /etc/sudoers.d/sudo-logger-managed ---\n" +
		"alice ALL=(ALL) ALL\n" +
		"# --- fake boundary ---\n" +
		"mallory ALL=(ALL) NOPASSWD: ALL\n"
	got := extractManagedSudoers(full)
	if strings.Contains(got, "mallory") {
		t.Errorf("extractManagedSudoers should stop at the first '# --- ' marker, got %q", got)
	}
}

// ── sha256Sum ─────────────────────────────────────────────────────────────────

func TestSha256Sum(t *testing.T) {
	got := sha256Sum([]byte("hello"))
	// Known SHA-256 of "hello".
	want := []byte{
		0x2c, 0xf2, 0x4d, 0xba, 0x5f, 0xb0, 0xa3, 0x0e,
		0x26, 0xe8, 0x3b, 0x2a, 0xc5, 0xb9, 0xe2, 0x9e,
		0x1b, 0x16, 0x1e, 0x5c, 0x1f, 0xa7, 0x42, 0x5e,
		0x73, 0x04, 0x33, 0x62, 0x93, 0x8b, 0x98, 0x24,
	}
	if len(got) != len(want) {
		t.Fatalf("sha256Sum length = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("sha256Sum(%q) = %x, want %x", "hello", got, want)
		}
	}
}

// ── validateSudoers (real visudo) ────────────────────────────────────────────

func TestValidateSudoers_Valid(t *testing.T) {
	if err := validateSudoers("alice ALL=(ALL) NOPASSWD: ALL\n"); err != nil {
		t.Errorf("valid sudoers syntax rejected: %v", err)
	}
}

func TestValidateSudoers_Invalid(t *testing.T) {
	if err := validateSudoers("this is not valid sudoers syntax @#$%\n"); err == nil {
		t.Error("invalid sudoers syntax should be rejected")
	}
}

func TestValidateSudoers_ErrorHidesTempFilename(t *testing.T) {
	err := validateSudoers("garbage !!! not sudoers\n")
	if err == nil {
		t.Fatal("expected an error for invalid syntax")
	}
	if strings.Contains(err.Error(), "sudoers-valid-") {
		t.Errorf("validateSudoers error leaked the temp file name: %v", err)
	}
}

// ── handlePutSudoersConfig ────────────────────────────────────────────────────

func putSudoersReq(host, content string) *http.Request {
	body := `{"content":` + strconv.Quote(content) + `}`
	url := "/api/sudoers/config"
	if host != "" {
		url += "?host=" + host
	}
	return httptest.NewRequest(http.MethodPut, url, strings.NewReader(body))
}

func TestHandlePutSudoersConfig_ValidDefault(t *testing.T) {
	initTestStore(t)
	req := putSudoersReq("", "alice ALL=(ALL) NOPASSWD: ALL\n")
	rr := httptest.NewRecorder()
	handlePutSudoersConfig(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("valid default config: got %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
}

func TestHandlePutSudoersConfig_ValidWithHost(t *testing.T) {
	initTestStore(t)
	req := putSudoersReq("host1", "bob ALL=(ALL) ALL\n")
	rr := httptest.NewRecorder()
	handlePutSudoersConfig(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("valid host config: got %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
}

func TestHandlePutSudoersConfig_EmptyContentIsValid(t *testing.T) {
	// Empty content skips validateSudoers entirely and is accepted (used to
	// clear a staged config back to "no override").
	initTestStore(t)
	req := putSudoersReq("host1", "")
	rr := httptest.NewRecorder()
	handlePutSudoersConfig(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("empty content: got %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
}

func TestHandlePutSudoersConfig_InvalidSyntax(t *testing.T) {
	initTestStore(t)
	req := putSudoersReq("", "not valid sudoers !!! @#$\n")
	rr := httptest.NewRecorder()
	handlePutSudoersConfig(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("invalid syntax: got %d, want 400; body: %s", rr.Code, rr.Body.String())
	}
}

func TestHandlePutSudoersConfig_InvalidHost(t *testing.T) {
	initTestStore(t)
	tests := []string{
		"../../etc/passwd",
		".hidden",
		"has/slash",
		"has\\backslash",
		strings.Repeat("a", 256),
	}
	for _, host := range tests {
		t.Run(host, func(t *testing.T) {
			req := putSudoersReq(host, "alice ALL=(ALL) ALL\n")
			rr := httptest.NewRecorder()
			handlePutSudoersConfig(rr, req)
			if rr.Code != http.StatusBadRequest {
				t.Errorf("host %q: got %d, want 400", host, rr.Code)
			}
		})
	}
}

func TestHandlePutSudoersConfig_BodyTooLarge(t *testing.T) {
	initTestStore(t)
	huge := strings.Repeat("a", 300*1024)
	req := putSudoersReq("", huge)
	rr := httptest.NewRecorder()
	handlePutSudoersConfig(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("oversized body: got %d, want 400; body: %s", rr.Code, rr.Body.String())
	}
}

func TestHandlePutSudoersConfig_InvalidJSON(t *testing.T) {
	initTestStore(t)
	req := httptest.NewRequest(http.MethodPut, "/api/sudoers/config", strings.NewReader("{bad"))
	rr := httptest.NewRecorder()
	handlePutSudoersConfig(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("invalid JSON: got %d, want 400", rr.Code)
	}
}

// ── handleDeleteSudoersConfig ─────────────────────────────────────────────────

func TestHandleDeleteSudoersConfig_HostRequired(t *testing.T) {
	initTestStore(t)
	req := httptest.NewRequest(http.MethodDelete, "/api/sudoers/config", nil)
	rr := httptest.NewRecorder()
	handleDeleteSudoersConfig(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("missing host: got %d, want 400", rr.Code)
	}
}

func TestHandleDeleteSudoersConfig_InvalidHost(t *testing.T) {
	initTestStore(t)
	req := httptest.NewRequest(http.MethodDelete, "/api/sudoers/config?host=../../etc/passwd", nil)
	rr := httptest.NewRecorder()
	handleDeleteSudoersConfig(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("traversal host: got %d, want 400", rr.Code)
	}
}

func TestHandleDeleteSudoersConfig_Valid(t *testing.T) {
	initTestStore(t)
	putReq := putSudoersReq("host1", "alice ALL=(ALL) ALL\n")
	putRR := httptest.NewRecorder()
	handlePutSudoersConfig(putRR, putReq)
	if putRR.Code != http.StatusOK {
		t.Fatalf("setup PUT failed: %d", putRR.Code)
	}

	delReq := httptest.NewRequest(http.MethodDelete, "/api/sudoers/config?host=host1", nil)
	delRR := httptest.NewRecorder()
	handleDeleteSudoersConfig(delRR, delReq)
	if delRR.Code != http.StatusOK {
		t.Errorf("delete: got %d, want 200; body: %s", delRR.Code, delRR.Body.String())
	}

	getReq := httptest.NewRequest(http.MethodGet, "/api/sudoers/config?host=host1", nil)
	getRR := httptest.NewRecorder()
	handleGetSudoersConfig(getRR, getReq)
	if !strings.Contains(getRR.Body.String(), `"is_override":false`) {
		t.Errorf("after delete, host config should no longer be an override; body: %s", getRR.Body.String())
	}
}

// ── handleGetSudoersConfig ────────────────────────────────────────────────────

func TestHandleGetSudoersConfig_FallsBackToDefault(t *testing.T) {
	initTestStore(t)
	putReq := putSudoersReq("", "alice ALL=(ALL) ALL\n")
	putRR := httptest.NewRecorder()
	handlePutSudoersConfig(putRR, putReq)
	if putRR.Code != http.StatusOK {
		t.Fatalf("setup PUT failed: %d", putRR.Code)
	}

	// host1 has no override — should fall back to the _default content.
	getReq := httptest.NewRequest(http.MethodGet, "/api/sudoers/config?host=host1", nil)
	getRR := httptest.NewRecorder()
	handleGetSudoersConfig(getRR, getReq)
	if getRR.Code != http.StatusOK {
		t.Fatalf("GET: got %d, want 200", getRR.Code)
	}
	if !strings.Contains(getRR.Body.String(), "alice") {
		t.Errorf("expected fallback to default content, body: %s", getRR.Body.String())
	}
	if !strings.Contains(getRR.Body.String(), `"is_override":false`) {
		t.Errorf("host with no override should report is_override=false, body: %s", getRR.Body.String())
	}
}

func TestHandleGetSudoersConfig_HostOverride(t *testing.T) {
	initTestStore(t)
	defReq := putSudoersReq("", "alice ALL=(ALL) ALL\n")
	handlePutSudoersConfig(httptest.NewRecorder(), defReq)
	hostReq := putSudoersReq("host1", "bob ALL=(ALL) ALL\n")
	handlePutSudoersConfig(httptest.NewRecorder(), hostReq)

	getReq := httptest.NewRequest(http.MethodGet, "/api/sudoers/config?host=host1", nil)
	getRR := httptest.NewRecorder()
	handleGetSudoersConfig(getRR, getReq)
	if !strings.Contains(getRR.Body.String(), "bob") {
		t.Errorf("expected host override content, body: %s", getRR.Body.String())
	}
	if !strings.Contains(getRR.Body.String(), `"is_override":true`) {
		t.Errorf("host with an override should report is_override=true, body: %s", getRR.Body.String())
	}
}

// ── summarizeLineDiff ────────────────────────────────────────────────────────

func TestSummarizeLineDiff(t *testing.T) {
	cases := []struct {
		name           string
		old, new       string
		added, removed int
	}{
		{"no change", "a\nb\n", "a\nb\n", 0, 0},
		{"pure addition", "a\n", "a\nb\n", 1, 0},
		{"pure removal", "a\nb\n", "a\n", 0, 1},
		{"replace one line", "a\nb\nc\n", "a\nx\nc\n", 1, 1},
		{"from empty", "", "a\nb\n", 2, 0},
		{"to empty", "a\nb\n", "", 0, 2},
		{"both empty", "", "", 0, 0},
		{"duplicate line added", "a\n", "a\na\n", 1, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			added, removed := summarizeLineDiff(c.old, c.new)
			if added != c.added || removed != c.removed {
				t.Errorf("summarizeLineDiff(%q, %q) = (+%d/-%d), want (+%d/-%d)",
					c.old, c.new, added, removed, c.added, c.removed)
			}
		})
	}
}
