package main

// Tests for the previously-uncovered functions in handlers_session.go:
// cachedListSessions, recordView, validateTSID, enforceOwnership,
// handleSessionEvents, handleSessionCast, handleMetrics.
//
// listSessions/handleListSessions/matchesAll already have dedicated tests in
// handlers_test.go, including the seedHTTPSession helper reused here.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"sudo-logger/internal/store"
)

// reqAsViewer builds a request whose context carries both a viewer identity
// (what viewerFromContext/enforceOwnership check) and a permission set — the
// combination accessLogMiddleware would normally attach after authenticating
// a non-admin user.
func reqAsViewer(method, target, viewerName string, perms map[store.Permission]bool) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	ctx := context.WithValue(r.Context(), ctxViewer, viewerName)
	ctx = context.WithValue(ctx, ctxRole, RoleViewer)
	ctx = context.WithValue(ctx, ctxPermissions, perms)
	return r.WithContext(ctx)
}

func seedSessionStore(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	var err error
	sessionStore, err = store.New(testStoreConfig(dir))
	if err != nil {
		t.Fatalf("init test store: %v", err)
	}
	t.Cleanup(func() { sessionStore.Close() })
	resetTestCaches(t)
	return dir
}

// ── cachedListSessions ──────────────────────────────────────────────────────

func TestCachedListSessions(t *testing.T) {
	dir := seedSessionStore(t)
	seedHTTPSession(t, dir, "alice", "host1", "visudo /etc/sudoers")

	got := cachedListSessions(t.Context())
	found := false
	for _, r := range got {
		if r.User == "alice" && r.Host == "host1" {
			found = true
		}
	}
	if !found {
		t.Errorf("cachedListSessions = %+v, want alice/host1 present", got)
	}
}

// ── validateTSID ────────────────────────────────────────────────────────────

func TestValidateTSID(t *testing.T) {
	tests := []struct {
		name    string
		tsid    string
		wantErr bool
	}{
		{"valid", "alice/host1_20260415-120000", false},
		{"path traversal", "../../etc/passwd", true},
		{"invalid char", "alice/host1;rm -rf", true},
		{"empty", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateTSID(tt.tsid)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateTSID(%q) error = %v, wantErr %v", tt.tsid, err, tt.wantErr)
			}
		})
	}
}

// ── recordView ──────────────────────────────────────────────────────────────

func TestRecordView(t *testing.T) {
	seedSessionStore(t)
	req := reqAsViewer(http.MethodGet, "/api/session/cast?tsid=x", "alice", nil)
	recordView(req, "alice/host1_20260415-120000", "https://replay.example/?tsid=x")

	entries, err := sessionStore.ListAccessLog(t.Context(), "", 10)
	if err != nil {
		t.Fatalf("ListAccessLog: %v", err)
	}
	if len(entries) != 1 || entries[0].Viewer != "alice" {
		t.Errorf("access log after recordView = %+v, want one alice entry", entries)
	}
}

// ── enforceOwnership ────────────────────────────────────────────────────────

func TestEnforceOwnership_UnauthenticatedOpenDeploymentAllowed(t *testing.T) {
	seedSessionStore(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/session/cast?tsid=x", nil) // viewer defaults to "-"
	if !enforceOwnership(rr, req, "alice/host1_20260415-120000") {
		t.Error("enforceOwnership should allow when viewer is unauthenticated (\"-\")")
	}
}

func TestEnforceOwnership_ReplayAllBypassesCheck(t *testing.T) {
	seedSessionStore(t)
	rr := httptest.NewRecorder()
	req := reqAsViewer(http.MethodGet, "/api/session/cast?tsid=x", "bob",
		map[store.Permission]bool{store.PermSessionsReplayAll: true})
	if !enforceOwnership(rr, req, "alice/host1_20260415-120000") {
		t.Error("enforceOwnership should allow a viewer with PermSessionsReplayAll regardless of ownership")
	}
}

func TestEnforceOwnership_OwnSessionAllowed(t *testing.T) {
	dir := seedSessionStore(t)
	seedHTTPSession(t, dir, "alice", "host1", "ls")
	rr := httptest.NewRecorder()
	req := reqAsViewer(http.MethodGet, "/api/session/cast?tsid=x", "alice",
		map[store.Permission]bool{store.PermSessionsReplayOwn: true})
	if !enforceOwnership(rr, req, "alice/host1_20260415-120000") {
		t.Errorf("enforceOwnership should allow alice her own session, body=%s", rr.Body.String())
	}
}

func TestEnforceOwnership_OtherUsersSessionForbidden(t *testing.T) {
	dir := seedSessionStore(t)
	seedHTTPSession(t, dir, "alice", "host1", "ls")
	rr := httptest.NewRecorder()
	req := reqAsViewer(http.MethodGet, "/api/session/cast?tsid=x", "mallory",
		map[store.Permission]bool{store.PermSessionsReplayOwn: true})
	if enforceOwnership(rr, req, "alice/host1_20260415-120000") {
		t.Error("enforceOwnership should refuse mallory access to alice's session")
	}
	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rr.Code)
	}
}

func TestEnforceOwnership_MissingSessionNotFound(t *testing.T) {
	seedSessionStore(t)
	rr := httptest.NewRecorder()
	req := reqAsViewer(http.MethodGet, "/api/session/cast?tsid=x", "alice",
		map[store.Permission]bool{store.PermSessionsReplayOwn: true})
	if enforceOwnership(rr, req, "nobody/nowhere_20260101-000000") {
		t.Error("enforceOwnership should refuse a tsid that doesn't exist")
	}
	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rr.Code)
	}
}

// ── handleSessionEvents / handleSessionCast ─────────────────────────────────

func TestHandleSessionEvents(t *testing.T) {
	dir := seedSessionStore(t)
	seedHTTPSession(t, dir, "alice", "host1", "ls")

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/session/events?tsid=alice/host1_20260415-120000", nil)
	handleSessionEvents(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"type"`) {
		t.Errorf("handleSessionEvents body = %q, want at least one PlaybackEvent", rr.Body.String())
	}
}

func TestHandleSessionEvents_MissingTSID(t *testing.T) {
	seedSessionStore(t)
	rr := httptest.NewRecorder()
	handleSessionEvents(rr, httptest.NewRequest(http.MethodGet, "/api/session/events", nil))
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

func TestHandleSessionEvents_InvalidTSID(t *testing.T) {
	seedSessionStore(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/session/events?tsid=../../etc/passwd", nil)
	handleSessionEvents(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

func TestHandleSessionEvents_RejectsNonGet(t *testing.T) {
	seedSessionStore(t)
	rr := httptest.NewRecorder()
	handleSessionEvents(rr, httptest.NewRequest(http.MethodPost, "/api/session/events?tsid=x", nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rr.Code)
	}
}

func TestHandleSessionCast(t *testing.T) {
	dir := seedSessionStore(t)
	seedHTTPSession(t, dir, "alice", "host1", "ls")

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/session/cast?tsid=alice/host1_20260415-120000", nil)
	handleSessionCast(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/octet-stream" {
		t.Errorf("Content-Type = %q, want application/octet-stream", ct)
	}
	if !strings.Contains(rr.Body.String(), `"version"`) {
		t.Errorf("handleSessionCast body missing cast header: %q", rr.Body.String())
	}
}

func TestHandleSessionCast_MissingSession(t *testing.T) {
	seedSessionStore(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/session/cast?tsid=nobody/nowhere_20260101-000000", nil)
	handleSessionCast(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rr.Code)
	}
}

// ── handleMetrics ────────────────────────────────────────────────────────────

func TestHandleMetrics(t *testing.T) {
	dir := seedSessionStore(t)
	seedHTTPSession(t, dir, "alice", "host1", "ls")

	rr := httptest.NewRecorder()
	handleMetrics(rr, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if !strings.Contains(body, "sudoreplay_sessions_total") {
		t.Errorf("handleMetrics missing sudoreplay_sessions_total, body=%s", body)
	}
	if !strings.Contains(body, "sudoreplay_session_views_total") {
		t.Errorf("handleMetrics missing sudoreplay_session_views_total, body=%s", body)
	}
}

func TestHandleMetrics_RejectsNonGet(t *testing.T) {
	seedSessionStore(t)
	rr := httptest.NewRecorder()
	handleMetrics(rr, httptest.NewRequest(http.MethodPost, "/metrics", nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rr.Code)
	}
}
