package main

// Tests for user/host/access-log admin handlers (handlers_admin_users.go):
// handleGetWhitelistedUsers, handlePutWhitelistedUsers, handleGetUsers,
// handlePutUser, handleDeleteUser, handleGetHosts, handleAccessLog.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"sudo-logger/internal/store"
)

func TestHandleWhitelistedUsers_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	var err error
	sessionStore, err = store.New(testStoreConfig(dir))
	if err != nil {
		t.Fatalf("init test store: %v", err)
	}
	t.Cleanup(func() { sessionStore.Close() })
	resetTestCaches(t)

	rr := httptest.NewRecorder()
	handleGetWhitelistedUsers(rr, adminReq(http.MethodGet, "/api/whitelisted-users", ""))
	if rr.Code != http.StatusOK {
		t.Fatalf("GET (empty) status = %d, body=%s", rr.Code, rr.Body.String())
	}
	var got struct {
		Config WhitelistedUsersConfig `json:"config"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got.Config.Users) != 0 {
		t.Errorf("GET (empty) users = %+v, want none", got.Config.Users)
	}

	body := `{"config":{"users":[{"username":"svc-deploy","hosts":["host1"],"reason":"automation"}]}}`
	rrPut := httptest.NewRecorder()
	handlePutWhitelistedUsers(rrPut, adminReq(http.MethodPut, "/api/whitelisted-users", body))
	if rrPut.Code != http.StatusOK {
		t.Fatalf("PUT status = %d, body=%s", rrPut.Code, rrPut.Body.String())
	}

	// GetWhitelistPolicy (LocalStore) serves from an in-memory cache refreshed
	// by a background reload goroutine every 30s (same design as
	// SaveBlockedPolicy) — a save is not immediately visible through it, by
	// design. Verify the actual persisted file content instead.
	data, err := os.ReadFile(dir + "/whitelisted-users.yaml")
	if err != nil {
		t.Fatalf("read whitelisted-users.yaml: %v", err)
	}
	if !strings.Contains(string(data), "svc-deploy") || !strings.Contains(string(data), "automation") {
		t.Errorf("whitelisted-users.yaml after PUT = %q, want it to contain svc-deploy/automation", data)
	}
}

func TestHandlePutWhitelistedUsers_RejectsEmptyUsername(t *testing.T) {
	initTestStore(t)
	rr := httptest.NewRecorder()
	body := `{"config":{"users":[{"username":"","hosts":[],"reason":"x"}]}}`
	handlePutWhitelistedUsers(rr, adminReq(http.MethodPut, "/api/whitelisted-users", body))
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

func TestHandleGetUsers(t *testing.T) {
	initTestStore(t)
	u := newUserWithPassword(t, "alice", "Correct-Horse1!", RoleAdmin)
	if err := sessionStore.UpsertUser(t.Context(), u); err != nil {
		t.Fatalf("UpsertUser: %v", err)
	}

	rr := httptest.NewRecorder()
	handleGetUsers(rr, adminReq(http.MethodGet, "/api/users", ""))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
	}
	var users []store.User
	if err := json.Unmarshal(rr.Body.Bytes(), &users); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	found := false
	for _, u := range users {
		if u.Username == "alice" {
			found = true
		}
	}
	if !found {
		t.Errorf("handleGetUsers = %+v, want alice present", users)
	}
}

func TestHandlePutUser_CreateAndUpdate(t *testing.T) {
	initTestStore(t)
	admin := newUserWithPassword(t, "root-admin", "Correct-Horse1!", RoleAdmin)
	if err := sessionStore.UpsertUser(t.Context(), admin); err != nil {
		t.Fatalf("UpsertUser: %v", err)
	}

	body := `{"username":"bob","role":"viewer","source":"local","password_hash":"Correct-Horse2!"}`
	rr := httptest.NewRecorder()
	handlePutUser(rr, adminReq(http.MethodPut, "/api/users", body))
	if rr.Code != http.StatusNoContent {
		t.Fatalf("create status = %d, body=%s", rr.Code, rr.Body.String())
	}

	got, err := sessionStore.GetUser(t.Context(), "bob")
	if err != nil || got == nil {
		t.Fatalf("GetUser after create: %v, %v", got, err)
	}
	if got.PasswordHash == "" {
		t.Error("expected a bcrypt password hash to be stored")
	}
}

func TestHandlePutUser_RequiresUsername(t *testing.T) {
	initTestStore(t)
	admin := newUserWithPassword(t, "root-admin", "Correct-Horse1!", RoleAdmin)
	if err := sessionStore.UpsertUser(t.Context(), admin); err != nil {
		t.Fatalf("UpsertUser: %v", err)
	}
	rr := httptest.NewRecorder()
	handlePutUser(rr, adminReq(http.MethodPut, "/api/users", `{"role":"viewer"}`))
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

func TestHandlePutUser_CannotAssignRoleAboveOwnPermissions(t *testing.T) {
	initTestStore(t)
	viewer := newUserWithPassword(t, "someone", "Correct-Horse1!", RoleViewer)
	if err := sessionStore.UpsertUser(t.Context(), viewer); err != nil {
		t.Fatalf("UpsertUser: %v", err)
	}
	rr := httptest.NewRecorder()
	body := `{"username":"newadmin","role":"admin","source":"local"}`
	handlePutUser(rr, viewerReq(http.MethodPut, "/api/users", body))
	if rr.Code != http.StatusForbidden {
		t.Errorf("viewer creating an admin user: status = %d, want 403, body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandlePutUser_BootstrapAllowsFirstUserWithoutAdmin(t *testing.T) {
	initTestStore(t) // zero users -> bootstrap mode
	rr := httptest.NewRecorder()
	body := `{"username":"first-admin","role":"admin","source":"local","password_hash":"Correct-Horse1!"}`
	req := httptest.NewRequest(http.MethodPut, "/api/users", strings.NewReader(body))
	handlePutUser(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("bootstrap create status = %d, body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandleDeleteUser(t *testing.T) {
	initTestStore(t)
	admin := newUserWithPassword(t, "root-admin", "Correct-Horse1!", RoleAdmin)
	if err := sessionStore.UpsertUser(t.Context(), admin); err != nil {
		t.Fatalf("UpsertUser: %v", err)
	}
	target := newUserWithPassword(t, "throwaway", "Correct-Horse2!", RoleViewer)
	if err := sessionStore.UpsertUser(t.Context(), target); err != nil {
		t.Fatalf("UpsertUser: %v", err)
	}

	rr := httptest.NewRecorder()
	handleDeleteUser(rr, adminReq(http.MethodDelete, "/api/users/throwaway", ""))
	if rr.Code != http.StatusNoContent {
		t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
	}

	got, err := sessionStore.GetUser(t.Context(), "throwaway")
	if err != nil {
		t.Fatalf("GetUser after delete: %v", err)
	}
	if got != nil {
		t.Error("user still present after handleDeleteUser")
	}
}

func TestHandleDeleteUser_RequiresUsernameInPath(t *testing.T) {
	initTestStore(t)
	admin := newUserWithPassword(t, "root-admin", "Correct-Horse1!", RoleAdmin)
	if err := sessionStore.UpsertUser(t.Context(), admin); err != nil {
		t.Fatalf("UpsertUser: %v", err)
	}
	rr := httptest.NewRecorder()
	handleDeleteUser(rr, adminReq(http.MethodDelete, "/api/users/", ""))
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

func TestHandleGetHosts(t *testing.T) {
	dir := t.TempDir()
	var err error
	sessionStore, err = store.New(testStoreConfig(dir))
	if err != nil {
		t.Fatalf("init test store: %v", err)
	}
	t.Cleanup(func() { sessionStore.Close() })
	resetTestCaches(t)

	seedCastWithOutput(t, dir, "alice", "host-a", "hello")
	seedCastWithOutput(t, dir, "bob", "host-b", "world")

	rr := httptest.NewRecorder()
	handleGetHosts(rr, adminReq(http.MethodGet, "/api/hosts", ""))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
	}
	var got struct {
		Hosts []string `json:"hosts"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got.Hosts) != 2 || got.Hosts[0] != "host-a" || got.Hosts[1] != "host-b" {
		t.Errorf("handleGetHosts = %v, want [host-a host-b] (sorted)", got.Hosts)
	}
}

func TestHandleAccessLog(t *testing.T) {
	initTestStore(t)
	if err := sessionStore.RecordView(t.Context(), "tsid-1", "alice", "/replay/tsid-1"); err != nil {
		t.Fatalf("RecordView: %v", err)
	}

	rr := httptest.NewRecorder()
	handleAccessLog(rr, adminReq(http.MethodGet, "/api/access-log", ""))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
	}
	var entries []store.AccessLogEntry
	if err := json.Unmarshal(rr.Body.Bytes(), &entries); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(entries) != 1 || entries[0].TSID != "tsid-1" || entries[0].Viewer != "alice" {
		t.Errorf("handleAccessLog = %+v, want one tsid-1/alice entry", entries)
	}
}

func TestHandleAccessLog_RejectsNonGet(t *testing.T) {
	initTestStore(t)
	rr := httptest.NewRecorder()
	handleAccessLog(rr, adminReq(http.MethodPost, "/api/access-log", ""))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rr.Code)
	}
}
