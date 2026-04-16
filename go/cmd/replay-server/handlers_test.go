package main

// Security and core-functionality tests for HTTP handlers.
// Focus areas:
//   - basicAuthMiddleware: authentication gate
//   - validateTLSPaths: path-traversal prevention (S1)
//   - handlePutRules: rule persistence and validation
//   - handlePutSiemConfig: transport/format enum + TLS path validation (S1)
//   - handleGetBlockedUsers / handlePutBlockedUsers: block-policy API
//   - handleListSessions: core session listing

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"sudo-logger/internal/siem"
	"sudo-logger/internal/store"
)

// ── test store helper ─────────────────────────────────────────────────────────

// initTestStore points the global sessionStore at a temp directory and
// registers a cleanup that closes it. Call at the start of any handler test
// that reads from or writes to the store.
func initTestStore(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	var err error
	sessionStore, err = store.New(store.Config{
		Backend:          "local",
		LogDir:           dir,
		RiskRulesPath:    dir + "/risk-rules.yaml",
		SiemConfigPath:   dir + "/siem.yaml",
		BlockedUsersPath: dir + "/blocked-users.yaml",
	})
	if err != nil {
		t.Fatalf("init test store: %v", err)
	}
	t.Cleanup(func() { sessionStore.Close() })
	// Reset the session cache so state from other tests does not bleed in.
	cache.mu.Lock()
	cache.built = false
	cache.mu.Unlock()
}

// ── validateTLSPaths ──────────────────────────────────────────────────────────

func TestValidateTLSPathsEmpty(t *testing.T) {
	if err := validateTLSPaths("https", siem.TLSCfg{}); err != nil {
		t.Errorf("empty TLSCfg should be accepted: %v", err)
	}
}

func TestValidateTLSPathsAbsolute(t *testing.T) {
	c := siem.TLSCfg{CA: "/etc/sudo-logger/ca.pem", Cert: "/etc/sudo-logger/client.crt", Key: "/etc/sudo-logger/client.key"}
	if err := validateTLSPaths("https", c); err != nil {
		t.Errorf("valid absolute paths rejected: %v", err)
	}
}

func TestValidateTLSPathsRelativeCA(t *testing.T) {
	if err := validateTLSPaths("https", siem.TLSCfg{CA: "relative/ca.pem"}); err == nil {
		t.Error("relative CA path should be rejected")
	}
}

func TestValidateTLSPathsRelativeCert(t *testing.T) {
	if err := validateTLSPaths("syslog", siem.TLSCfg{Cert: "certs/client.crt"}); err == nil {
		t.Error("relative cert path should be rejected")
	}
}

func TestValidateTLSPathsTraversalCA(t *testing.T) {
	// Attempts to escape via path traversal must be blocked.
	if err := validateTLSPaths("https", siem.TLSCfg{CA: "/etc/sudo-logger/../../etc/passwd"}); err == nil {
		t.Error("path traversal in CA should be rejected")
	}
}

func TestValidateTLSPathsTraversalKey(t *testing.T) {
	if err := validateTLSPaths("syslog", siem.TLSCfg{Key: "/valid/../../../etc/shadow"}); err == nil {
		t.Error("path traversal in key should be rejected")
	}
}

// ── basicAuthMiddleware ───────────────────────────────────────────────────────

func newOKHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func TestBasicAuthMiddleware401NoCreds(t *testing.T) {
	hash := makeBcrypt(t, "secret")
	hs, _ := newHTPasswd(tempHTPasswd(t, "alice:"+hash))
	handler := basicAuthMiddleware(newOKHandler(), hs)

	req := httptest.NewRequest(http.MethodGet, "/api/sessions", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("no creds: got %d, want 401", rr.Code)
	}
	if !strings.Contains(rr.Header().Get("WWW-Authenticate"), "Basic") {
		t.Error("WWW-Authenticate header missing or wrong")
	}
}

func TestBasicAuthMiddleware401WrongPassword(t *testing.T) {
	hash := makeBcrypt(t, "correct")
	hs, _ := newHTPasswd(tempHTPasswd(t, "alice:"+hash))
	handler := basicAuthMiddleware(newOKHandler(), hs)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth("alice", "wrong")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("wrong password: got %d, want 401", rr.Code)
	}
}

func TestBasicAuthMiddleware401UnknownUser(t *testing.T) {
	hash := makeBcrypt(t, "pw")
	hs, _ := newHTPasswd(tempHTPasswd(t, "alice:"+hash))
	handler := basicAuthMiddleware(newOKHandler(), hs)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth("nobody", "pw")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("unknown user: got %d, want 401", rr.Code)
	}
}

func TestBasicAuthMiddleware200ValidCreds(t *testing.T) {
	hash := makeBcrypt(t, "secret")
	hs, _ := newHTPasswd(tempHTPasswd(t, "alice:"+hash))
	handler := basicAuthMiddleware(newOKHandler(), hs)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth("alice", "secret")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("valid creds: got %d, want 200", rr.Code)
	}
}

// ── handlePutRules ────────────────────────────────────────────────────────────

func TestHandlePutRulesValid(t *testing.T) {
	initTestStore(t)
	body := `{"rules":[{"id":"test-rule","score":50,"reason":"test","command_base_any":["bash"]}]}`
	req := httptest.NewRequest(http.MethodPut, "/api/rules", strings.NewReader(body))
	rr := httptest.NewRecorder()
	handlePutRules(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("valid rules: got %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
}

func TestHandlePutRulesInvalidJSON(t *testing.T) {
	initTestStore(t)
	req := httptest.NewRequest(http.MethodPut, "/api/rules", strings.NewReader("{not json"))
	rr := httptest.NewRecorder()
	handlePutRules(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("invalid JSON: got %d, want 400", rr.Code)
	}
}

func TestHandlePutRulesWrongMethod(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/rules", nil)
	rr := httptest.NewRecorder()
	handlePutRules(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET method: got %d, want 405", rr.Code)
	}
}

func TestHandlePutRulesEmptyRules(t *testing.T) {
	initTestStore(t)
	req := httptest.NewRequest(http.MethodPut, "/api/rules", strings.NewReader(`{"rules":[]}`))
	rr := httptest.NewRecorder()
	handlePutRules(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("empty rules list: got %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
}

// ── handlePutSiemConfig ───────────────────────────────────────────────────────

func siemConfigBody(cfg map[string]any) *bytes.Reader {
	b, _ := json.Marshal(map[string]any{"config": cfg})
	return bytes.NewReader(b)
}

func TestHandlePutSiemConfigInvalidTransport(t *testing.T) {
	initTestStore(t)
	req := httptest.NewRequest(http.MethodPut, "/api/siem-config",
		siemConfigBody(map[string]any{"transport": "grpc", "format": "json"}))
	rr := httptest.NewRecorder()
	handlePutSiemConfig(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("invalid transport: got %d, want 400; body: %s", rr.Code, rr.Body.String())
	}
}

func TestHandlePutSiemConfigInvalidFormat(t *testing.T) {
	initTestStore(t)
	req := httptest.NewRequest(http.MethodPut, "/api/siem-config",
		siemConfigBody(map[string]any{"transport": "https", "format": "xml"}))
	rr := httptest.NewRecorder()
	handlePutSiemConfig(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("invalid format: got %d, want 400; body: %s", rr.Code, rr.Body.String())
	}
}

func TestHandlePutSiemConfigPathTraversalHTTPS(t *testing.T) {
	// S1: path traversal in TLS cert paths must be rejected before writing to disk.
	initTestStore(t)
	cfg := map[string]any{
		"transport": "https",
		"format":    "json",
		"https": map[string]any{
			"url": "https://siem.example.com/log",
			"tls": map[string]any{"ca": "/etc/sudo-logger/../../etc/passwd"},
		},
	}
	req := httptest.NewRequest(http.MethodPut, "/api/siem-config", siemConfigBody(cfg))
	rr := httptest.NewRecorder()
	handlePutSiemConfig(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("path traversal in CA: got %d, want 400; body: %s", rr.Code, rr.Body.String())
	}
}

func TestHandlePutSiemConfigPathTraversalSyslog(t *testing.T) {
	initTestStore(t)
	cfg := map[string]any{
		"transport": "syslog",
		"format":    "json",
		"syslog": map[string]any{
			"addr":     "siem.example.com:514",
			"protocol": "tcp-tls",
			"tls":      map[string]any{"cert": "relative/client.crt"},
		},
	}
	req := httptest.NewRequest(http.MethodPut, "/api/siem-config", siemConfigBody(cfg))
	rr := httptest.NewRecorder()
	handlePutSiemConfig(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("relative syslog TLS cert: got %d, want 400; body: %s", rr.Code, rr.Body.String())
	}
}

func TestHandlePutSiemConfigValid(t *testing.T) {
	initTestStore(t)
	cfg := map[string]any{
		"enabled":   true,
		"transport": "stdout",
		"format":    "json",
	}
	req := httptest.NewRequest(http.MethodPut, "/api/siem-config", siemConfigBody(cfg))
	rr := httptest.NewRecorder()
	handlePutSiemConfig(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("valid config: got %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
	var resp map[string]bool
	json.NewDecoder(rr.Body).Decode(&resp) //nolint:errcheck
	if !resp["ok"] {
		t.Error(`response body: "ok" is not true`)
	}
}

func TestHandlePutSiemConfigInvalidJSON(t *testing.T) {
	req := httptest.NewRequest(http.MethodPut, "/api/siem-config", strings.NewReader("{bad"))
	rr := httptest.NewRecorder()
	handlePutSiemConfig(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("invalid JSON: got %d, want 400", rr.Code)
	}
}

// ── handleGetBlockedUsers / handlePutBlockedUsers ─────────────────────────────

func TestHandleGetBlockedUsersEmpty(t *testing.T) {
	initTestStore(t)
	req := httptest.NewRequest(http.MethodGet, "/api/blocked-users", nil)
	rr := httptest.NewRecorder()
	handleGetBlockedUsers(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("GET blocked-users: got %d, want 200", rr.Code)
	}
	var resp map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("response not valid JSON: %v", err)
	}
	if _, ok := resp["config"]; !ok {
		t.Error("response missing 'config' key")
	}
}

func TestHandlePutBlockedUsersValid(t *testing.T) {
	initTestStore(t)
	body := `{"config":{"block_message":"Access denied","users":[{"username":"mallory","hosts":[],"reason":"bad actor"}]}}`
	req := httptest.NewRequest(http.MethodPut, "/api/blocked-users", strings.NewReader(body))
	rr := httptest.NewRecorder()
	handlePutBlockedUsers(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("valid PUT: got %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
}

func TestHandlePutBlockedUsersMissingUsername(t *testing.T) {
	initTestStore(t)
	// A user entry with an empty username must be rejected (security: avoids
	// accidentally blocking all users with an empty string match).
	body := `{"config":{"users":[{"username":"","hosts":[],"reason":"oops"}]}}`
	req := httptest.NewRequest(http.MethodPut, "/api/blocked-users", strings.NewReader(body))
	rr := httptest.NewRecorder()
	handlePutBlockedUsers(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("empty username: got %d, want 400", rr.Code)
	}
}

func TestHandlePutBlockedUsersInvalidJSON(t *testing.T) {
	req := httptest.NewRequest(http.MethodPut, "/api/blocked-users", strings.NewReader("{invalid"))
	rr := httptest.NewRecorder()
	handlePutBlockedUsers(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("invalid JSON: got %d, want 400", rr.Code)
	}
}

func TestHandlePutAndGetBlockedUsersRoundtrip(t *testing.T) {
	// SaveBlockedPolicy writes to disk but does NOT update the in-memory
	// blockedCfg (the background goroutine does that every 30 s). To verify
	// the round-trip we PUT via the API, then re-open the store so that the
	// new store instance loads the file into memory, and finally GET via the API.
	dir := t.TempDir()
	cfg := store.Config{
		Backend:          "local",
		LogDir:           dir,
		BlockedUsersPath: dir + "/blocked-users.yaml",
		RiskRulesPath:    dir + "/risk-rules.yaml",
		SiemConfigPath:   dir + "/siem.yaml",
	}
	var err error
	sessionStore, err = store.New(cfg)
	if err != nil {
		t.Fatalf("init store: %v", err)
	}

	putBody := `{"config":{"block_message":"Blocked","users":[{"username":"attacker","hosts":["host1"],"reason":"suspicious"}]}}`
	putReq := httptest.NewRequest(http.MethodPut, "/api/blocked-users", strings.NewReader(putBody))
	putRec := httptest.NewRecorder()
	handlePutBlockedUsers(putRec, putReq)
	if putRec.Code != http.StatusOK {
		t.Fatalf("PUT: got %d, want 200; body: %s", putRec.Code, putRec.Body.String())
	}

	// Reopen the store so the policy file is loaded into in-memory state.
	sessionStore.Close()
	sessionStore, err = store.New(cfg)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	t.Cleanup(func() { sessionStore.Close() })
	cache.mu.Lock()
	cache.built = false
	cache.mu.Unlock()

	getReq := httptest.NewRequest(http.MethodGet, "/api/blocked-users", nil)
	getRec := httptest.NewRecorder()
	handleGetBlockedUsers(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("GET after PUT: got %d, want 200", getRec.Code)
	}
	var resp struct {
		Config BlockedUsersConfig `json:"config"`
	}
	if err := json.NewDecoder(getRec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode GET response: %v", err)
	}
	if resp.Config.BlockMessage != "Blocked" {
		t.Errorf("block_message: got %q, want %q", resp.Config.BlockMessage, "Blocked")
	}
	if len(resp.Config.Users) != 1 || resp.Config.Users[0].Username != "attacker" {
		t.Errorf("users: got %v, want [{attacker}]", resp.Config.Users)
	}
}

// ── handleListSessions ────────────────────────────────────────────────────────

func TestHandleListSessionsMethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/sessions", nil)
	rr := httptest.NewRecorder()
	handleListSessions(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST method: got %d, want 405", rr.Code)
	}
}

func TestHandleListSessionsReturnsJSON(t *testing.T) {
	initTestStore(t)
	// No sessions on disk — expect an empty but valid JSON response.
	req := httptest.NewRequest(http.MethodGet, "/api/sessions", nil)
	rr := httptest.NewRecorder()
	handleListSessions(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("GET sessions: got %d, want 200", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type: got %q, want application/json", ct)
	}
	var resp map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("response not valid JSON: %v", err)
	}
	if _, ok := resp["sessions"]; !ok {
		t.Error("response missing 'sessions' key")
	}
}

func TestHandleListSessionsWithSeededSessions(t *testing.T) {
	// Seed two sessions on disk and verify they appear in the API response.
	dir := t.TempDir()
	var err error
	sessionStore, err = store.New(store.Config{Backend: "local", LogDir: dir, RiskRulesPath: dir + "/risk-rules.yaml"})
	if err != nil {
		t.Fatalf("init store: %v", err)
	}
	t.Cleanup(func() { sessionStore.Close() })
	cache.mu.Lock()
	cache.built = false
	cache.mu.Unlock()

	// Use the helper from the existing test file to plant sessions on disk.
	seedHTTPSession(t, dir, "alice", "host1", "visudo /etc/sudoers")
	seedHTTPSession(t, dir, "bob", "host2", "echo hello")

	rulesMu.Lock()
	globalRules = nil
	globalRulesHash = "empty"
	rulesMu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/api/sessions", nil)
	rr := httptest.NewRecorder()
	handleListSessions(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("GET sessions: got %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Sessions []SessionInfo `json:"sessions"`
		Total    int           `json:"total"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Total < 2 {
		t.Errorf("total: got %d, want >= 2", resp.Total)
	}
}

func TestHandleListSessionsQueryFilter(t *testing.T) {
	dir := t.TempDir()
	var err error
	sessionStore, err = store.New(store.Config{Backend: "local", LogDir: dir, RiskRulesPath: dir + "/risk-rules.yaml"})
	if err != nil {
		t.Fatalf("init store: %v", err)
	}
	t.Cleanup(func() { sessionStore.Close() })
	cache.mu.Lock()
	cache.built = false
	cache.mu.Unlock()

	seedHTTPSession(t, dir, "alice", "host1", "visudo /etc/sudoers")
	seedHTTPSession(t, dir, "bob", "host2", "echo hello")

	rulesMu.Lock()
	globalRules = nil
	globalRulesHash = "empty-filter"
	rulesMu.Unlock()

	// Filter for alice only.
	req := httptest.NewRequest(http.MethodGet, "/api/sessions?q=alice", nil)
	rr := httptest.NewRecorder()
	handleListSessions(rr, req)

	var resp struct {
		Sessions []SessionInfo `json:"sessions"`
	}
	json.NewDecoder(rr.Body).Decode(&resp) //nolint:errcheck
	for _, s := range resp.Sessions {
		if s.User != "alice" {
			t.Errorf("filter q=alice: unexpected session user=%q tsid=%s", s.User, s.TSID)
		}
	}
}

// ── seedHTTPSession ───────────────────────────────────────────────────────────

// seedHTTPSession writes a minimal session directory with session.cast so that
// ListSessions can discover it. The TSID format is user/host_YYYYMMDD-HHMMSS.
func seedHTTPSession(t *testing.T, logDir, user, host, command string) {
	t.Helper()
	ts := "20260415-120000"
	sessDir := logDir + "/" + user + "/" + host + "_" + ts
	if err := os.MkdirAll(sessDir, 0o755); err != nil {
		t.Fatalf("seedHTTPSession mkdirall: %v", err)
	}
	hdr := `{"version":2,"width":220,"height":50,"timestamp":1744718400,` +
		`"session_id":"` + host + `-` + user + `",` +
		`"user":"` + user + `","host":"` + host + `","runas_user":"root",` +
		`"runas_uid":0,"runas_gid":0,"cwd":"/home/` + user + `",` +
		`"command":"` + command + `"}` + "\n"
	cast := hdr + `[0.5,"o","output\r\n"]` + "\n"
	if err := os.WriteFile(sessDir+"/session.cast", []byte(cast), 0o644); err != nil {
		t.Fatalf("seedHTTPSession write cast: %v", err)
	}
}
