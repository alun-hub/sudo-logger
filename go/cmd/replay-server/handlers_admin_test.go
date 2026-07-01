package main

// Tests for the risk-scoring engine: matchPattern, matchesRule, stripANSI,
// parseTtyOut/loadTtyOut, loadRules.

import (
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"sudo-logger/internal/store"
)

// ── matchPattern ──────────────────────────────────────────────────────────────

func TestMatchPattern(t *testing.T) {
	tests := []struct {
		name string
		p    *MatchPattern
		text string
		want bool
	}{
		{
			name: "no conditions matches anything",
			p:    &MatchPattern{},
			text: "anything at all",
			want: true,
		},
		{
			name: "contains_any only, match",
			p:    &MatchPattern{ContainsAny: []string{"foo", "bar"}},
			text: "line one\nline with bar in it\n",
			want: true,
		},
		{
			name: "contains_any only, no match",
			p:    &MatchPattern{ContainsAny: []string{"foo", "bar"}},
			text: "nothing relevant here",
			want: false,
		},
		{
			name: "also_any only, match",
			p:    &MatchPattern{AlsoAny: []string{"stop", "disable"}},
			text: "please stop now",
			want: true,
		},
		{
			name: "also_any only, no match",
			p:    &MatchPattern{AlsoAny: []string{"stop", "disable"}},
			text: "please continue",
			want: false,
		},
		{
			name: "both groups co-occur on the same line",
			p:    &MatchPattern{ContainsAny: []string{"sudo-log"}, AlsoAny: []string{"stop"}},
			text: "unrelated first line\nsystemctl stop sudo-logger-agent now\nother line",
			want: true,
		},
		{
			name: "both groups present but on different lines must not match",
			p:    &MatchPattern{ContainsAny: []string{"sudo-log"}, AlsoAny: []string{"stop"}},
			text: "sudo-logger-client-1.20.123-1.fc44.x86_64.rpm\nfirewalld.service.d/refuse-stop.conf",
			want: false,
		},
		{
			name: "case-insensitive on pattern terms",
			p:    &MatchPattern{ContainsAny: []string{"SUDO-LOG"}, AlsoAny: []string{"STOP"}},
			text: "sudo-log and stop on the same line",
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchPattern(tt.p, tt.text); got != tt.want {
				t.Errorf("matchPattern(%+v, %q) = %v, want %v", tt.p, tt.text, got, tt.want)
			}
		})
	}
}

// ── matchesRule ───────────────────────────────────────────────────────────────

// TestMatchesRule_CrossLineWordsDoNotMatch reconstructs the real false
// positive: an `ls` line naming a sudo-logger RPM and an unrelated `dmesg`
// line mentioning a stopped service jointly satisfied a "sudo-logger
// stopped or disabled" rule even though no single line said both things.
func TestMatchesRule_CrossLineWordsDoNotMatch(t *testing.T) {
	rule := Rule{
		ID:     "stop_sudo_logger",
		Score:  50,
		Reason: "sudo-logger stopped or disabled",
		Content: &MatchPattern{
			ContainsAny: []string{"sudo-log", "sudolog"},
			AlsoAny:     []string{"stop", "disable", "kill", "purge", "uninstall"},
		},
	}
	s := &SessionInfo{Command: "bash"}
	content := "sudo-logger-client-1.20.123-1.fc44.x86_64.rpm\n" +
		"systemd[1]: /etc/systemd/system/firewalld.service.d/refuse-stop.conf: unknown key\n"
	getContent := func() string { return content }

	if matchesRule(rule, s, "bash", "bash", getContent) {
		t.Error("rule matched even though the two keywords are on different lines")
	}
}

// TestMatchesRule_SameLineDoesMatch is the positive control for the above:
// when the same two keywords co-occur on one line, the rule must still fire.
func TestMatchesRule_SameLineDoesMatch(t *testing.T) {
	rule := Rule{
		Content: &MatchPattern{
			ContainsAny: []string{"sudo-log"},
			AlsoAny:     []string{"stop"},
		},
	}
	s := &SessionInfo{Command: "bash"}
	content := "systemctl stop sudo-logger-agent\n"
	getContent := func() string { return content }

	if !matchesRule(rule, s, "bash", "bash", getContent) {
		t.Error("rule did not match when both keywords co-occur on the same line")
	}
}

func TestMatchesRule_Source(t *testing.T) {
	rule := Rule{Source: "ebpf-tty"}
	s := &SessionInfo{Source: "plugin"}
	if matchesRule(rule, s, "", "", func() string { return "" }) {
		t.Error("source mismatch should not match")
	}
	s.Source = "ebpf-tty"
	if !matchesRule(rule, s, "", "", func() string { return "" }) {
		t.Error("matching source should match")
	}
}

func TestMatchesRule_ExitCode(t *testing.T) {
	var want int32 = 1
	rule := Rule{ExitCode: &want}
	s := &SessionInfo{ExitCode: 0}
	if matchesRule(rule, s, "", "", func() string { return "" }) {
		t.Error("exit code mismatch should not match")
	}
	s.ExitCode = 1
	if !matchesRule(rule, s, "", "", func() string { return "" }) {
		t.Error("matching exit code should match")
	}
}

func TestMatchesRule_IncompleteXORNetworkOutage(t *testing.T) {
	incomplete := true
	rule := Rule{Incomplete: &incomplete}

	// Agent-killed (incomplete, no network outage) counts as incomplete.
	s := &SessionInfo{Incomplete: true, NetworkOutage: false}
	if !matchesRule(rule, s, "", "", func() string { return "" }) {
		t.Error("agent-killed session should count as incomplete")
	}

	// Network-outage-terminated session is treated as NOT incomplete for
	// risk-scoring purposes (it's a network event, not a security incident).
	s = &SessionInfo{Incomplete: true, NetworkOutage: true}
	if matchesRule(rule, s, "", "", func() string { return "" }) {
		t.Error("network-outage session should not count as incomplete")
	}
}

func TestMatchesRule_AfterHours(t *testing.T) {
	afterHours := true
	rule := Rule{AfterHours: &afterHours}

	night := time.Date(2026, 1, 1, 3, 0, 0, 0, time.Local)
	s := &SessionInfo{StartTime: night.Unix()}
	if !matchesRule(rule, s, "", "", func() string { return "" }) {
		t.Error("3am session should be after-hours")
	}

	noon := time.Date(2026, 1, 1, 12, 0, 0, 0, time.Local)
	s = &SessionInfo{StartTime: noon.Unix()}
	if matchesRule(rule, s, "", "", func() string { return "" }) {
		t.Error("noon session should not be after-hours")
	}
}

func TestMatchesRule_MinDuration(t *testing.T) {
	rule := Rule{MinDuration: 100}
	s := &SessionInfo{Duration: 50}
	if matchesRule(rule, s, "", "", func() string { return "" }) {
		t.Error("duration below min_duration should not match")
	}
	s.Duration = 150
	if !matchesRule(rule, s, "", "", func() string { return "" }) {
		t.Error("duration above min_duration should match")
	}
}

func TestMatchesRule_RunasCaseInsensitive(t *testing.T) {
	rule := Rule{Runas: "root"}
	s := &SessionInfo{Runas: "ROOT"}
	if !matchesRule(rule, s, "", "", func() string { return "" }) {
		t.Error("runas comparison should be case-insensitive")
	}
	s.Runas = "deploy"
	if matchesRule(rule, s, "", "", func() string { return "" }) {
		t.Error("mismatched runas should not match")
	}
}

func TestMatchesRule_ORGroupCommandBaseAny(t *testing.T) {
	rule := Rule{CommandBaseAny: []string{"bash", "sh"}}
	s := &SessionInfo{}
	if !matchesRule(rule, s, "bash", "bash", func() string { return "" }) {
		t.Error("command_base_any should match on cmdBase")
	}
	if matchesRule(rule, s, "vim", "vim", func() string { return "" }) {
		t.Error("command_base_any should not match unrelated cmdBase")
	}
}

func TestMatchesRule_ORGroupNoneMatch(t *testing.T) {
	rule := Rule{
		CommandBaseAny: []string{"bash"},
		Command:        &MatchPattern{ContainsAny: []string{"visudo"}},
		Content:        &MatchPattern{ContainsAny: []string{"passwd"}},
	}
	s := &SessionInfo{}
	if matchesRule(rule, s, "vim /etc/hosts", "vim", func() string { return "empty" }) {
		t.Error("rule should not match when none of command_base_any/command/content match")
	}
}

func TestMatchesRule_NoORGroupConditionsAlwaysMatchesCommand(t *testing.T) {
	// A rule with only metadata conditions (no command_base_any/command/content)
	// should match purely on the AND-conditions.
	rule := Rule{Runas: "root"}
	s := &SessionInfo{Runas: "root"}
	if !matchesRule(rule, s, "anything", "anything", func() string { return "" }) {
		t.Error("rule with no OR-group conditions should match on metadata alone")
	}
}

// TestMatchesRule_ContentNotLoadedWhenNoContentRule verifies the laziness
// contract real callers rely on: getContent must not be invoked unless the
// rule actually has a Content pattern, since loading it means reading the
// full TTY recording from the store.
func TestMatchesRule_ContentNotLoadedWhenNoContentRule(t *testing.T) {
	rule := Rule{CommandBaseAny: []string{"bash"}}
	s := &SessionInfo{}
	called := false
	getContent := func() string {
		called = true
		return ""
	}
	matchesRule(rule, s, "bash", "bash", getContent)
	if called {
		t.Error("getContent should not be called when the rule has no content pattern")
	}
}

// ── stripANSI ─────────────────────────────────────────────────────────────────

func TestStripANSI(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"no escapes", "plain text", "plain text"},
		{"color codes stripped", "\x1b[31mred\x1b[0m text", "red text"},
		{"cursor movement stripped", "a\x1b[2Kb", "ab"},
		{"multiple sequences", "\x1b[1;31mbold red\x1b[0m normal", "bold red normal"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := stripANSI(tt.in); got != tt.want {
				t.Errorf("stripANSI(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// ── parseTtyOut ───────────────────────────────────────────────────────────────

func TestParseTtyOut(t *testing.T) {
	cast := `{"version":2,"width":80,"height":24}` + "\n" +
		`[0.1,"o","Hello "]` + "\n" +
		`[0.2,"i","ignored input event"]` + "\n" +
		`not json at all` + "\n" +
		`[0.3,"o","WORLD"]` + "\n"
	got := parseTtyOut(strings.NewReader(cast))
	want := "hello world"
	if got != want {
		t.Errorf("parseTtyOut = %q, want %q", got, want)
	}
}

func TestParseTtyOut_EmptyInput(t *testing.T) {
	if got := parseTtyOut(strings.NewReader("")); got != "" {
		t.Errorf("parseTtyOut of empty input = %q, want empty", got)
	}
}

func TestParseTtyOut_OnlyHeaderLine(t *testing.T) {
	cast := `{"version":2,"width":80,"height":24}` + "\n"
	if got := parseTtyOut(strings.NewReader(cast)); got != "" {
		t.Errorf("parseTtyOut with only a header line = %q, want empty", got)
	}
}

func TestParseTtyOut_RespectsMaxBytesCap(t *testing.T) {
	var sb strings.Builder
	sb.WriteString(`{"version":2}` + "\n")
	// Each event contributes ~10 bytes; write far more than maxTtyOutBytes.
	chunk := strings.Repeat("x", 100)
	for i := 0; i < (maxTtyOutBytes/100)+50; i++ {
		sb.WriteString(`[0.1,"o","` + chunk + `"]` + "\n")
	}
	got := parseTtyOut(strings.NewReader(sb.String()))
	// The cap is checked before each append, so the result can exceed the
	// cap by at most one chunk's worth of bytes.
	if len(got) < maxTtyOutBytes {
		t.Errorf("parseTtyOut result too short: %d bytes, want at least %d", len(got), maxTtyOutBytes)
	}
	if len(got) > maxTtyOutBytes+len(chunk) {
		t.Errorf("parseTtyOut result too long: %d bytes, want at most %d", len(got), maxTtyOutBytes+len(chunk))
	}
}

// ── loadTtyOut ────────────────────────────────────────────────────────────────

func TestLoadTtyOut(t *testing.T) {
	dir := t.TempDir()
	var err error
	sessionStore, err = store.New(testStoreConfig(dir))
	if err != nil {
		t.Fatalf("init test store: %v", err)
	}
	t.Cleanup(func() { sessionStore.Close() })
	resetTestCaches(t)

	seedCastWithOutput(t, dir, "alice", "host1", "SUDO-LOG output\nSTOP here\n")
	tsid := "alice/host1_20260415-120000"

	got := loadTtyOut(t.Context(), tsid)
	if !strings.Contains(got, "sudo-log") {
		t.Errorf("loadTtyOut result missing expected content, got: %q", got)
	}
}

func TestLoadTtyOut_MissingSession(t *testing.T) {
	initTestStore(t)
	if got := loadTtyOut(t.Context(), "nobody/nowhere_20260101-000000"); got != "" {
		t.Errorf("loadTtyOut for missing session = %q, want empty", got)
	}
}

// seedCastWithOutput writes a minimal session.cast with a single "o" event
// carrying the given raw output text, at the fixed TSID
// "<user>/<host>_20260415-120000", matching seedHTTPSession's layout.
func seedCastWithOutput(t *testing.T, logDir, user, host, output string) {
	t.Helper()
	ts := "20260415-120000"
	sessDir := logDir + "/" + user + "/" + host + "_" + ts
	if err := os.MkdirAll(sessDir, 0o755); err != nil {
		t.Fatalf("seedCastWithOutput mkdirall: %v", err)
	}
	hdr := `{"version":2,"width":220,"height":50,"timestamp":1744718400,` +
		`"session_id":"` + host + `-` + user + `",` +
		`"user":"` + user + `","host":"` + host + `","runas_user":"root",` +
		`"runas_uid":0,"runas_gid":0,"cwd":"/home/` + user + `",` +
		`"command":"bash"}` + "\n"
	line := `[0.5,"o",` + strconv.Quote(output) + `]` + "\n"
	cast := hdr + line
	if err := os.WriteFile(sessDir+"/session.cast", []byte(cast), 0o644); err != nil {
		t.Fatalf("seedCastWithOutput write cast: %v", err)
	}
}

// ── loadRules ─────────────────────────────────────────────────────────────────

func TestLoadRules_ReloadsOnChange(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/risk-rules.yaml"

	rulesMu.Lock()
	globalRules = nil
	globalRulesHash = ""
	rulesMu.Unlock()

	if err := os.WriteFile(path, []byte("rules:\n  - id: r1\n    score: 10\n    reason: test\n"), 0o644); err != nil {
		t.Fatalf("write rules file: %v", err)
	}
	if err := loadRules(path); err != nil {
		t.Fatalf("loadRules: %v", err)
	}
	rulesMu.RLock()
	n := len(globalRules)
	hash1 := globalRulesHash
	rulesMu.RUnlock()
	if n != 1 {
		t.Fatalf("expected 1 rule loaded, got %d", n)
	}

	// Re-loading unchanged content must be a no-op (same hash).
	if err := loadRules(path); err != nil {
		t.Fatalf("loadRules (unchanged): %v", err)
	}
	rulesMu.RLock()
	hash2 := globalRulesHash
	rulesMu.RUnlock()
	if hash1 != hash2 {
		t.Error("hash changed on reload of unchanged content")
	}

	// Changing content must update the globals.
	if err := os.WriteFile(path, []byte("rules:\n  - id: r1\n    score: 10\n    reason: test\n  - id: r2\n    score: 20\n    reason: test2\n"), 0o644); err != nil {
		t.Fatalf("rewrite rules file: %v", err)
	}
	if err := loadRules(path); err != nil {
		t.Fatalf("loadRules (changed): %v", err)
	}
	rulesMu.RLock()
	n2 := len(globalRules)
	rulesMu.RUnlock()
	if n2 != 2 {
		t.Errorf("expected 2 rules after reload, got %d", n2)
	}
}

func TestLoadRules_MissingFile(t *testing.T) {
	if err := loadRules("/nonexistent/path/risk-rules.yaml"); err == nil {
		t.Error("expected error for missing rules file")
	}
}
