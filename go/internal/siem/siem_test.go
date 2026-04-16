package siem

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ── Event.FormatJSON ──────────────────────────────────────────────────────────

func TestFormatJSON(t *testing.T) {
	e := testEvent()
	b, err := e.FormatJSON()
	if err != nil {
		t.Fatalf("FormatJSON: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("not valid JSON: %v", err)
	}
	check := map[string]any{
		"session_id": "sess-1",
		"user":       "alice",
		"host":       "host1",
		"runas":      "root",
		"command":    "/bin/bash",
		"exit_code":  float64(0),
		"incomplete": false,
		"risk_score": float64(42),
	}
	for k, want := range check {
		if got := m[k]; got != want {
			t.Errorf("FormatJSON[%q] = %v, want %v", k, got, want)
		}
	}
}

func TestFormatJSONOptionalFields(t *testing.T) {
	e := testEvent()
	e.ReplayURL = "https://replay.example.com/?tsid=alice/host1_20260415-120000"
	e.ResolvedCommand = "/usr/bin/bash"
	e.Flags = "login_shell"
	e.RiskReasons = []string{"high_risk_cmd"}

	b, err := e.FormatJSON()
	if err != nil {
		t.Fatalf("FormatJSON: %v", err)
	}
	var m map[string]any
	json.Unmarshal(b, &m) //nolint:errcheck

	for _, key := range []string{"replay_url", "resolved_command", "flags", "risk_reasons"} {
		if _, ok := m[key]; !ok {
			t.Errorf("FormatJSON: optional field %q missing", key)
		}
	}
}

// ── Event.FormatCEF ───────────────────────────────────────────────────────────

func TestFormatCEFPrefix(t *testing.T) {
	e := testEvent()
	cef := e.FormatCEF()
	if !strings.HasPrefix(cef, "CEF:0|sudo-logger|sudo-logger|1.0|sudo-session|") {
		t.Errorf("FormatCEF prefix wrong: %q", cef[:min(len(cef), 80)])
	}
}

func TestFormatCEFEscaping(t *testing.T) {
	e := testEvent()
	e.Command = `evil\cmd=foo|bar` + "\nnewline"
	cef := e.FormatCEF()
	// None of the unescaped special chars should appear in the extension.
	ext := cef[strings.LastIndex(cef, "|")+1:]
	// Literal pipe not escaped by cefEscape (it's in the extension values) —
	// but the extension field value for dproc must have | escaped to \|.
	if strings.Contains(ext, "evil\\cmd=foo|bar") {
		t.Errorf("CEF extension contains unescaped pipe: %q", ext)
	}
	if strings.Contains(ext, "\n") {
		t.Errorf("CEF extension contains raw newline: %q", ext)
	}
}

func TestFormatCEFSeverityExitZero(t *testing.T) {
	e := testEvent()
	e.ExitCode = 0
	e.Incomplete = false
	cef := e.FormatCEF()
	// Severity 3 (Low) expected: "...| Privileged Command Session|3|..."
	if !strings.Contains(cef, "|3|") {
		t.Errorf("expected severity 3 for success, got: %q", cef)
	}
}

func TestFormatCEFSeverityNonZeroExit(t *testing.T) {
	e := testEvent()
	e.ExitCode = 1
	e.Incomplete = false
	cef := e.FormatCEF()
	if !strings.Contains(cef, "|5|") {
		t.Errorf("expected severity 5 for failed exit, got: %q", cef)
	}
}

func TestFormatCEFSeverityIncomplete(t *testing.T) {
	e := testEvent()
	e.Incomplete = true
	cef := e.FormatCEF()
	if !strings.Contains(cef, "|6|") {
		t.Errorf("expected severity 6 for incomplete, got: %q", cef)
	}
}

// ── Event.FormatOCSF ──────────────────────────────────────────────────────────

func TestFormatOCSFStructure(t *testing.T) {
	e := testEvent()
	b, err := e.FormatOCSF()
	if err != nil {
		t.Fatalf("FormatOCSF: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("OCSF not valid JSON: %v", err)
	}
	if m["class_uid"].(float64) != 3003 {
		t.Errorf("class_uid: got %v, want 3003", m["class_uid"])
	}
	actor, ok := m["actor"].(map[string]any)
	if !ok {
		t.Fatal("OCSF actor field missing or wrong type")
	}
	user, ok := actor["user"].(map[string]any)
	if !ok {
		t.Fatal("OCSF actor.user missing or wrong type")
	}
	if user["name"] != "alice" {
		t.Errorf("actor.user.name: got %v, want alice", user["name"])
	}
}

func TestFormatOCSFStatusSuccess(t *testing.T) {
	e := testEvent()
	e.ExitCode = 0
	e.Incomplete = false
	b, _ := e.FormatOCSF()
	var m map[string]any
	json.Unmarshal(b, &m) //nolint:errcheck
	if m["status"] != "Success" {
		t.Errorf("OCSF status: got %v, want Success", m["status"])
	}
	if m["status_id"].(float64) != 1 {
		t.Errorf("OCSF status_id: got %v, want 1", m["status_id"])
	}
}

func TestFormatOCSFStatusIncomplete(t *testing.T) {
	e := testEvent()
	e.Incomplete = true
	b, _ := e.FormatOCSF()
	var m map[string]any
	json.Unmarshal(b, &m) //nolint:errcheck
	if m["status"] != "Unknown" {
		t.Errorf("OCSF status: got %v, want Unknown", m["status"])
	}
}

// ── syslogPRI ─────────────────────────────────────────────────────────────────

func TestSyslogPRI(t *testing.T) {
	cases := []struct {
		exitCode   int32
		incomplete bool
		want       int
	}{
		{0, false, 10*8 + 5}, // LOG_NOTICE
		{1, false, 10*8 + 4}, // LOG_WARNING
		{0, true, 10*8 + 4},  // LOG_WARNING
	}
	for _, tc := range cases {
		got := syslogPRI(tc.exitCode, tc.incomplete)
		if got != tc.want {
			t.Errorf("syslogPRI(%d,%v) = %d, want %d", tc.exitCode, tc.incomplete, got, tc.want)
		}
	}
}

// ── encodeEvent ───────────────────────────────────────────────────────────────

func TestEncodeEventJSON(t *testing.T) {
	body, ct, err := encodeEvent(testEvent(), "json")
	if err != nil {
		t.Fatalf("encodeEvent json: %v", err)
	}
	if !strings.HasPrefix(ct, "application/json") {
		t.Errorf("content-type: got %q, want application/json", ct)
	}
	if !json.Valid(body) {
		t.Errorf("body not valid JSON")
	}
}

func TestEncodeEventCEF(t *testing.T) {
	body, ct, err := encodeEvent(testEvent(), "cef")
	if err != nil {
		t.Fatalf("encodeEvent cef: %v", err)
	}
	if !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("content-type: got %q, want text/plain", ct)
	}
	if !strings.HasPrefix(string(body), "CEF:0|") {
		t.Errorf("CEF body prefix wrong: %q", string(body)[:min(len(body), 20)])
	}
}

func TestEncodeEventOCSF(t *testing.T) {
	body, ct, err := encodeEvent(testEvent(), "ocsf")
	if err != nil {
		t.Fatalf("encodeEvent ocsf: %v", err)
	}
	if !strings.HasPrefix(ct, "application/json") {
		t.Errorf("content-type: got %q, want application/json", ct)
	}
	if !json.Valid(body) {
		t.Errorf("OCSF body not valid JSON")
	}
}

func TestEncodeEventUnknownFormat(t *testing.T) {
	// Unknown format falls back to JSON.
	body, ct, err := encodeEvent(testEvent(), "unknown")
	if err != nil {
		t.Fatalf("encodeEvent unknown: %v", err)
	}
	if !strings.HasPrefix(ct, "application/json") {
		t.Errorf("fallback content-type: got %q, want application/json", ct)
	}
	if !json.Valid(body) {
		t.Errorf("fallback body not valid JSON")
	}
}

// ── buildTLSConfig ────────────────────────────────────────────────────────────

func TestBuildTLSConfigEmpty(t *testing.T) {
	cfg, err := buildTLSConfig(TLSCfg{})
	if err != nil {
		t.Fatalf("buildTLSConfig empty: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil tls.Config")
	}
}

func TestBuildTLSConfigRelativeCARejected(t *testing.T) {
	_, err := buildTLSConfig(TLSCfg{CA: "relative/path/ca.pem"})
	if err == nil {
		t.Error("expected error for relative CA path")
	}
}

func TestBuildTLSConfigCertWithoutKey(t *testing.T) {
	_, err := buildTLSConfig(TLSCfg{Cert: "/etc/cert.pem"})
	if err == nil {
		t.Error("expected error when cert is set but key is missing")
	}
}

func TestBuildTLSConfigKeyWithoutCert(t *testing.T) {
	_, err := buildTLSConfig(TLSCfg{Key: "/etc/key.pem"})
	if err == nil {
		t.Error("expected error when key is set but cert is missing")
	}
}

func TestBuildTLSConfigRelativeCertRejected(t *testing.T) {
	_, err := buildTLSConfig(TLSCfg{Cert: "relative/cert.pem", Key: "relative/key.pem"})
	if err == nil {
		t.Error("expected error for relative cert/key paths")
	}
}

// ── sendHTTPS SSRF guard ──────────────────────────────────────────────────────

func TestSendHTTPSRejectsNonHTTPS(t *testing.T) {
	cases := []string{
		"http://example.com/log",
		"ftp://example.com",
		"not-a-url",
		"",
	}
	for _, u := range cases {
		cfg := Config{
			Transport: "https",
			Format:    "json",
			HTTPS:     HTTPSCfg{URL: u},
		}
		err := sendHTTPS(cfg, testEvent(), []byte("{}"), "application/json")
		if err == nil {
			t.Errorf("sendHTTPS(%q): expected error for non-https URL, got nil", u)
		}
	}
}

// TestSendHTTPSPostsToServer verifies HTTPS transport against a local test server.
func TestSendHTTPSPostsToServer(t *testing.T) {
	var received []byte
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 4096)
		n, _ := r.Body.Read(buf)
		received = buf[:n]
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Reset the cached client so that our test server's TLS config is used.
	httpsClientMu.Lock()
	httpsClient = srv.Client()
	httpsClientKey = "\t\t" // empty CA/Cert/Key → matches empty TLSCfg paths
	httpsClientMu.Unlock()

	cfg := Config{
		Transport: "https",
		Format:    "json",
		HTTPS:     HTTPSCfg{URL: srv.URL + "/log"},
	}
	body := []byte(`{"session_id":"test"}`)
	if err := sendHTTPS(cfg, testEvent(), body, "application/json"); err != nil {
		t.Fatalf("sendHTTPS: %v", err)
	}
	if string(received) != string(body) {
		t.Errorf("server received %q, want %q", received, body)
	}
}

// TestSendHTTPSBearerToken verifies Authorization header for generic URLs.
func TestSendHTTPSBearerToken(t *testing.T) {
	var authHeader string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	httpsClientMu.Lock()
	httpsClient = srv.Client()
	httpsClientKey = "\t\t"
	httpsClientMu.Unlock()

	cfg := Config{
		Transport: "https",
		Format:    "json",
		HTTPS:     HTTPSCfg{URL: srv.URL + "/ingest", Token: "my-token"},
	}
	if err := sendHTTPS(cfg, testEvent(), []byte("{}"), "application/json"); err != nil {
		t.Fatalf("sendHTTPS: %v", err)
	}
	if authHeader != "Bearer my-token" {
		t.Errorf("Authorization: got %q, want %q", authHeader, "Bearer my-token")
	}
}

// TestSendHTTPSSplunkToken verifies Splunk HEC token prefix.
func TestSendHTTPSSplunkToken(t *testing.T) {
	var authHeader string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	httpsClientMu.Lock()
	httpsClient = srv.Client()
	httpsClientKey = "\t\t"
	httpsClientMu.Unlock()

	cfg := Config{
		Transport: "https",
		Format:    "json",
		HTTPS:     HTTPSCfg{URL: srv.URL + "/services/collector", Token: "splunk-tok"},
	}
	if err := sendHTTPS(cfg, testEvent(), []byte("{}"), "application/json"); err != nil {
		t.Fatalf("sendHTTPS: %v", err)
	}
	if authHeader != "Splunk splunk-tok" {
		t.Errorf("Authorization: got %q, want %q", authHeader, "Splunk splunk-tok")
	}
}

// TestSendHTTPSNon2xxError verifies that a non-2xx response is reported as error.
func TestSendHTTPSNon2xxError(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	httpsClientMu.Lock()
	httpsClient = srv.Client()
	httpsClientKey = "\t\t"
	httpsClientMu.Unlock()

	cfg := Config{
		Transport: "https",
		Format:    "json",
		HTTPS:     HTTPSCfg{URL: srv.URL + "/log"},
	}
	err := sendHTTPS(cfg, testEvent(), []byte("{}"), "application/json")
	if err == nil {
		t.Error("expected error for HTTP 500 response")
	}
}

// ── syslog UDP transport ───────────────────────────────────────────────────────

func TestSendSyslogUDP(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen UDP: %v", err)
	}
	defer pc.Close()
	addr := pc.LocalAddr().String()

	done := make(chan string, 1)
	go func() {
		buf := make([]byte, 4096)
		n, _, _ := pc.ReadFrom(buf)
		done <- string(buf[:n])
	}()

	cfg := Config{
		Transport: "syslog",
		Format:    "json",
		Syslog:    SyslogCfg{Protocol: "udp", Addr: addr},
	}
	body, _, _ := encodeEvent(testEvent(), "json")
	if err := sendSyslog(cfg, testEvent(), body); err != nil {
		t.Fatalf("sendSyslog UDP: %v", err)
	}

	select {
	case msg := <-done:
		if !strings.Contains(msg, "sudo-logger") {
			t.Errorf("UDP syslog missing app-name: %q", msg)
		}
		if !strings.HasPrefix(msg, "<") {
			t.Errorf("UDP syslog missing PRI: %q", msg[:min(len(msg), 20)])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for UDP syslog message")
	}
}

// TestSendSyslogTCP verifies the TCP transport delivers the message.
func TestSendSyslogTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen TCP: %v", err)
	}
	defer ln.Close()

	done := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- ""
			return
		}
		defer conn.Close()
		buf := make([]byte, 4096)
		n, _ := conn.Read(buf)
		done <- string(buf[:n])
	}()

	cfg := Config{
		Transport: "syslog",
		Format:    "json",
		Syslog:    SyslogCfg{Protocol: "tcp", Addr: ln.Addr().String()},
	}
	body, _, _ := encodeEvent(testEvent(), "json")
	if err := sendSyslog(cfg, testEvent(), body); err != nil {
		t.Fatalf("sendSyslog TCP: %v", err)
	}

	select {
	case msg := <-done:
		if !strings.Contains(msg, "sudo-session") {
			t.Errorf("TCP syslog missing MSGID: %q", msg)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for TCP syslog message")
	}
}

func TestSendSyslogUnknownProtocol(t *testing.T) {
	cfg := Config{
		Syslog: SyslogCfg{Protocol: "quic", Addr: "127.0.0.1:9999"},
	}
	if err := sendSyslog(cfg, testEvent(), []byte("{}")); err == nil {
		t.Error("expected error for unknown syslog protocol")
	}
}

// ── getHTTPSClient caching ────────────────────────────────────────────────────

func TestGetHTTPSClientCaching(t *testing.T) {
	// Reset global state.
	httpsClientMu.Lock()
	httpsClient = nil
	httpsClientKey = ""
	httpsClientMu.Unlock()

	tlsCfg := TLSCfg{} // empty — no real files needed
	c1, err := getHTTPSClient(tlsCfg)
	if err != nil {
		t.Fatalf("getHTTPSClient first call: %v", err)
	}
	c2, err := getHTTPSClient(tlsCfg)
	if err != nil {
		t.Fatalf("getHTTPSClient second call: %v", err)
	}
	if c1 != c2 {
		t.Error("expected same *http.Client on repeated calls with same config")
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func testEvent() Event {
	start := time.Date(2026, 4, 15, 12, 0, 0, 0, time.UTC)
	return Event{
		SessionID: "sess-1",
		TSID:      "alice/host1_20260415-120000",
		User:      "alice",
		Host:      "host1",
		RunasUser: "root",
		RunasUID:  0,
		RunasGID:  0,
		Cwd:       "/home/alice",
		Command:   "/bin/bash",
		StartTime: start,
		EndTime:   start.Add(30 * time.Second),
		ExitCode:  0,
		Incomplete: false,
		RiskScore: 42,
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
