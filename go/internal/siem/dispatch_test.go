package siem

// Tests for the Send/SendAudit dispatcher entry points, the buildTLSConfig
// safe-root allowlist success path, and the Load/Set/Get/reloadConfig
// config lifecycle.

import (
	"io"
	"os"
	"strings"
	"testing"
)

// captureStdout redirects os.Stdout for the duration of fn and returns
// everything written to it.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w
	fn()
	w.Close()
	os.Stdout = orig
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read captured stdout: %v", err)
	}
	return string(out)
}

func resetSiemConfig(t *testing.T) {
	t.Helper()
	t.Cleanup(func() { Set(Config{}) })
}

// ── Send dispatcher ───────────────────────────────────────────────────────────

func TestSend_DisabledIsNoop(t *testing.T) {
	resetSiemConfig(t)
	Set(Config{Enabled: false, Transport: "stdout", Format: "json"})

	out := captureStdout(t, func() { Send(testEvent()) })
	if out != "" {
		t.Errorf("Send with Enabled=false should not write anything, got: %q", out)
	}
}

func TestSend_StdoutTransport(t *testing.T) {
	resetSiemConfig(t)
	Set(Config{Enabled: true, Transport: "stdout", Format: "json"})

	out := captureStdout(t, func() { Send(testEvent()) })
	if !strings.Contains(out, `"session_id":"sess-1"`) {
		t.Errorf("stdout output missing expected session_id, got: %q", out)
	}
}

func TestSend_ReplayURLBaseAppendsTSID(t *testing.T) {
	resetSiemConfig(t)
	Set(Config{Enabled: true, Transport: "stdout", Format: "json", ReplayURLBase: "https://replay.example.com"})

	out := captureStdout(t, func() { Send(testEvent()) })
	want := `"replay_url":"https://replay.example.com/?tsid=alice%2Fhost1_20260415-120000"`
	if !strings.Contains(out, want) {
		t.Errorf("stdout output missing constructed replay_url.\ngot:  %q\nwant substring: %q", out, want)
	}
}

func TestSend_UnknownTransportDoesNotPanicOrWrite(t *testing.T) {
	resetSiemConfig(t)
	Set(Config{Enabled: true, Transport: "carrier-pigeon", Format: "json"})

	out := captureStdout(t, func() { Send(testEvent()) })
	if out != "" {
		t.Errorf("unknown transport should not write to stdout, got: %q", out)
	}
}

// ── SendAudit dispatcher ──────────────────────────────────────────────────────

func TestSendAudit_DisabledIsNoop(t *testing.T) {
	resetSiemConfig(t)
	Set(Config{Enabled: false, Transport: "stdout"})

	out := captureStdout(t, func() { SendAudit("user_login", map[string]any{"user": "alice"}) })
	if out != "" {
		t.Errorf("SendAudit with Enabled=false should not write anything, got: %q", out)
	}
}

func TestSendAudit_StdoutTransport(t *testing.T) {
	resetSiemConfig(t)
	Set(Config{Enabled: true, Transport: "stdout"})

	out := captureStdout(t, func() {
		SendAudit("user_login", map[string]any{"user": "alice", "addr": "10.0.0.1"})
	})
	for _, want := range []string{`"event":"user_login"`, `"user":"alice"`, `"addr":"10.0.0.1"`, `"time":"`} {
		if !strings.Contains(out, want) {
			t.Errorf("audit output missing %q, got: %q", want, out)
		}
	}
}

// ── buildTLSConfig safe-root allowlist ────────────────────────────────────────

// TestBuildTLSConfig_CASuccessFromSafeRoot proves the success path of the
// allowlist: a real, pre-existing, world-readable CA bundle under
// /etc/ssl/certs (one of the four permitted roots) must load successfully.
// This deliberately reads an existing system file rather than writing one,
// since none of the four allowed roots are writable by an unprivileged
// test process.
func TestBuildTLSConfig_CASuccessFromSafeRoot(t *testing.T) {
	const systemCABundle = "/etc/ssl/certs/ca-bundle.crt"
	if _, err := os.Stat(systemCABundle); err != nil {
		t.Skipf("system CA bundle not present at %s on this machine: %v", systemCABundle, err)
	}

	cfg, err := buildTLSConfig(TLSCfg{CA: systemCABundle})
	if err != nil {
		t.Fatalf("buildTLSConfig with a CA under the allowed /etc/ssl/certs root: %v", err)
	}
	if cfg.RootCAs == nil {
		t.Error("RootCAs pool should be populated from the loaded CA bundle")
	}
}

func TestBuildTLSConfig_PathOutsideAllowlistRejectedEvenIfExists(t *testing.T) {
	// A real, valid, readable PEM file — but sitting in a temp dir, not
	// under any of the four permitted roots. The allowlist check must
	// reject it purely on path, before ever attempting to read it.
	dir := t.TempDir()
	path := dir + "/ca.pem"
	pem := "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n"
	if err := os.WriteFile(path, []byte(pem), 0o600); err != nil {
		t.Fatalf("write test CA: %v", err)
	}

	_, err := buildTLSConfig(TLSCfg{CA: path})
	if err == nil {
		t.Fatal("expected buildTLSConfig to reject a CA path outside the allowlist even though the file exists")
	}
	if !strings.Contains(err.Error(), "prohibited path") {
		t.Errorf("error = %v, want it to mention the prohibited-path rejection", err)
	}
}

// ── Load / Set / Get / reloadConfig lifecycle ────────────────────────────────

func TestSetAndGet_Roundtrip(t *testing.T) {
	resetSiemConfig(t)
	Set(Config{Enabled: true, Transport: "https", Format: "cef"})
	got := Get()
	if !got.Enabled || got.Transport != "https" || got.Format != "cef" {
		t.Errorf("Get() after Set() = %+v, want the set values back", got)
	}
}

func TestLoad_MissingFileIsNonFatal(t *testing.T) {
	resetSiemConfig(t)
	// Load must not panic when the file doesn't exist yet — SIEM forwarding
	// simply stays disabled until the file is created.
	Load(t.TempDir() + "/does-not-exist.yaml")
	got := Get()
	if got.Enabled {
		t.Error("Get() after Load() of a missing file should report Enabled=false")
	}
}

func TestReloadConfig_LoadsFileContent(t *testing.T) {
	resetSiemConfig(t)
	dir := t.TempDir()
	path := dir + "/siem.yaml"
	if err := os.WriteFile(path, []byte("enabled: true\ntransport: stdout\nformat: json\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	origPath, origMtime := cfgPath, cfgMtime
	cfgPath = path
	t.Cleanup(func() { cfgPath, cfgMtime = origPath, origMtime })

	if err := reloadConfig(); err != nil {
		t.Fatalf("reloadConfig: %v", err)
	}
	got := Get()
	if !got.Enabled || got.Transport != "stdout" || got.Format != "json" {
		t.Errorf("Get() after reloadConfig = %+v, want the file's content", got)
	}
}

// TestReloadConfig_MtimeGatedNoop verifies the hot-reload caching: calling
// reloadConfig() again against an unchanged file (same mtime) must not
// re-parse and overwrite the in-memory config, even if something else
// changed it in between.
func TestReloadConfig_MtimeGatedNoop(t *testing.T) {
	resetSiemConfig(t)
	dir := t.TempDir()
	path := dir + "/siem.yaml"
	if err := os.WriteFile(path, []byte("enabled: true\ntransport: stdout\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	origPath, origMtime := cfgPath, cfgMtime
	cfgPath = path
	t.Cleanup(func() { cfgPath, cfgMtime = origPath, origMtime })

	if err := reloadConfig(); err != nil {
		t.Fatalf("reloadConfig (initial): %v", err)
	}

	// Manually set a sentinel value distinguishable from the file's content.
	Set(Config{Enabled: true, Transport: "sentinel-value"})

	// The file on disk has not changed — this call must be a no-op and must
	// not clobber the sentinel value we just set.
	if err := reloadConfig(); err != nil {
		t.Fatalf("reloadConfig (unchanged): %v", err)
	}
	got := Get()
	if got.Transport != "sentinel-value" {
		t.Errorf("reloadConfig re-parsed an unchanged file: got transport=%q, want the sentinel preserved", got.Transport)
	}
}
