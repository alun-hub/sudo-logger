package main

// Tests for config.go: loadConfig and expandEscapes.

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ── expandEscapes ─────────────────────────────────────────────────────────────

func TestExpandEscapes(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{`hello`, "hello"},
		{`line1\nline2`, "line1\nline2"},
		{`col1\tcol2`, "col1\tcol2"},
		{`a\nb\tc`, "a\nb\tc"},
		{`no escapes here`, "no escapes here"},
	}
	for _, tt := range tests {
		if got := expandEscapes(tt.in); got != tt.want {
			t.Errorf("expandEscapes(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// ── loadConfig ────────────────────────────────────────────────────────────────

func writeConfigFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "agent.conf")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestLoadConfig_Defaults(t *testing.T) {
	path := writeConfigFile(t, "# empty config, only comments\n\n")
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	def := defaultConfig()
	if cfg.Server != def.Server || cfg.Socket != def.Socket || cfg.FreezeTimeout != def.FreezeTimeout {
		t.Errorf("empty config did not fall back to defaults: got %+v", cfg)
	}
}

func TestLoadConfig_MissingFile(t *testing.T) {
	_, err := loadConfig(filepath.Join(t.TempDir(), "nonexistent.conf"))
	if err == nil {
		t.Error("expected an error for a missing config file")
	}
}

func TestLoadConfig_AllKnownKeys(t *testing.T) {
	content := `server = logserver.internal:9876
socket = /run/custom/plugin.sock
cert = /etc/custom/client.crt
key = /etc/custom/client.key
ca = /etc/custom/ca.crt
verify_key = /etc/custom/verify.key
mask_pattern = password=\S+
mask_pattern = token=\S+
freeze_timeout = 5m
idle_timeout = 10m
debug = true
disclaimer = Line1\nLine2
disclaimer_color = yellow
ebpf = false
sandbox_config = /etc/custom/sandbox.yaml
hostname = custom-host
`
	path := writeConfigFile(t, content)
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.Server != "logserver.internal:9876" {
		t.Errorf("Server = %q", cfg.Server)
	}
	if cfg.Socket != "/run/custom/plugin.sock" {
		t.Errorf("Socket = %q", cfg.Socket)
	}
	if len(cfg.MaskPatterns) != 2 {
		t.Errorf("MaskPatterns = %v, want 2 entries", cfg.MaskPatterns)
	}
	if cfg.FreezeTimeout != 5*time.Minute {
		t.Errorf("FreezeTimeout = %v, want 5m", cfg.FreezeTimeout)
	}
	if cfg.IdleTimeout != 10*time.Minute {
		t.Errorf("IdleTimeout = %v, want 10m", cfg.IdleTimeout)
	}
	if !cfg.Debug {
		t.Error("Debug should be true")
	}
	if cfg.Disclaimer != "Line1\nLine2" {
		t.Errorf("Disclaimer = %q, want escapes expanded", cfg.Disclaimer)
	}
	if cfg.Ebpf {
		t.Error("Ebpf should be false")
	}
	if cfg.Hostname != "custom-host" {
		t.Errorf("Hostname = %q", cfg.Hostname)
	}
}

func TestLoadConfig_LegacyLogserverKeyAlias(t *testing.T) {
	path := writeConfigFile(t, "LOGSERVER = legacy-server:9876\n")
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.Server != "legacy-server:9876" {
		t.Errorf("Server = %q, want the LOGSERVER alias to populate it", cfg.Server)
	}
}

func TestLoadConfig_UnknownKeyIgnored(t *testing.T) {
	path := writeConfigFile(t, "totally_unknown_key = some value\nserver = real-server:9876\n")
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig should silently ignore unknown keys, got error: %v", err)
	}
	if cfg.Server != "real-server:9876" {
		t.Errorf("Server = %q", cfg.Server)
	}
}

func TestLoadConfig_MissingEquals(t *testing.T) {
	path := writeConfigFile(t, "this line has no equals sign\n")
	if _, err := loadConfig(path); err == nil {
		t.Error("expected an error for a line missing '='")
	}
}

func TestLoadConfig_InvalidDuration(t *testing.T) {
	path := writeConfigFile(t, "freeze_timeout = not-a-duration\n")
	if _, err := loadConfig(path); err == nil {
		t.Error("expected an error for an invalid freeze_timeout duration")
	}
}

func TestLoadConfig_InlineComment(t *testing.T) {
	path := writeConfigFile(t, "server = myserver:9876 # trailing comment\n")
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.Server != "myserver:9876" {
		t.Errorf("Server = %q, want inline comment stripped", cfg.Server)
	}
}

func TestLoadConfig_DebugFalseyValues(t *testing.T) {
	for _, v := range []string{"false", "0", "no", ""} {
		path := writeConfigFile(t, "debug = "+v+"\n")
		cfg, err := loadConfig(path)
		if err != nil {
			t.Fatalf("loadConfig(debug=%q): %v", v, err)
		}
		if cfg.Debug {
			t.Errorf("debug=%q should not enable Debug", v)
		}
	}
}
