package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"sudo-logger/internal/config"
)

func TestResolveSecret_FlagValueWins(t *testing.T) {
	t.Setenv("SUDO_TEST_A", "from-env")
	got, err := config.ResolveSecret("from-flag", "", "SUDO_TEST_A")
	if err != nil || got != "from-flag" {
		t.Errorf("got %q, %v — want from-flag", got, err)
	}
}

func TestResolveSecret_EnvFallback(t *testing.T) {
	t.Setenv("SUDO_TEST_B", "from-env")
	got, err := config.ResolveSecret("", "", "SUDO_TEST_B")
	if err != nil || got != "from-env" {
		t.Errorf("got %q, %v — want from-env", got, err)
	}
}

func TestResolveSecret_FileFallback(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(f, []byte("file-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := config.ResolveSecret("", f, "SUDO_TEST_UNSET_XYZ")
	if err != nil || got != "file-secret" {
		t.Errorf("got %q, %v — want file-secret", got, err)
	}
}

func TestResolveSecret_FileTrimsCRLF(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "secret.txt")
	os.WriteFile(f, []byte("trimme\r\n"), 0o600)
	got, _ := config.ResolveSecret("", f, "")
	if got != "trimme" {
		t.Errorf("got %q — want trimme (no CRLF)", got)
	}
}

func TestResolveSecret_MissingFile(t *testing.T) {
	_, err := config.ResolveSecret("", "/nonexistent/secret.txt", "")
	if err == nil {
		t.Error("expected error for missing file, got nil")
	}
}

func TestResolveSecret_AllEmpty(t *testing.T) {
	got, err := config.ResolveSecret("", "", "SUDO_TEST_DEFINITELY_UNSET_12345")
	if err != nil || got != "" {
		t.Errorf("got %q, %v — want empty string", got, err)
	}
}

func TestResolveSecret_FlagBeatsFile(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "secret.txt")
	os.WriteFile(f, []byte("file-value"), 0o600)
	got, err := config.ResolveSecret("flag-value", f, "")
	if err != nil || got != "flag-value" {
		t.Errorf("got %q, %v — want flag-value", got, err)
	}
}

func TestResolveSecret_EnvBeatsFile(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "secret.txt")
	os.WriteFile(f, []byte("file-value"), 0o600)
	t.Setenv("SUDO_TEST_C", "env-value")
	got, err := config.ResolveSecret("", f, "SUDO_TEST_C")
	if err != nil || got != "env-value" {
		t.Errorf("got %q, %v — want env-value", got, err)
	}
}
