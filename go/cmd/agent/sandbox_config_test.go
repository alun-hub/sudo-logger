package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ── featureDefault / featureDefaultFalse ─────────────────────────────────────

func TestFeatureDefault(t *testing.T) {
	bTrue := true
	bFalse := false

	if !featureDefault(nil) {
		t.Error("nil → want true")
	}
	if !featureDefault(&bTrue) {
		t.Error("&true → want true")
	}
	if featureDefault(&bFalse) {
		t.Error("&false → want false")
	}
}

func TestFeatureDefaultFalse(t *testing.T) {
	bTrue := true
	bFalse := false

	if featureDefaultFalse(nil) {
		t.Error("nil → want false")
	}
	if !featureDefaultFalse(&bTrue) {
		t.Error("&true → want true")
	}
	if featureDefaultFalse(&bFalse) {
		t.Error("&false → want false")
	}
}

// ── sigName ───────────────────────────────────────────────────────────────────

func TestSigName(t *testing.T) {
	cases := []struct {
		sig  uint32
		want string
	}{
		{1, "SIGHUP"},
		{2, "SIGINT"},
		{3, "SIGQUIT"},
		{9, "SIGKILL"},
		{11, "SIGSEGV"},
		{15, "SIGTERM"},
		{17, "SIGCHLD"},
		{19, "SIGSTOP"},
		{0, "SIG0"},   // unknown → SIG%d
		{99, "SIG99"}, // unknown → SIG%d
	}
	for _, tc := range cases {
		got := sigName(tc.sig)
		if got != tc.want {
			t.Errorf("sigName(%d) = %q, want %q", tc.sig, got, tc.want)
		}
	}
}

// ── mountDev ─────────────────────────────────────────────────────────────────

func TestMountDev_RootExists(t *testing.T) {
	dev, err := mountDev("/")
	if err != nil {
		t.Fatalf("mountDev(/): %v", err)
	}
	if dev == 0 {
		t.Error("mountDev(/) returned dev=0 — expected a non-zero device number")
	}
}

func TestMountDev_TmpExists(t *testing.T) {
	dev, err := mountDev("/tmp")
	if err != nil {
		t.Fatalf("mountDev(/tmp): %v", err)
	}
	_ = dev // value is filesystem-dependent; just verify no error
}

func TestMountDev_NonExistentPath(t *testing.T) {
	// A deeply nested non-existent path still matches the root mount entry.
	// What matters is that the function returns without panicking.
	_, _ = mountDev("/nonexistent/path/abc")
}

// ── resolveInodeKey ───────────────────────────────────────────────────────────

func TestResolveInodeKey_ExistingPath(t *testing.T) {
	dir := t.TempDir()
	key, ok := resolveInodeKey(dir)
	if !ok {
		t.Fatalf("resolveInodeKey(%s): expected ok=true", dir)
	}
	if key.Ino == 0 {
		t.Error("expected non-zero inode")
	}
}

func TestResolveInodeKey_NonExistentPath(t *testing.T) {
	_, ok := resolveInodeKey("/nonexistent/path/xyz_abc")
	if ok {
		t.Error("expected ok=false for non-existent path")
	}
}

// ── loadSandboxConfigFromBytes ────────────────────────────────────────────────

func TestLoadSandboxConfig_InvalidYAML(t *testing.T) {
	_, err := loadSandboxConfigFromBytes([]byte("{unclosed"))
	if err == nil {
		t.Error("expected error for invalid YAML, got nil")
	}
}

func TestLoadSandboxConfig_EnabledFalse(t *testing.T) {
	yaml := `enabled: false`
	res, err := loadSandboxConfigFromBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Enforcement disabled — all inode sets should be empty.
	if len(res.Inodes) != 0 || len(res.Forbidden) != 0 || len(res.Noexec) != 0 {
		t.Errorf("expected empty inode sets when enabled=false, got Inodes=%d Forbidden=%d Noexec=%d",
			len(res.Inodes), len(res.Forbidden), len(res.Noexec))
	}
}

func TestLoadSandboxConfig_DefaultFeatures(t *testing.T) {
	// Empty config → all deny_* defaults to true except deny_systemd_ipc.
	res, err := loadSandboxConfigFromBytes([]byte("{}"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	f := res.Features
	checks := []struct {
		name string
		got  bool
		want bool
	}{
		{"DenyNetlink", f.DenyNetlink, true},
		{"DenyMount", f.DenyMount, true},
		{"DenyPtrace", f.DenyPtrace, true},
		{"DenyCapAuditControl", f.DenyCapAuditControl, true},
		{"DenyCapNetAdmin", f.DenyCapNetAdmin, true},
		{"DenyCapSysModule", f.DenyCapSysModule, true},
		{"DenyCapMacAdmin", f.DenyCapMacAdmin, true},
		{"DenyCapSysRawio", f.DenyCapSysRawio, true},
		{"DenyCapSysBoot", f.DenyCapSysBoot, true},
		{"DenySystemdIPC", f.DenySystemdIPC, false}, // default false
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("Feature %s: got %v, want %v", c.name, c.got, c.want)
		}
	}
}

func TestLoadSandboxConfig_ExplicitFeatureOverride(t *testing.T) {
	yaml := `
features:
  deny_netlink: false
  deny_ptrace: false
  deny_systemd_ipc: true
`
	res, err := loadSandboxConfigFromBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Features.DenyNetlink {
		t.Error("DenyNetlink: expected false (overridden)")
	}
	if res.Features.DenyPtrace {
		t.Error("DenyPtrace: expected false (overridden)")
	}
	if !res.Features.DenySystemdIPC {
		t.Error("DenySystemdIPC: expected true (overridden)")
	}
	// Unmentioned flags keep their default (true).
	if !res.Features.DenyMount {
		t.Error("DenyMount: expected true (default)")
	}
}

func TestLoadSandboxConfig_ProcessesTruncation(t *testing.T) {
	yaml := `
protect:
  processes:
    - short
    - exactlyfifteen
    - toolongprocessname
`
	res, err := loadSandboxConfigFromBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Processes) != 3 {
		t.Fatalf("expected 3 processes, got %d", len(res.Processes))
	}
	if res.Processes[0] != "short" {
		t.Errorf("processes[0] = %q, want %q", res.Processes[0], "short")
	}
	if res.Processes[1] != "exactlyfifteen" {
		t.Errorf("processes[1] = %q, want %q", res.Processes[1], "exactlyfifteen")
	}
	if len(res.Processes[2]) > 15 {
		t.Errorf("processes[2] not truncated: %q (%d chars)", res.Processes[2], len(res.Processes[2]))
	}
	if !strings.HasPrefix("toolongprocessname", res.Processes[2]) {
		t.Errorf("processes[2] = %q — should be prefix of original", res.Processes[2])
	}
}

func TestLoadSandboxConfig_NonAbsolutePath(t *testing.T) {
	yaml := `
protect:
  files:
    - relative/path/file.txt
    - ../traversal
`
	res, err := loadSandboxConfigFromBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Non-absolute paths are skipped — PathInodes should be empty.
	if len(res.PathInodes) != 0 {
		t.Errorf("expected no path inodes for non-absolute paths, got %d", len(res.PathInodes))
	}
}

func TestLoadSandboxConfig_ExistingFileProtected(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "protected.txt")
	if err := os.WriteFile(f, []byte("secret"), 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	yaml := "protect:\n  files:\n    - " + f + "\n"
	res, err := loadSandboxConfigFromBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	key, ok := res.PathInodes[f]
	if !ok {
		t.Fatalf("expected path %s to be in PathInodes", f)
	}
	if key.Ino == 0 {
		t.Error("expected non-zero inode for protected file")
	}
	if len(res.Inodes) == 0 {
		t.Error("expected at least one inode in Inodes slice")
	}
}

func TestLoadSandboxConfig_DirectoryRecursion(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o750); err != nil {
		t.Fatalf("mkdir sub: %v", err)
	}
	f := filepath.Join(sub, "file.txt")
	os.WriteFile(f, []byte("data"), 0o600)

	yaml := "protect:\n  files:\n    - " + dir + "\n"
	res, err := loadSandboxConfigFromBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// The top-level dir and its subdirectory should be protected.
	if _, ok := res.PathInodes[dir]; !ok {
		t.Errorf("expected %s in PathInodes", dir)
	}
	if _, ok := res.PathInodes[sub]; !ok {
		t.Errorf("expected subdirectory %s in PathInodes", sub)
	}
}

func TestLoadSandboxConfig_NonExistentFileSkipped(t *testing.T) {
	yaml := `
protect:
  files:
    - /nonexistent/path/that/does/not/exist
`
	res, err := loadSandboxConfigFromBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.PathInodes) != 0 {
		t.Errorf("expected non-existent paths to be skipped, got %d path inodes", len(res.PathInodes))
	}
}

func TestLoadSandboxConfig_ForbiddenBinary(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "dangerous-binary")
	os.WriteFile(bin, []byte("#!/bin/sh\nexit 1"), 0o755)

	yaml := "protect:\n  forbidden:\n    - " + bin + "\n"
	res, err := loadSandboxConfigFromBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Forbidden) == 0 {
		t.Error("expected forbidden binary to be resolved into Forbidden slice")
	}
}

func TestLoadSandboxConfig_EmptyYAML(t *testing.T) {
	res, err := loadSandboxConfigFromBytes([]byte(""))
	if err != nil {
		t.Fatalf("unexpected error for empty YAML: %v", err)
	}
	// All defaults: no paths protected, default features applied.
	if len(res.PathInodes) != 0 {
		t.Errorf("expected empty PathInodes for empty config, got %d", len(res.PathInodes))
	}
	if !res.Features.DenyNetlink {
		t.Error("expected DenyNetlink=true for empty config (default)")
	}
}

func TestLoadSandboxConfigFile_MissingFile(t *testing.T) {
	_, err := loadSandboxConfig("/nonexistent/sandbox.yaml")
	if err == nil {
		t.Error("expected error for missing config file, got nil")
	}
}

func TestLoadSandboxConfigFile_ValidFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "sandbox.yaml")
	os.WriteFile(p, []byte("enabled: true\n"), 0o600)

	res, err := loadSandboxConfig(p)
	if err != nil {
		t.Fatalf("loadSandboxConfig: %v", err)
	}
	if !res.Features.DenyMount {
		t.Error("expected DenyMount=true from valid config file")
	}
}
