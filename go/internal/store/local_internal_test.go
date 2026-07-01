package store

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestUnescapeJSONString(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{`"hello"`, "hello"},
		{`"hello\nworld"`, "hello\nworld"},
		{`"hello\\world"`, "hello\\world"},
		{`"hello\"world"`, "hello\"world"},
		{`"hello\bworld"`, "hello\bworld"},
		{`"hello\fworld"`, "hello\fworld"},
		{`"hello\rworld"`, "hello\rworld"},
		{`"hello\tworld"`, "hello\tworld"},
		{`"hello\u0041world"`, "helloAworld"},
		{`"hello\u000aworld"`, "hello\nworld"},
		{`"hello\xworld"`, `hello\xworld`}, // invalid escape should retain backslash
		{`hello`, `hello`}, // unquoted string should be returned as-is
	}
	for _, tt := range tests {
		got := unescapeJSONString([]byte(tt.input))
		if string(got) != tt.expected {
			t.Errorf("unescapeJSONString(%q) = %q, expected %q", tt.input, string(got), tt.expected)
		}
	}
}

func TestValidSudoersHost(t *testing.T) {
	tests := []struct {
		host  string
		valid bool
	}{
		{"host1", true},
		{"host-a", true},
		{"", false},
		{".host", false},
		{"host/name", false},
		{"host\\name", false},
		{"host..name", false},
		{"..", false},
		{strings.Repeat("a", 256), false},
	}
	for _, tt := range tests {
		if got := validSudoersHost(tt.host); got != tt.valid {
			t.Errorf("validSudoersHost(%q) = %v, expected %v", tt.host, got, tt.valid)
		}
	}
}

// TestSudoersConfigPath_TraversalNeutralized verifies the traversal-prevention
// mechanism backing every sudoers config handler: filepath.Base strips any
// ".." or "/" components from the key's subpath before it is joined onto the
// sudoers config directory, so a malicious key with embedded traversal
// segments can only ever resolve to a plain filename inside that directory.
func TestSudoersConfigPath_TraversalNeutralized(t *testing.T) {
	logDir := t.TempDir()
	ls := &LocalStore{cfg: Config{LogDir: logDir}}
	wantDir := filepath.Join(logDir, ".sudoers-config")

	tests := []struct {
		key      string
		wantBase string
	}{
		{"sudoers/host1", "host1"},
		{"sudoers/../../etc/passwd", "passwd"},
		{"sudoers/../../../../root/.ssh/authorized_keys", "authorized_keys"},
		{"sudoers/foo/bar", "bar"},
	}
	for _, tt := range tests {
		got := ls.sudoersConfigPath(tt.key)
		if filepath.Base(got) != tt.wantBase {
			t.Errorf("sudoersConfigPath(%q) base = %q, want %q (full: %q)", tt.key, filepath.Base(got), tt.wantBase, got)
		}
		if !strings.HasPrefix(got, wantDir+string(filepath.Separator)) {
			t.Errorf("sudoersConfigPath(%q) = %q, escaped the sudoers config dir %q", tt.key, got, wantDir)
		}
	}
}

// TestSudoersConfigPath_BareDotDotEscapesSubdir documents a narrower case:
// a key of exactly "sudoers/.." is NOT reduced to a safe basename —
// filepath.Base("..") returns ".." unchanged, so the joined path collapses
// back to LogDir itself, one level above the intended .sudoers-config
// subdirectory. sudoersConfigPath alone does not fully neutralize this; the
// HTTP handlers (handlePutSudoersConfig/handleDeleteSudoersConfig) are what
// actually block it, by rejecting any host containing ".." before it ever
// reaches this function. This test exists to make that reliance explicit —
// if the handler-level check is ever removed, this is the function that
// would need a matching fix.
func TestSudoersConfigPath_BareDotDotEscapesSubdir(t *testing.T) {
	logDir := t.TempDir()
	ls := &LocalStore{cfg: Config{LogDir: logDir}}

	got := ls.sudoersConfigPath("sudoers/..")
	if got != logDir {
		t.Errorf("sudoersConfigPath(\"sudoers/..\") = %q, want %q (documented escape to LogDir)", got, logDir)
	}
}

func TestRunCleanupWorkerCancel(t *testing.T) {
	ls := &LocalStore{
		cfg: Config{
			LogDir:        t.TempDir(),
			RetentionPath: filepath.Join(t.TempDir(), "retention.json"),
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		ls.runCleanupWorker(ctx)
		close(done)
	}()
	cancel()
	select {
	case <-done:
		// success
	case <-time.After(2 * time.Second):
		t.Fatal("runCleanupWorker did not exit after context cancellation")
	}
}
