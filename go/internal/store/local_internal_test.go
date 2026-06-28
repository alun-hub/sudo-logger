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
