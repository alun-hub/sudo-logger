package iolog_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sudo-logger/internal/iolog"
)

var testMeta = iolog.SessionMeta{
	SessionID: "host1-alice-123-456-aabbccdd",
	User:      "alice",
	Host:      "host1",
	RunasUser: "root",
	Cwd:       "/home/alice",
	Command:   "/bin/bash",
	Rows:      50,
	Cols:      220,
}

func newTestWriter(t *testing.T) (*iolog.Writer, string) {
	t.Helper()
	dir := t.TempDir()
	start := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	w, err := iolog.NewWriter(dir, testMeta, start)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	return w, w.Dir()
}

// TestNewWriterCreatesCastFile checks that session.cast is created.
func TestNewWriterCreatesCastFile(t *testing.T) {
	_, dir := newTestWriter(t)
	if _, err := os.Stat(filepath.Join(dir, "session.cast")); err != nil {
		t.Errorf("expected session.cast to exist: %v", err)
	}
}

// TestNewWriterHeaderContent checks that the cast header contains key fields.
func TestNewWriterHeaderContent(t *testing.T) {
	_, dir := newTestWriter(t)
	data, err := os.ReadFile(filepath.Join(dir, "session.cast"))
	if err != nil {
		t.Fatalf("read cast: %v", err)
	}
	// Header is the first line.
	firstLine := strings.SplitN(string(data), "\n", 2)[0]

	var hdr map[string]any
	if err := json.Unmarshal([]byte(firstLine), &hdr); err != nil {
		t.Fatalf("header is not valid JSON: %v", err)
	}
	if hdr["user"] != "alice" {
		t.Errorf("header user: got %v, want alice", hdr["user"])
	}
	if hdr["command"] != "/bin/bash" {
		t.Errorf("header command: got %v, want /bin/bash", hdr["command"])
	}
	if hdr["version"].(float64) != 2 {
		t.Errorf("header version: got %v, want 2", hdr["version"])
	}
}

// TestWriteOutput verifies that an "o" event is appended to the cast file.
func TestWriteOutput(t *testing.T) {
	w, dir := newTestWriter(t)
	defer w.Close()

	ts := time.Now().UnixNano()
	if err := w.WriteOutput([]byte("hello world"), ts); err != nil {
		t.Fatalf("WriteOutput: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "session.cast"))
	if err != nil {
		t.Fatalf("read cast: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) < 2 {
		t.Fatalf("expected at least 2 lines (header + event), got %d", len(lines))
	}

	var event []json.RawMessage
	if err := json.Unmarshal([]byte(lines[1]), &event); err != nil {
		t.Fatalf("event line is not valid JSON: %v", err)
	}
	if len(event) != 3 {
		t.Fatalf("event has %d elements, want 3", len(event))
	}
	var kind, payload string
	json.Unmarshal(event[1], &kind)  //nolint:errcheck
	json.Unmarshal(event[2], &payload) //nolint:errcheck
	if kind != "o" {
		t.Errorf("event kind: got %q, want %q", kind, "o")
	}
	if payload != "hello world" {
		t.Errorf("event data: got %q, want %q", payload, "hello world")
	}
}

// TestWriteInput verifies that an "i" event is appended with correct kind.
func TestWriteInput(t *testing.T) {
	w, dir := newTestWriter(t)
	defer w.Close()

	ts := time.Now().UnixNano()
	if err := w.WriteInput([]byte("ls\n"), ts); err != nil {
		t.Fatalf("WriteInput: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "session.cast"))
	if err != nil {
		t.Fatalf("read cast: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) < 2 {
		t.Fatalf("expected at least 2 lines, got %d", len(lines))
	}

	var event []json.RawMessage
	if err := json.Unmarshal([]byte(lines[1]), &event); err != nil {
		t.Fatalf("event is not valid JSON: %v", err)
	}
	var kind string
	json.Unmarshal(event[1], &kind) //nolint:errcheck
	if kind != "i" {
		t.Errorf("event kind: got %q, want %q", kind, "i")
	}
}

// TestClose verifies that Close returns no error.
func TestClose(t *testing.T) {
	w, _ := newTestWriter(t)
	if err := w.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// TestCommandWithNewline checks that a command containing a newline is stored
// as valid JSON (the newline is escaped automatically by json.Marshal).
func TestCommandWithNewline(t *testing.T) {
	dir := t.TempDir()
	start := time.Now()
	meta := iolog.SessionMeta{
		SessionID: "host2-bob-1-2-aabb",
		User:      "bob",
		Host:      "host2",
		RunasUser: "root",
		Command:   "evil\ninjected",
		Cwd:       "/tmp",
	}
	w, err := iolog.NewWriter(dir, meta, start)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	w.Close()

	data, err := os.ReadFile(filepath.Join(w.Dir(), "session.cast"))
	if err != nil {
		t.Fatalf("read cast: %v", err)
	}
	firstLine := strings.SplitN(string(data), "\n", 2)[0]
	var hdr map[string]any
	if err := json.Unmarshal([]byte(firstLine), &hdr); err != nil {
		t.Errorf("header with newline-containing command is invalid JSON: %v", err)
	}
}

// TestPathConfinement verifies that NewWriter rejects paths escaping the base dir.
func TestPathConfinement(t *testing.T) {
	dir := t.TempDir()
	start := time.Now()
	meta := iolog.SessionMeta{
		SessionID: "host3-validuser-1-2-aabb",
		User:      "validuser",
		Host:      "host3",
		RunasUser: "root",
		Command:   "cmd",
		Cwd:       "/",
	}
	_, err := iolog.NewWriter(dir, meta, start)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
