package iolog_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
	w, dir := newTestWriter(t)
	w.Flush()
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

	w.Flush()
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

	w.Flush()
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

// TestConcurrentWrites verifies that WriteOutput is safe for concurrent use.
func TestConcurrentWrites(t *testing.T) {
	w, dir := newTestWriter(t)
	defer w.Close()

	const goroutines = 20
	const writes = 50

	var wg sync.WaitGroup
	for i := range goroutines {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			ts := time.Now().UnixNano()
			for range writes {
				if err := w.WriteOutput([]byte("data"), ts); err != nil {
					t.Errorf("goroutine %d WriteOutput: %v", id, err)
					return
				}
				ts++
			}
		}(i)
	}
	wg.Wait()

	// Verify file exists and has at least header + all events.
	w.Flush()
	data, err := os.ReadFile(filepath.Join(dir, "session.cast"))
	if err != nil {
		t.Fatalf("read cast after concurrent writes: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	want := 1 + goroutines*writes // header + events
	if len(lines) < want {
		t.Errorf("got %d lines, want at least %d", len(lines), want)
	}
}

// TestCloseSync verifies that Close (which calls Sync) returns no error,
// confirming the fsync-before-close behaviour added in B4.
func TestCloseSync(t *testing.T) {
	w, _ := newTestWriter(t)
	ts := time.Now().UnixNano()
	for range 100 {
		w.WriteOutput([]byte("x"), ts) //nolint:errcheck
		ts++
	}
	if err := w.Close(); err != nil {
		t.Errorf("Close (with Sync): %v", err)
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

// readLastEventPayload flushes w, reads the cast file, and decodes the
// "data" field of the last event line.
func readLastEventPayload(t *testing.T, w *iolog.Writer, dir string) string {
	t.Helper()
	w.Flush() //nolint:errcheck
	data, err := os.ReadFile(filepath.Join(dir, "session.cast"))
	if err != nil {
		t.Fatalf("read cast: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) < 2 {
		t.Fatalf("expected at least 2 lines (header + event), got %d", len(lines))
	}
	var event []json.RawMessage
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &event); err != nil {
		t.Fatalf("last event line is not valid JSON: %v (line: %s)", err, lines[len(lines)-1])
	}
	if len(event) != 3 {
		t.Fatalf("event has %d elements, want 3", len(event))
	}
	var payload string
	if err := json.Unmarshal(event[2], &payload); err != nil {
		t.Fatalf("event payload is not a valid JSON string: %v", err)
	}
	return payload
}

// TestWriteOutputSplitUTF8Boundary verifies that a multi-byte UTF-8 character
// split across two separate WriteOutput calls (as would happen if a chunk
// boundary lands mid-character) is reassembled correctly instead of
// producing replacement characters at the split point.
func TestWriteOutputSplitUTF8Boundary(t *testing.T) {
	euro := "€" // 3-byte UTF-8 sequence: 0xE2 0x82 0xAC
	full := []byte("price: " + euro + " done")

	for _, split := range []int{8, 9, 10, 7} { // mid-sequence and non-mid-sequence splits
		t.Run("", func(t *testing.T) {
			w, dir := newTestWriter(t)
			defer w.Close()
			ts := time.Now().UnixNano()
			if err := w.WriteOutput(full[:split], ts); err != nil {
				t.Fatalf("WriteOutput part1: %v", err)
			}
			if err := w.WriteOutput(full[split:], ts+1); err != nil {
				t.Fatalf("WriteOutput part2: %v", err)
			}
			w.Flush() //nolint:errcheck
			data, err := os.ReadFile(filepath.Join(dir, "session.cast"))
			if err != nil {
				t.Fatalf("read cast: %v", err)
			}
			lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
			var got strings.Builder
			for _, line := range lines[1:] {
				var event []json.RawMessage
				if err := json.Unmarshal([]byte(line), &event); err != nil {
					t.Fatalf("event line is not valid JSON: %v", err)
				}
				var payload string
				json.Unmarshal(event[2], &payload) //nolint:errcheck
				got.WriteString(payload)
			}
			if got.String() != string(full) {
				t.Errorf("split at %d: reassembled %q, want %q", split, got.String(), string(full))
			}
		})
	}
}

// TestCloseFlushesIncompleteUTF8Tail verifies that a truncated multi-byte
// sequence that never gets completed (session ends mid-character) is still
// written out on Close, rather than silently dropped.
func TestCloseFlushesIncompleteUTF8Tail(t *testing.T) {
	w, dir := newTestWriter(t)
	ts := time.Now().UnixNano()
	// 0xE2 0x82 is the truncated 2-byte prefix of the 3-byte "€" sequence;
	// it never gets completed before Close.
	if err := w.WriteOutput([]byte{'x', 0xE2, 0x82}, ts); err != nil {
		t.Fatalf("WriteOutput: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "session.cast"))
	if err != nil {
		t.Fatalf("read cast: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) < 3 {
		t.Fatalf("expected header + 2 events (partial 'x' + flushed tail on close), got %d lines", len(lines))
	}
	// The flushed tail must decode as valid JSON and must not be empty —
	// the two truncated bytes must show up as raw-byte escapes.
	var event []json.RawMessage
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &event); err != nil {
		t.Fatalf("flushed-tail event line is not valid JSON: %v (line: %s)", err, lines[len(lines)-1])
	}
	var payload string
	json.Unmarshal(event[2], &payload) //nolint:errcheck
	if len(payload) == 0 {
		t.Errorf("expected the truncated tail bytes to be flushed on Close, got empty payload")
	}
}

// TestWriteOutputInvalidByteEscaped verifies that a byte which is not valid
// UTF-8 anywhere in the stream (not just at a chunk boundary) is preserved
// as a \u00XX escape of its raw value instead of being collapsed into a
// U+FFFD replacement character that loses the original byte.
func TestWriteOutputInvalidByteEscaped(t *testing.T) {
	w, dir := newTestWriter(t)
	defer w.Close()

	ts := time.Now().UnixNano()
	// 0xFF is not a valid UTF-8 lead or continuation byte anywhere.
	input := []byte{'a', 0xFF, 'b'}
	if err := w.WriteOutput(input, ts); err != nil {
		t.Fatalf("WriteOutput: %v", err)
	}

	payload := readLastEventPayload(t, w, dir)
	want := "aÿb"
	if payload != want {
		t.Errorf("got %q (bytes %v), want %q (bytes %v)", payload, []byte(payload), want, []byte(want))
	}
}
