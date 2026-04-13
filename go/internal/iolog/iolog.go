// Package iolog writes asciinema v2 session recordings (.cast files).
//
// Directory structure:
//
//	<base>/<user>/<host>_<timestamp>/
//	    session.cast  - asciinema v2 recording (header + event lines)
//	    ACTIVE        - marker written at open, removed at close
//	    INCOMPLETE    - marker written if connection drops without session_end
//	    risk.json     - optional risk score cache (written by replay-server)
//
// Format: https://docs.asciinema.org/manual/asciicast/v2/
package iolog

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// SessionMeta holds the per-session metadata written into the cast header.
type SessionMeta struct {
	SessionID       string
	User            string
	Host            string
	RunasUser       string
	RunasUID        int
	RunasGID        int
	Cwd             string
	Command         string
	ResolvedCommand string
	Flags           string
	Rows            int // terminal height; 0 → default 50
	Cols            int // terminal width;  0 → default 220
}

// Writer appends events to an asciinema v2 cast file.
// Safe for concurrent use.
type Writer struct {
	mu        sync.Mutex
	dir       string
	castF     *os.File
	startTime time.Time
}

// castHeader is the first line of an asciinema v2 file.
// Custom fields (user, host, …) are allowed by the spec and ignored by
// standard players.
type castHeader struct {
	Version         int    `json:"version"`
	Width           int    `json:"width"`
	Height          int    `json:"height"`
	Timestamp       int64  `json:"timestamp"`
	Title           string `json:"title"`
	SessionID       string `json:"session_id"`
	User            string `json:"user"`
	Host            string `json:"host"`
	RunasUser       string `json:"runas_user"`
	RunasUID        int    `json:"runas_uid"`
	RunasGID        int    `json:"runas_gid"`
	Cwd             string `json:"cwd,omitempty"`
	Command         string `json:"command"`
	ResolvedCommand string `json:"resolved_command,omitempty"`
	Flags           string `json:"flags,omitempty"`
}

// NewWriter creates the session directory and opens session.cast for writing.
func NewWriter(baseDir string, meta SessionMeta, startTime time.Time) (*Writer, error) {
	ts := startTime.UTC().Format("20060102-150405")
	// Append the last 6 characters of the session ID as a suffix to make the
	// directory name unique even when two sessions start within the same second.
	// Falls back to the bare timestamp when SessionID is too short (e.g. tests).
	dirName := fmt.Sprintf("%s_%s", meta.Host, ts)
	if len(meta.SessionID) >= 6 {
		dirName += "-" + meta.SessionID[len(meta.SessionID)-6:]
	}
	dir := filepath.Join(baseDir, meta.User, dirName)

	absBase, err := filepath.Abs(baseDir)
	if err != nil {
		return nil, fmt.Errorf("resolve base dir: %w", err)
	}
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("resolve session dir: %w", err)
	}
	if !strings.HasPrefix(absDir, absBase+string(filepath.Separator)) {
		return nil, fmt.Errorf("session dir %q escapes base dir %q", absDir, absBase)
	}

	if err := os.MkdirAll(dir, 0750); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", dir, err)
	}

	castF, err := os.Create(filepath.Join(dir, "session.cast"))
	if err != nil {
		return nil, err
	}

	cols := meta.Cols
	if cols <= 0 {
		cols = 220
	}
	rows := meta.Rows
	if rows <= 0 {
		rows = 50
	}

	hdr := castHeader{
		Version:         2,
		Width:           cols,
		Height:          rows,
		Timestamp:       startTime.Unix(),
		Title:           meta.User + "@" + meta.Host + ": " + meta.Command,
		SessionID:       meta.SessionID,
		User:            meta.User,
		Host:            meta.Host,
		RunasUser:       meta.RunasUser,
		RunasUID:        meta.RunasUID,
		RunasGID:        meta.RunasGID,
		Cwd:             meta.Cwd,
		Command:         meta.Command,
		ResolvedCommand: meta.ResolvedCommand,
		Flags:           meta.Flags,
	}

	b, err := json.Marshal(hdr)
	if err != nil {
		castF.Close()
		return nil, fmt.Errorf("marshal cast header: %w", err)
	}
	if _, err := castF.Write(append(b, '\n')); err != nil {
		castF.Close()
		return nil, fmt.Errorf("write cast header: %w", err)
	}

	return &Writer{
		dir:       dir,
		castF:     castF,
		startTime: startTime,
	}, nil
}

// WriteOutput appends a terminal output event ("o") to the cast file.
func (w *Writer) WriteOutput(data []byte, ts int64) error {
	return w.writeEvent("o", data, ts)
}

// WriteInput appends a terminal input event ("i") to the cast file.
func (w *Writer) WriteInput(data []byte, ts int64) error {
	return w.writeEvent("i", data, ts)
}

func (w *Writer) writeEvent(kind string, data []byte, tsNs int64) error {
	if len(data) == 0 {
		return nil
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	elapsed := time.Unix(0, tsNs).Sub(w.startTime).Seconds()
	if elapsed < 0 {
		elapsed = 0
	}

	// Event: [elapsed_seconds, "o"/"i", "data"]
	// Data must be valid UTF-8; replace invalid bytes with the replacement char.
	event := []any{elapsed, kind, strings.ToValidUTF8(string(data), "\ufffd")}
	b, err := json.Marshal(event)
	if err != nil {
		return err
	}
	_, err = w.castF.Write(append(b, '\n'))
	return err
}

// Dir returns the session directory path (contains session.cast and marker files).
func (w *Writer) Dir() string {
	return w.dir
}

// CastPath returns the absolute path to session.cast.
func (w *Writer) CastPath() string {
	return filepath.Join(w.dir, "session.cast")
}

// Close syncs and closes the cast file.
// Sync is called first so that kernel crash or power loss cannot silently
// truncate the tail of a security recording.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.castF.Sync(); err != nil {
		return err
	}
	return w.castF.Close()
}
