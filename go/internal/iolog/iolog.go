// Package iolog writes asciinema v2 session recordings (.cast files).
//
// Directory structure:
//
//	<base>/<user>/<host>_<timestamp>/
//	    session.cast  - asciinema v2 recording (header + event lines)
//	    session.json  - header-only copy for fast metadata listing (no I/O data)
//	    ACTIVE        - marker written at open, removed at close
//	    INCOMPLETE    - marker written if connection drops without session_end
//	    risk.json     - optional risk score cache (written by replay-server)
//
// Format: https://docs.asciinema.org/manual/asciicast/v2/
package iolog

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
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
	// Source identifies the recording path: "plugin", "ebpf-tty", "ebpf-pkexec".
	// Empty means "plugin" (backward compatible with pre-agent recordings).
	Source          string
	// ParentSessionID links an ebpf-pkexec session to its parent session.
	ParentSessionID string
	// HasIO is false for pkexec background services that produce no TTY output.
	HasIO           bool
	// DivergenceStatus is the initial status set by the agent at session start.
	// "confirmed" = eBPF witnessed the sudo execve; "unwitnessed" = eBPF
	// was down or did not see the execve.  Empty is treated as "unwitnessed".
	DivergenceStatus string
	// CallerProcess is the process name or service that triggered the polkit
	// authorization (dbus-polkit sessions only; empty for sudo plugin sessions).
	CallerProcess string
}

// Writer appends events to an asciinema v2 cast file.
// Safe for concurrent use.
type Writer struct {
	mu        sync.Mutex
	dir       string
	castF     *os.File
	castBuf   *bufio.Writer
	startTime time.Time
	// pendingUTF8 holds, per event kind ("o"/"i"), trailing bytes that look
	// like the start of a multi-byte UTF-8 sequence but were cut off at the
	// end of the chunk — held back until the next chunk of the same kind
	// completes them (or Close flushes them as raw bytes if none ever
	// arrives), so a character split across a chunk boundary is not
	// corrupted into replacement characters.
	pendingUTF8 map[string][]byte
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
	Source          string `json:"source,omitempty"`
	ParentSessionID string `json:"parent_session_id,omitempty"`
	HasIO           bool   `json:"has_io,omitempty"`
	CallerProcess   string `json:"caller_process,omitempty"`
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
		Source:          meta.Source,
		ParentSessionID: meta.ParentSessionID,
		HasIO:           meta.HasIO,
		CallerProcess:   meta.CallerProcess,
	}

	b, err := json.Marshal(hdr)
	if err != nil {
		castF.Close()
		return nil, fmt.Errorf("marshal cast header: %w", err)
	}
	castBuf := bufio.NewWriter(castF)
	if _, err := castBuf.Write(append(b, '\n')); err != nil {
		castF.Close()
		return nil, fmt.Errorf("write cast header: %w", err)
	}

	// Write session.json alongside session.cast so that ListSessions can read
	// only this small file instead of opening the full (potentially large) cast.
	if err := os.WriteFile(filepath.Join(dir, "session.json"), b, 0640); err != nil {
		castF.Close()
		return nil, fmt.Errorf("write session.json: %w", err)
	}

	return &Writer{
		dir:       dir,
		castF:     castF,
		castBuf:   castBuf,
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

// WriteResize appends a terminal resize event ("r") to the cast file.
// The asciinema v2 format represents this as [elapsed, "r", "COLSxROWS"].
func (w *Writer) WriteResize(cols, rows int, tsNs int64) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	elapsed := time.Unix(0, tsNs).Sub(w.startTime).Seconds()
	if elapsed < 0 {
		elapsed = 0
	}
	b, err := json.Marshal([]any{elapsed, "r", fmt.Sprintf("%dx%d", cols, rows)})
	if err != nil {
		return err
	}
	_, err = w.castBuf.Write(append(b, '\n'))
	return err
}

func (w *Writer) writeEvent(kind string, data []byte, tsNs int64) error {
	if len(data) == 0 {
		return nil
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	if pending := w.pendingUTF8[kind]; len(pending) > 0 {
		combined := make([]byte, 0, len(pending)+len(data))
		combined = append(combined, pending...)
		combined = append(combined, data...)
		data = combined
	}

	complete, pending := splitIncompleteUTF8Suffix(data)
	if len(pending) > 0 {
		if w.pendingUTF8 == nil {
			w.pendingUTF8 = make(map[string][]byte)
		}
		w.pendingUTF8[kind] = append([]byte(nil), pending...)
	} else {
		delete(w.pendingUTF8, kind)
	}
	if len(complete) == 0 {
		// Entire chunk is a not-yet-complete multi-byte sequence; wait for
		// the rest to arrive in a later chunk of the same kind.
		return nil
	}

	return w.writeEventBytes(kind, complete, tsNs)
}

// splitIncompleteUTF8Suffix returns data split into a leading part that is
// safe to encode now and a trailing part that looks like the truncated
// start of a multi-byte UTF-8 sequence (fewer bytes present than the lead
// byte requires). The trailing part should be held back and prepended to
// the next chunk of the same stream.
func splitIncompleteUTF8Suffix(data []byte) (complete, pending []byte) {
	n := len(data)
	for i := 1; i <= 3 && i <= n; i++ {
		b := data[n-i]
		if b < 0x80 {
			break // ASCII byte: no truncated lead byte precedes it
		}
		if b >= 0xc0 {
			var want int
			switch {
			case b&0xe0 == 0xc0:
				want = 2
			case b&0xf0 == 0xe0:
				want = 3
			case b&0xf8 == 0xf0:
				want = 4
			default:
				want = 1 // not a valid lead byte; nothing to hold back
			}
			if want > i {
				return data[:n-i], data[n-i:]
			}
			break
		}
		// 0x80-0xbf: continuation byte, keep scanning backward.
	}
	return data, nil
}

// writeEventBytes encodes data (which must not itself be split mid-sequence)
// as a cast event line: [elapsed_seconds, "o"/"i", "data"]. Built manually
// (not via encoding/json) to escape bytes that are not valid UTF-8 as
// \u00XX from their raw value, instead of collapsing them to U+FFFD and
// losing the original byte -- this is a forensic recording, so a corrupt or
// binary byte in the stream must survive intact.
func (w *Writer) writeEventBytes(kind string, data []byte, tsNs int64) error {
	elapsed := time.Unix(0, tsNs).Sub(w.startTime).Seconds()
	if elapsed < 0 {
		elapsed = 0
	}

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "[%f, %q, \"", elapsed, kind)

	for i := 0; i < len(data); {
		r, size := utf8.DecodeRune(data[i:])
		if r == utf8.RuneError && size <= 1 {
			// Genuinely invalid byte (not a valid encoding of anything,
			// including a real U+FFFD) -- escape the raw byte value so it's
			// still recoverable from the recording.
			fmt.Fprintf(&buf, "\\u%04x", data[i])
			i++
			continue
		}
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
				fmt.Fprintf(&buf, "\\u%04x", r)
			} else {
				buf.WriteRune(r)
			}
		}
		i += size
	}
	buf.WriteString("\"]\n")
	_, err := w.castBuf.Write(buf.Bytes())
	return err
}

// Flush explicitly flushes the underlying buffer to disk.
func (w *Writer) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.castBuf.Flush()
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
	// Flush any trailing bytes still held back as a possibly-incomplete
	// multi-byte UTF-8 sequence — no more chunks are coming to complete
	// them, so write them out now (as raw-byte escapes if still invalid)
	// rather than silently dropping them from the recording.
	now := time.Now().UnixNano()
	for kind, pending := range w.pendingUTF8 {
		if len(pending) == 0 {
			continue
		}
		if err := w.writeEventBytes(kind, pending, now); err != nil {
			log.Printf("iolog: flush pending %q bytes on close: %v", kind, err)
		}
	}
	w.pendingUTF8 = nil
	if err := w.castBuf.Flush(); err != nil {
		return err
	}
	if err := w.castF.Sync(); err != nil {
		return err
	}
	return w.castF.Close()
}
