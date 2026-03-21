// Package iolog writes sudo I/O log directories compatible with sudoreplay.
//
// Directory structure:
//   <base>/<user>/<host>_<timestamp>/
//       log     - session metadata (text)
//       timing  - event timing (text)
//       ttyout  - terminal output (binary)
//       ttyin   - terminal input (binary)
//
// Format references: sudoreplay(8), sudo source plugins/sudoers/iolog*.c
package iolog

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Event types as defined by sudo's I/O log plugin.
const (
	EventStdin  = 0
	EventStdout = 1
	EventStderr = 2
	EventTtyIn  = 3
	EventTtyOut = 4
)

// Writer writes a sudo-compatible I/O log session.
// Safe for concurrent use.
type Writer struct {
	mu        sync.Mutex
	dir       string
	ttyoutF   *os.File
	ttyinF    *os.File
	timingF   *os.File
	startTime time.Time
	lastEvent time.Time
}

// NewWriter creates a new session log directory and opens the log files.
//
// Parameters map to sudo's log(5) fields:
//   host      - client hostname
//   user      - the user who invoked sudo
//   runas     - the user sudo ran as (typically "root")
//   tty       - terminal name (e.g. "/dev/pts/0") or "unknown"
//   command   - full command path and arguments
//   cwd       - working directory at the time sudo was invoked
//   startTime - session start time
func NewWriter(baseDir, user, host, runas, tty, command, cwd string, startTime time.Time) (*Writer, error) {
	ts := startTime.UTC().Format("20060102-150405")
	dir := filepath.Join(baseDir, user, fmt.Sprintf("%s_%s", host, ts))

	// Defence-in-depth: ensure the resolved path stays within baseDir.
	// filepath.Join already cleans ".." but we verify explicitly.
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

	// log file: metadata read by sudoreplay
	// Legacy format (iolog_parse_loginfo_legacy):
	//   line 1: timestamp:submituser:runasuser:runasgroup:ttyname
	//   line 2: cwd
	//   line 3: command with args
	logF, err := os.Create(filepath.Join(dir, "log"))
	if err != nil {
		return nil, err
	}
	safeCmd := strings.NewReplacer("\n", " ", "\r", " ").Replace(command)
	safeCwd := strings.NewReplacer("\n", " ", "\r", " ").Replace(cwd)
	if safeCwd == "" {
		safeCwd = "/"
	}
	if _, err = fmt.Fprintf(logF, "%d:%s:%s::%s\n%s\n%s\n",
		startTime.Unix(), user, runas, tty, safeCwd, safeCmd); err != nil {
		_ = logF.Close()
		return nil, fmt.Errorf("write log header: %w", err)
	}
	if err = logF.Close(); err != nil {
		return nil, fmt.Errorf("close log file: %w", err)
	}

	ttyoutF, err := os.Create(filepath.Join(dir, "ttyout"))
	if err != nil {
		return nil, err
	}
	ttyinF, err := os.Create(filepath.Join(dir, "ttyin"))
	if err != nil {
		ttyoutF.Close()
		return nil, err
	}
	timingF, err := os.Create(filepath.Join(dir, "timing"))
	if err != nil {
		ttyoutF.Close()
		ttyinF.Close()
		return nil, err
	}

	return &Writer{
		dir:       dir,
		ttyoutF:   ttyoutF,
		ttyinF:    ttyinF,
		timingF:   timingF,
		startTime: startTime,
		lastEvent: startTime,
	}, nil
}

// WriteOutput writes terminal output (what the user sees).
func (w *Writer) WriteOutput(data []byte, ts int64) error {
	return w.write(EventTtyOut, w.ttyoutF, data, ts)
}

// WriteInput writes terminal input (what the user typed).
func (w *Writer) WriteInput(data []byte, ts int64) error {
	return w.write(EventTtyIn, w.ttyinF, data, ts)
}

func (w *Writer) write(eventType int, f *os.File, data []byte, tsNs int64) error {
	if len(data) == 0 {
		return nil
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	t := time.Unix(0, tsNs)
	delta := t.Sub(w.lastEvent).Seconds()
	if delta < 0 {
		delta = 0
	}

	// timing entry: "<type> <delta_seconds> <num_bytes>"
	if _, err := fmt.Fprintf(w.timingF, "%d %f %d\n", eventType, delta, len(data)); err != nil {
		return err
	}

	if _, err := f.Write(data); err != nil {
		return err
	}

	w.lastEvent = t
	return nil
}

// Dir returns the session log directory path.
func (w *Writer) Dir() string {
	return w.dir
}

// Close flushes and closes all log files.
// Returns the first error encountered, if any.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	var firstErr error
	for _, f := range []*os.File{w.ttyoutF, w.ttyinF, w.timingF} {
		if err := f.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
