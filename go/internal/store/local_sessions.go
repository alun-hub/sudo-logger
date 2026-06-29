package store

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// scanAllSessions walks the two-level logDir/<user>/<session> hierarchy and
// returns metadata for every parseable session directory.
func scanAllSessions(logDir string) ([]SessionRecord, error) {
	records := make([]SessionRecord, 0)
	userEntries, err := os.ReadDir(logDir)
	if err != nil {
		if os.IsNotExist(err) {
			return records, nil
		}
		return nil, fmt.Errorf("read logdir: %w", err)
	}
	for _, userEntry := range userEntries {
		if !userEntry.IsDir() {
			continue
		}
		userDir := filepath.Join(logDir, userEntry.Name())
		sessEntries, err := os.ReadDir(userDir)
		if err != nil {
			continue
		}
		for _, sessEntry := range sessEntries {
			if !sessEntry.IsDir() {
				continue
			}
			sessDir := filepath.Join(userDir, sessEntry.Name())
			hasCast := false
			if _, err := os.Stat(filepath.Join(sessDir, "session.cast")); err == nil {
				hasCast = true
			}
			if _, err := os.Stat(filepath.Join(sessDir, "session.json")); err != nil && !hasCast {
				continue // not a cast session directory
			}
			tsid := userEntry.Name() + "/" + sessEntry.Name()
			rec, err := parseSessionRecord(sessDir, tsid)
			if err != nil {
				log.Printf("store/local: parse session %s: %v", sessDir, err)
				continue
			}
			records = append(records, *rec)
		}
	}
	return records, nil
}

// parseSessionRecord reads the session header and marker files, returning a
// SessionRecord. It prefers session.json (header-only, cheap) and falls back
// to reading the first line of session.cast for sessions created before
// session.json was introduced.
func parseSessionRecord(sessDir, tsid string) (*SessionRecord, error) {
	var headerBytes []byte

	if b, err := os.ReadFile(filepath.Join(sessDir, "session.json")); err == nil {
		headerBytes = b
	} else {
		f, err := os.Open(filepath.Join(sessDir, "session.cast"))
		if err != nil {
			return nil, err
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 64*1024), 64*1024)
		if !scanner.Scan() {
			return nil, fmt.Errorf("empty cast file")
		}
		headerBytes = scanner.Bytes()
	}

	var hdr struct {
		Timestamp       int64  `json:"timestamp"`
		SessionID       string `json:"session_id"`
		User            string `json:"user"`
		Host            string `json:"host"`
		RunasUser       string `json:"runas_user"`
		RunasUID        int    `json:"runas_uid"`
		RunasGID        int    `json:"runas_gid"`
		Width           int    `json:"width"`
		Height          int    `json:"height"`
		Cwd             string `json:"cwd"`
		Command         string `json:"command"`
		ResolvedCommand string `json:"resolved_command"`
		Flags           string `json:"flags"`
		Source          string `json:"source"`
		ParentSessionID string `json:"parent_session_id"`
		HasIO           bool   `json:"has_io"`
		CallerProcess   string `json:"caller_process"`
	}
	if err := json.Unmarshal(headerBytes, &hdr); err != nil {
		return nil, fmt.Errorf("parse cast header: %w", err)
	}

	rec := &SessionRecord{
		TSID:            tsid,
		SessionID:       hdr.SessionID,
		User:            hdr.User,
		Host:            hdr.Host,
		Runas:           hdr.RunasUser,
		RunasUID:        hdr.RunasUID,
		RunasGID:        hdr.RunasGID,
		Cols:            hdr.Width,
		Rows:            hdr.Height,
		Command:         hdr.Command,
		ResolvedCommand: hdr.ResolvedCommand,
		Cwd:             hdr.Cwd,
		Flags:           hdr.Flags,
		StartTime:       hdr.Timestamp,
		Duration:        castLastTime(sessDir),
		Source:          hdr.Source,
		ParentSessionID: hdr.ParentSessionID,
		HasIO:           hdr.HasIO,
		CallerProcess:   hdr.CallerProcess,
	}

	if _, err := os.Stat(filepath.Join(sessDir, "INCOMPLETE")); err == nil {
		rec.Incomplete = true
	}
	if _, err := os.Stat(filepath.Join(sessDir, "NETWORK_OUTAGE")); err == nil {
		rec.NetworkOutage = true
	}
	if _, err := os.Stat(filepath.Join(sessDir, "ACTIVE")); err == nil {
		rec.InProgress = true
	}
	if data, err := os.ReadFile(filepath.Join(sessDir, "exit_code")); err == nil {
		if v, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 32); err == nil {
			rec.ExitCode = int32(v)
		}
	}

	return rec, nil
}

// castLastTime reads the timestamp of the last event line in session.cast by
// seeking to the file tail — O(1) regardless of recording length.
func castLastTime(sessDir string) float64 {
	f, err := os.Open(filepath.Join(sessDir, "session.cast"))
	if err != nil {
		return 0
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil || fi.Size() == 0 {
		return 0
	}

	const tailSize = 8 * 1024
	readFrom := fi.Size() - tailSize
	if readFrom < 0 {
		readFrom = 0
	}
	buf := make([]byte, fi.Size()-readFrom)
	if _, err := f.ReadAt(buf, readFrom); err != nil {
		return 0
	}

	lines := bytes.Split(bytes.TrimRight(buf, "\n"), []byte("\n"))
	for i := len(lines) - 1; i >= 0; i-- {
		line := bytes.TrimSpace(lines[i])
		if len(line) == 0 || line[0] != '[' {
			continue
		}
		var event []json.RawMessage
		if json.Unmarshal(line, &event) != nil || len(event) < 1 {
			continue
		}
		var t float64
		if json.Unmarshal(event[0], &t) == nil {
			return t
		}
	}
	return 0
}

// localReadEvents parses session.cast in sessDir and returns all playback events.
func localReadEvents(sessDir string) ([]RawEvent, error) {
	f, err := os.Open(filepath.Join(sessDir, "session.cast"))
	if err != nil {
		return nil, fmt.Errorf("open cast: %w", err)
	}
	defer f.Close()

	return parseRawEvents(f)
}

// unescapeJSONString recovers raw bytes from a JSON string literal.
func unescapeJSONString(raw []byte) []byte {
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return raw
	}
	s := raw[1 : len(raw)-1]
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case '"':  out = append(out, '"'); i++
			case '\\': out = append(out, '\\'); i++
			case 'b':  out = append(out, '\b'); i++
			case 'f':  out = append(out, '\f'); i++
			case 'n':  out = append(out, '\n'); i++
			case 'r':  out = append(out, '\r'); i++
			case 't':  out = append(out, '\t'); i++
			case 'u':
				if i+5 < len(s) {
					var u uint16
					fmt.Sscanf(string(s[i+2:i+6]), "%04x", &u)
					out = append(out, byte(u))
					i += 5
					continue
				}
				out = append(out, '\\')
			default:
				out = append(out, '\\')
			}
		} else {
			out = append(out, s[i])
		}
	}
	return out
}

// parseRawEvents reads asciinema v2 events from r, skipping the header line.
func parseRawEvents(r io.Reader) ([]RawEvent, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 2*1024*1024), 2*1024*1024)

	// Skip header line.
	if !scanner.Scan() {
		return nil, fmt.Errorf("empty cast file")
	}

	events := make([]RawEvent, 0)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 || line[0] != '[' {
			continue
		}
		var raw []json.RawMessage
		if json.Unmarshal(line, &raw) != nil || len(raw) < 3 {
			continue
		}
		var t float64
		var kind string
		var dataStr string
		if json.Unmarshal(raw[0], &t) != nil {
			continue
		}
		if json.Unmarshal(raw[1], &kind) != nil {
			continue
		}
		if json.Unmarshal(raw[2], &dataStr) != nil {
			continue
		}

		events = append(events, RawEvent{T: t, Kind: kind, Data: []byte(dataStr)})
	}
	return events, scanner.Err()
}
