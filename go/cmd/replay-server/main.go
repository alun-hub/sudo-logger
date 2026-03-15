// sudo-replay-server: browser-based playback interface for sudo session logs.
//
// Reads iolog directories written by sudo-logserver and serves a single-page
// application with a terminal player.  No authentication is built in — deploy
// behind a reverse proxy or restrict to a management network.
//
// Run: sudo-replay-server -logdir /var/log/sudoreplay -listen :8080
package main

import (
	"bufio"
	"embed"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

//go:embed static
var staticFiles embed.FS

var (
	flagListen = flag.String("listen", ":8080", "Listen address")
	flagLogDir = flag.String("logdir", "/var/log/sudoreplay", "Base directory for session logs")
)

// SessionInfo is the metadata returned for each session in the list API.
type SessionInfo struct {
	TSID      string  `json:"tsid"`
	User      string  `json:"user"`
	Host      string  `json:"host"`
	Runas     string  `json:"runas"`
	TTY       string  `json:"tty"`
	Command   string  `json:"command"`
	Cwd       string  `json:"cwd"`
	StartTime int64   `json:"start_time"` // unix seconds
	Duration  float64 `json:"duration"`   // seconds
}

// PlaybackEvent is one timed chunk of terminal output or input.
type PlaybackEvent struct {
	T    float64 `json:"t"`    // cumulative seconds from session start
	Type int     `json:"type"` // 3=TtyIn, 4=TtyOut (sudo iolog event types)
	Data string  `json:"data"` // base64-encoded bytes
}

// SessionList is the envelope returned by /api/sessions.
type SessionList struct {
	Sessions []SessionInfo `json:"sessions"`
	Total    int           `json:"total"`
}

func main() {
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/sessions", handleListSessions)
	mux.HandleFunc("/api/session/events", handleSessionEvents)

	staticFS, err := fs.Sub(staticFiles, "static")
	if err != nil {
		log.Fatalf("embed static: %v", err)
	}
	mux.Handle("/", http.FileServer(http.FS(staticFS)))

	log.Printf("sudo-replay-server listening on %s, logdir=%s", *flagListen, *flagLogDir)
	log.Fatal(http.ListenAndServe(*flagListen, mux))
}

func handleListSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	sortBy := r.URL.Query().Get("sort")
	order := r.URL.Query().Get("order")

	limit := 200
	offset := 0
	if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 && v <= 1000 {
		limit = v
	}
	if v, err := strconv.Atoi(r.URL.Query().Get("offset")); err == nil && v >= 0 {
		offset = v
	}

	var from, to int64
	if v, err := strconv.ParseInt(r.URL.Query().Get("from"), 10, 64); err == nil {
		from = v
	}
	if v, err := strconv.ParseInt(r.URL.Query().Get("to"), 10, 64); err == nil {
		to = v
	}

	result, err := listSessions(*flagLogDir, q, sortBy, order, from, to, limit, offset)
	if err != nil {
		log.Printf("list sessions: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func handleSessionEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	tsid := r.URL.Query().Get("tsid")
	if tsid == "" {
		http.Error(w, "missing tsid", http.StatusBadRequest)
		return
	}
	if err := validateTSID(tsid); err != nil {
		http.Error(w, "invalid tsid", http.StatusBadRequest)
		return
	}

	// Verify the resolved path stays within the log directory.
	// EvalSymlinks resolves all symlinks so a symlink pointing outside logdir
	// is caught even when filepath.Abs would pass it through.
	absLogDir, err := filepath.EvalSymlinks(*flagLogDir)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	sessDir := filepath.Join(absLogDir, tsid)
	absSessDir, err := filepath.EvalSymlinks(sessDir)
	if err != nil {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}
	if !strings.HasPrefix(absSessDir, absLogDir+string(filepath.Separator)) {
		http.Error(w, "invalid tsid", http.StatusBadRequest)
		return
	}

	events, err := readEvents(absSessDir)
	if err != nil {
		log.Printf("read events %s: %v", tsid, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(events)
}

// validateTSID ensures the TSID (e.g. "alice/host1_20260307-112244") contains
// only safe characters and no path-traversal sequences.
func validateTSID(tsid string) error {
	if strings.Contains(tsid, "..") {
		return fmt.Errorf("path traversal attempt")
	}
	for _, c := range tsid {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '/' || c == '_' || c == '-' || c == '.') {
			return fmt.Errorf("invalid character: %q", c)
		}
	}
	return nil
}

// listSessions scans the log directory, applies filter/sort/pagination, and
// returns a SessionList with the requested page and the unfiltered total count.
func listSessions(logDir, q, sortBy, order string, from, to int64, limit, offset int) (*SessionList, error) {
	sessions := make([]SessionInfo, 0)

	userEntries, err := os.ReadDir(logDir)
	if err != nil {
		if os.IsNotExist(err) {
			return &SessionList{Sessions: sessions, Total: 0}, nil
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
			tsid := userEntry.Name() + "/" + sessEntry.Name()
			sessDir := filepath.Join(userDir, sessEntry.Name())
			info, err := parseSession(sessDir, tsid)
			if err != nil {
				log.Printf("parse session %s: %v", sessDir, err)
				continue
			}
			if from > 0 && info.StartTime < from {
				continue
			}
			if to > 0 && info.StartTime > to {
				continue
			}
			if q != "" && !matchesAll(*info, q) {
				continue
			}
			sessions = append(sessions, *info)
		}
	}

	switch sortBy {
	case "user":
		if order == "asc" {
			sort.Slice(sessions, func(i, j int) bool { return sessions[i].User < sessions[j].User })
		} else {
			sort.Slice(sessions, func(i, j int) bool { return sessions[i].User > sessions[j].User })
		}
	case "host":
		if order == "asc" {
			sort.Slice(sessions, func(i, j int) bool { return sessions[i].Host < sessions[j].Host })
		} else {
			sort.Slice(sessions, func(i, j int) bool { return sessions[i].Host > sessions[j].Host })
		}
	case "duration":
		if order == "asc" {
			sort.Slice(sessions, func(i, j int) bool { return sessions[i].Duration < sessions[j].Duration })
		} else {
			sort.Slice(sessions, func(i, j int) bool { return sessions[i].Duration > sessions[j].Duration })
		}
	default: // "time" or ""
		if order == "asc" {
			sort.Slice(sessions, func(i, j int) bool { return sessions[i].StartTime < sessions[j].StartTime })
		} else {
			sort.Slice(sessions, func(i, j int) bool { return sessions[i].StartTime > sessions[j].StartTime })
		}
	}

	total := len(sessions)
	if offset >= total {
		return &SessionList{Sessions: make([]SessionInfo, 0), Total: total}, nil
	}
	end := offset + limit
	if end > total {
		end = total
	}
	return &SessionList{Sessions: sessions[offset:end], Total: total}, nil
}

// matchesAll returns true if every space-separated term in q appears in at
// least one of user, host, or command (case-insensitive AND logic).
func matchesAll(s SessionInfo, q string) bool {
	user := strings.ToLower(s.User)
	host := strings.ToLower(s.Host)
	cmd  := strings.ToLower(s.Command)
	for _, term := range strings.Fields(q) {
		if !strings.Contains(user, term) &&
			!strings.Contains(host, term) &&
			!strings.Contains(cmd, term) {
			return false
		}
	}
	return true
}

// parseSession reads the iolog "log" file and timing file for a session directory.
//
// The sudo iolog legacy log format (written by iolog.go):
//
//	line 1: unix_ts:submituser:runasuser::ttyname
//	line 2: cwd (always "/" in this implementation)
//	line 3: command with arguments
func parseSession(sessDir, tsid string) (*SessionInfo, error) {
	logData, err := os.ReadFile(filepath.Join(sessDir, "log"))
	if err != nil {
		return nil, err
	}

	lines := strings.SplitN(strings.TrimRight(string(logData), "\n"), "\n", 3)
	if len(lines) < 3 {
		return nil, fmt.Errorf("malformed log file (%d lines)", len(lines))
	}

	// "unix_ts:user:runas::tty" — split into at most 5 fields.
	// The double colon is because runasgroup is always empty here.
	parts := strings.SplitN(lines[0], ":", 5)
	if len(parts) < 5 {
		return nil, fmt.Errorf("malformed log metadata: %q", lines[0])
	}

	ts, _ := strconv.ParseInt(parts[0], 10, 64)
	user := parts[1]
	runas := parts[2]
	tty := parts[4]
	cwd := lines[1]
	command := lines[2]

	// Extract host from session directory name "host_YYYYMMDD-HHMMSS".
	// The timestamp suffix is always "_YYYYMMDD-HHMMSS" = 16 chars.
	host := ""
	dirName := filepath.Base(sessDir)
	if len(dirName) > 16 {
		host = dirName[:len(dirName)-16]
	}

	return &SessionInfo{
		TSID:      tsid,
		User:      user,
		Host:      host,
		Runas:     runas,
		TTY:       tty,
		Command:   command,
		Cwd:       cwd,
		StartTime: ts,
		Duration:  calcDuration(filepath.Join(sessDir, "timing")),
	}, nil
}

// calcDuration sums all delta values in a timing file to get total duration.
func calcDuration(timingPath string) float64 {
	f, err := os.Open(timingPath)
	if err != nil {
		return 0
	}
	defer f.Close()
	var total float64
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 {
			delta, _ := strconv.ParseFloat(fields[1], 64)
			total += delta
		}
	}
	return total
}

// readEvents parses the timing file and reads the corresponding raw bytes from
// the ttyout (EventTtyOut=4) and ttyin (EventTtyIn=3) data files.
//
// The timing file format (one entry per line):
//
//	<event_type> <delta_seconds> <byte_count>
func readEvents(sessDir string) ([]PlaybackEvent, error) {
	timingData, err := os.ReadFile(filepath.Join(sessDir, "timing"))
	if err != nil {
		return nil, fmt.Errorf("read timing: %w", err)
	}

	ttyout, _ := os.ReadFile(filepath.Join(sessDir, "ttyout"))
	ttyin, _ := os.ReadFile(filepath.Join(sessDir, "ttyin"))

	events := make([]PlaybackEvent, 0)
	var cumTime float64
	var outOffset, inOffset int

	for _, line := range strings.Split(string(timingData), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		eventType, _ := strconv.Atoi(fields[0])
		delta, _ := strconv.ParseFloat(fields[1], 64)
		nbytes, _ := strconv.Atoi(fields[2])
		cumTime += delta

		var chunk []byte
		switch eventType {
		case 4: // TtyOut — what the user sees
			end := outOffset + nbytes
			if end <= len(ttyout) {
				chunk = make([]byte, nbytes)
				copy(chunk, ttyout[outOffset:end])
				outOffset = end
			}
		case 3: // TtyIn — what the user typed
			end := inOffset + nbytes
			if end <= len(ttyin) {
				chunk = make([]byte, nbytes)
				copy(chunk, ttyin[inOffset:end])
				inOffset = end
			}
		}

		if len(chunk) > 0 {
			events = append(events, PlaybackEvent{
				T:    cumTime,
				Type: eventType,
				Data: base64.StdEncoding.EncodeToString(chunk),
			})
		}
	}

	return events, nil
}
