package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"sudo-logger/internal/siem"
	"sudo-logger/internal/store"
)

// sessionsCache caches the result of ListSessions to avoid an expensive
// full directory walk on every /api/sudoers/hosts poll (called every 15 s).
var sessionsCache struct {
	mu      sync.Mutex
	records []store.SessionRecord
	expiry  time.Time
}

func cachedListSessions(ctx context.Context) []store.SessionRecord {
	sessionsCache.mu.Lock()
	defer sessionsCache.mu.Unlock()
	if time.Now().Before(sessionsCache.expiry) {
		return sessionsCache.records
	}
	records, err := sessionStore.ListSessions(ctx)
	if err != nil {
		return sessionsCache.records // return stale on error
	}
	sessionsCache.records = records
	sessionsCache.expiry = time.Now().Add(60 * time.Second)
	return records
}

var viewsTotal atomic.Int64 // monotonic per-process counter for Prometheus

func recordView(r *http.Request, tsid, replayURL string) {
	viewsTotal.Add(1)
	viewer := viewerFromContext(r)
	if err := sessionStore.RecordView(r.Context(), tsid, viewer, replayURL); err != nil {
		log.Printf("record view: %v", err)
	}
}

// SessionInfo is the metadata returned for each session in the list API.
type SessionInfo struct {
	TSID             string   `json:"tsid"`
	SessionID        string   `json:"session_id,omitempty"`
	User             string   `json:"user"`
	Host             string   `json:"host"`
	Runas            string   `json:"runas"`
	RunasUID         int      `json:"runas_uid,omitempty"`
	RunasGID         int      `json:"runas_gid,omitempty"`
	TTY              string   `json:"tty"`
	Command          string   `json:"command"`
	ResolvedCommand  string   `json:"resolved_command,omitempty"`
	Cwd              string   `json:"cwd,omitempty"`
	Flags            string   `json:"flags,omitempty"`
	StartTime        int64    `json:"start_time"` // unix seconds
	Duration         float64  `json:"duration"`   // seconds
	ExitCode         int32    `json:"exit_code"`
	Incomplete       bool     `json:"incomplete,omitempty"`     // true if session ended without clean session_end
	NetworkOutage    bool     `json:"network_outage,omitempty"` // true when terminated by network loss (not a agent kill)
	InProgress       bool     `json:"in_progress,omitempty"`    // true if session is still being recorded
	RiskScore        int      `json:"risk_score"`
	RiskLevel        string   `json:"risk_level"` // low | medium | high | critical
	RiskReasons      []string `json:"risk_reasons,omitempty"`
	Source           string   `json:"source,omitempty"`            // "plugin" | "ebpf-tty" | "ebpf-pkexec"
	ParentSessionID  string   `json:"parent_session_id,omitempty"` // for ebpf-pkexec → parent session
	HasIO            bool     `json:"has_io,omitempty"`            // false for pkexec background services
	DivergenceStatus string   `json:"divergence_status,omitempty"` // "confirmed" | "unwitnessed" | "missing_plugin"
	MatchedSessionID string   `json:"matched_session_id,omitempty"` // TSID of matched counterpart
	CallerProcess    string   `json:"caller_process,omitempty"`    // process/service that triggered polkit (dbus-polkit only)
	Cols             int      `json:"cols,omitempty"`              // terminal width from recording; 0 if unknown
	Rows             int      `json:"rows,omitempty"`              // terminal height from recording; 0 if unknown
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

// validateTSID ensures the TSID (e.g. "alice/host1_20260307-112244") contains
// only safe characters and no path-traversal sequences.
func validateTSID(tsid string) error {
	if strings.Contains(tsid, "..") {
		return fmt.Errorf("path traversal attempt")
	}
	for _, c := range tsid {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || //nolint:staticcheck
			(c >= '0' && c <= '9') || c == '/' || c == '_' || c == '-' || c == '.') {
			return fmt.Errorf("invalid character: %q", c)
		}
	}
	return nil
}

// listSessions filters, sorts and paginates sessions from the in-memory cache.
func listSessions(ctx context.Context, q, sortBy, order string, from, to int64, limit, offset int, ownerFilter string) (*SessionList, error) {
	all, err := cache.get(ctx)
	if err != nil {
		return nil, err
	}

	sessions := make([]SessionInfo, 0, len(all))
	for _, s := range all {
		// Hide eBPF TTY sessions that are matched to a plugin session — the
		// plugin session already appears in the list with full detail.
		// Unmatched eBPF sessions (su, screen, SSH without sudo) are shown.
		if s.Source == "ebpf-tty" && s.MatchedSessionID != "" {
			continue
		}
		// Hide divergence alerts where no I/O was ever captured — these are
		// spurious entries from flag-only sudo invocations (sudo -v, sudo -l)
		// that eBPF sees but the I/O plugin never handles.
		if s.DivergenceStatus == "missing_plugin" && !s.HasIO {
			continue
		}
		if ownerFilter != "" && s.User != ownerFilter {
			continue
		}
		if from > 0 && s.StartTime < from {
			continue
		}
		if to > 0 && s.StartTime > to {
			continue
		}
		if q != "" && !matchesAll(s, q) {
			continue
		}
		sessions = append(sessions, s)
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
	case "risk":
		if order == "asc" {
			sort.Slice(sessions, func(i, j int) bool { return sessions[i].RiskScore < sessions[j].RiskScore })
		} else {
			sort.Slice(sessions, func(i, j int) bool { return sessions[i].RiskScore > sessions[j].RiskScore })
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
	cmd := strings.ToLower(s.Command)
	tsid := strings.ToLower(s.TSID)
	for _, term := range strings.Fields(q) {
		if !strings.Contains(user, term) &&
			!strings.Contains(host, term) &&
			!strings.Contains(cmd, term) &&
			!strings.Contains(tsid, term) {
			return false
		}
	}
	return true
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

	var ownerFilter string
	if !can(r, store.PermSessionsListAll) {
		ownerFilter = viewerFromContext(r)
		if ownerFilter == "-" {
			ownerFilter = "" // unauthenticated open deployment — show all
		}
	}
	result, err := listSessions(r.Context(), q, sortBy, order, from, to, limit, offset, ownerFilter)
	if err != nil {
		log.Printf("list sessions: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(result); err != nil {
		log.Printf("encode session list: %v", err)
	}
}

// enforceOwnership checks that the request's viewer is allowed to access
// tsid: viewers without PermSessionsReplayAll may only access their own
// sessions. Writes the appropriate error response and returns false if
// access is denied; callers must return immediately when it does.
func enforceOwnership(w http.ResponseWriter, r *http.Request, tsid string) bool {
	viewer := viewerFromContext(r)
	if can(r, store.PermSessionsReplayAll) || viewer == "-" {
		return true
	}
	all := cachedListSessions(r.Context())
	for _, s := range all {
		if s.TSID == tsid {
			if s.User != viewer {
				http.Error(w, "forbidden", http.StatusForbidden)
				return false
			}
			return true
		}
	}
	http.Error(w, "session not found", http.StatusNotFound)
	return false
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

	if !enforceOwnership(w, r, tsid) {
		return
	}

	// Record who viewed this session before streaming the response.
	viewer := viewerFromContext(r)
	var replayURL string
	if base := strings.TrimRight(siem.Get().ReplayURLBase, "/"); base != "" {
		replayURL = base + "/?tsid=" + url.QueryEscape(tsid)
	} else {
		scheme := "https"
		if r.TLS == nil {
			scheme = "http"
		}
		replayURL = scheme + "://" + r.Host + "/?tsid=" + url.QueryEscape(tsid)
	}
	recordView(r, tsid, replayURL)
	log.Printf("session-view user=%s addr=%s tsid=%s url=%s", sanitizeForLog(viewer), r.RemoteAddr, tsid, replayURL)

	rc, err := sessionStore.OpenCast(r.Context(), tsid)
	if err != nil {
		log.Printf("open cast %s: %v", tsid, err)
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}
	defer rc.Close()

	// Set headers for streaming NDJSON
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Accel-Buffering", "no") // Disable Nginx buffering
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	enc := json.NewEncoder(w)

	scanner := bufio.NewScanner(rc)
	// Allow for very long lines (e.g. large screen frames or terminal bursts)
	scanner.Buffer(make([]byte, 1024*1024), 10*1024*1024)

	// Skip header line
	if !scanner.Scan() {
		return
	}

	lineCount := 0
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 || line[0] != '[' {
			continue
		}

		var raw [3]json.RawMessage
		if err := json.Unmarshal(line, &raw); err != nil {
			continue
		}

		var relTime float64
		var kind string
		var dataStr string
		_ = json.Unmarshal(raw[0], &relTime)
		_ = json.Unmarshal(raw[1], &kind)
		_ = json.Unmarshal(raw[2], &dataStr)

		evType := 4 // TtyOut
		if kind == "i" {
			evType = 3 // TtyIn
		}

		event := PlaybackEvent{
			T:    relTime,
			Type: evType,
			Data: base64.StdEncoding.EncodeToString([]byte(dataStr)),
		}

		if err := enc.Encode(event); err != nil {
			return
		}

		lineCount++
		// Flush every 100 events to keep the connection alive and the proxy happy
		if ok && lineCount%100 == 0 {
			flusher.Flush()
		}
	}
	if ok {
		flusher.Flush()
	}

	if err := scanner.Err(); err != nil {
		log.Printf("[%s] scan error during streaming: %v", tsid, err)
	}
}

func handleSessionCast(w http.ResponseWriter, r *http.Request) {
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

	if !enforceOwnership(w, r, tsid) {
		return
	}

	// Record who viewed this session before streaming the response.
	viewer := viewerFromContext(r)
	var replayURL string
	if base := strings.TrimRight(siem.Get().ReplayURLBase, "/"); base != "" {
		replayURL = base + "/?tsid=" + url.QueryEscape(tsid)
	} else {
		scheme := "https"
		if r.TLS == nil {
			scheme = "http"
		}
		replayURL = scheme + "://" + r.Host + "/?tsid=" + url.QueryEscape(tsid)
	}
	recordView(r, tsid, replayURL)
	log.Printf("session-view user=%s addr=%s tsid=%s url=%s", sanitizeForLog(viewer), r.RemoteAddr, tsid, replayURL)

	rc, err := sessionStore.OpenCast(r.Context(), tsid)
	if err != nil {
		log.Printf("open cast %s: %v", tsid, err)
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}
	defer rc.Close()

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.cast", url.QueryEscape(tsid)))

	// Filter out "i" (input) events and patch the header height.
	// asciinema-player doesn't display input events, and they can cause VT emulator
	// corruption when the player seeks/fast-forwards.
	//
	// The header height patch corrects a known issue where iolog.go defaults to
	// height=50 when the plugin sends 0 rows. vi/ncurses detect the actual PTY
	// size via TIOCGWINSZ and may use a different row count. We detect the actual
	// row count from the first few output events: vi always emits ESC[1;Nr
	// (set-scroll-region) as its first action, where N is the actual row count.
	// In the cast file, ESC is JSON-encoded as  .
	scanner := bufio.NewScanner(rc)
	scanner.Buffer(make([]byte, 1024*1024), 10*1024*1024)

	scrollRegionRE := regexp.MustCompile(`\\u001b\[1;(\d+)r`)

	if !scanner.Scan() {
		return
	}
	headerBytes := append([]byte(nil), scanner.Bytes()...)

	// Buffer the first 5 output events to detect actual terminal rows before
	// writing the (possibly patched) header.
	type bufferedLine struct{ data []byte }
	var buffered []bufferedLine
	detectedRows := 0
	for len(buffered) < 5 && detectedRows == 0 && scanner.Scan() {
		line := scanner.Bytes()
		cp := make([]byte, len(line))
		copy(cp, line)
		buffered = append(buffered, bufferedLine{cp})
		if m := scrollRegionRE.FindSubmatch(line); m != nil {
			if n, err2 := strconv.Atoi(string(m[1])); err2 == nil && n > 0 {
				detectedRows = n
			}
		}
	}

	if detectedRows > 0 {
		var hdr map[string]json.RawMessage
		if json.Unmarshal(headerBytes, &hdr) == nil {
			var currentHeight int
			if json.Unmarshal(hdr["height"], &currentHeight) == nil && currentHeight != detectedRows {
				hdr["height"], _ = json.Marshal(detectedRows)
				if patched, perr := json.Marshal(hdr); perr == nil {
					headerBytes = patched
				}
			}
		}
	}

	w.Write(headerBytes)
	w.Write([]byte("\n"))

	isInputEvent := func(line []byte) bool {
		if !bytes.Contains(line, []byte(`"i"`)) {
			return false
		}
		var raw []json.RawMessage
		if json.Unmarshal(line, &raw) != nil || len(raw) < 2 {
			return false
		}
		var kind string
		return json.Unmarshal(raw[1], &kind) == nil && kind == "i"
	}

	for _, bl := range buffered {
		if !isInputEvent(bl.data) {
			w.Write(bl.data)
			w.Write([]byte("\n"))
		}
	}

	for scanner.Scan() {
		line := scanner.Bytes()
		if isInputEvent(line) {
			continue
		}
		w.Write(line)
		w.Write([]byte("\n"))
	}
	if err := scanner.Err(); err != nil {
		log.Printf("error streaming cast %s: %v", tsid, err)
	}
}

// handleMetrics serves a Prometheus text exposition (no external library needed).
// Endpoint: GET /metrics
func handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	sessions, err := cache.get(r.Context())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	var total, active, incomplete int
	byRisk := map[string]int{"low": 0, "medium": 0, "high": 0, "critical": 0}
	for _, s := range sessions {
		total++
		if s.InProgress {
			active++
		}
		if s.Incomplete {
			incomplete++
		}
		byRisk[store.RiskLevel(s.RiskScore)]++
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	fmt.Fprintf(w, "# HELP sudoreplay_sessions_total Total number of recorded sessions.\n")
	fmt.Fprintf(w, "# TYPE sudoreplay_sessions_total gauge\n")
	fmt.Fprintf(w, "sudoreplay_sessions_total %d\n", total)

	fmt.Fprintf(w, "# HELP sudoreplay_sessions_active Sessions currently being recorded.\n")
	fmt.Fprintf(w, "# TYPE sudoreplay_sessions_active gauge\n")
	fmt.Fprintf(w, "sudoreplay_sessions_active %d\n", active)

	fmt.Fprintf(w, "# HELP sudoreplay_sessions_incomplete Sessions that ended without clean termination.\n")
	fmt.Fprintf(w, "# TYPE sudoreplay_sessions_incomplete gauge\n")
	fmt.Fprintf(w, "sudoreplay_sessions_incomplete %d\n", incomplete)

	fmt.Fprintf(w, "# HELP sudoreplay_sessions_by_risk Number of sessions per risk level.\n")
	fmt.Fprintf(w, "# TYPE sudoreplay_sessions_by_risk gauge\n")
	for _, level := range []string{"low", "medium", "high", "critical"} {
		fmt.Fprintf(w, "sudoreplay_sessions_by_risk{level=%q} %d\n", level, byRisk[level])
	}

	fmt.Fprintf(w, "# HELP sudoreplay_session_views_total Total session views via the replay UI since last restart.\n")
	fmt.Fprintf(w, "# TYPE sudoreplay_session_views_total counter\n")
	fmt.Fprintf(w, "sudoreplay_session_views_total %d\n", viewsTotal.Load())
}
