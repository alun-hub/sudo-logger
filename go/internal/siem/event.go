package siem

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Event carries the per-session metadata forwarded to the SIEM.
// It is populated by replay-server after the session completes —
// risk score is included because it is computed by the replay-server.
type Event struct {
	SessionID       string
	TSID            string // user/host_YYYYmmdd-HHMMSS — matches ?tsid= in the replay GUI
	User            string
	Host            string
	RunasUser       string
	RunasUID        int
	RunasGID        int
	Cwd             string
	Command         string
	ResolvedCommand string
	Flags           string // sudo flags: login_shell, preserve_env, implied_shell
	StartTime       time.Time
	EndTime         time.Time
	ExitCode        int32
	Incomplete      bool     // true when connection was lost without SESSION_END
	RiskScore       int      // 0–100 from risk scoring rules
	RiskReasons     []string // rule names that triggered
	ReplayURL       string   // populated by Send() from Config.ReplayURLBase + TSID
}

// durationSec returns the session length in seconds (≥ 0).
func (e Event) durationSec() float64 {
	d := e.EndTime.Sub(e.StartTime).Seconds()
	if d < 0 {
		return 0
	}
	return d
}

// ── JSON ─────────────────────────────────────────────────────────────────────

// FormatJSON returns the event as a flat JSON object.
func (e Event) FormatJSON() ([]byte, error) {
	obj := map[string]any{
		"session_id": e.SessionID,
		"user":       e.User,
		"host":       e.Host,
		"runas":      e.RunasUser,
		"runas_uid":  e.RunasUID,
		"runas_gid":  e.RunasGID,
		"command":    e.Command,
		"cwd":        e.Cwd,
		"start_time": e.StartTime.UTC().Format(time.RFC3339),
		"end_time":   e.EndTime.UTC().Format(time.RFC3339),
		"duration_s": e.durationSec(),
		"exit_code":  e.ExitCode,
		"incomplete": e.Incomplete,
		"risk_score": e.RiskScore,
	}
	if e.ResolvedCommand != "" {
		obj["resolved_command"] = e.ResolvedCommand
	}
	if e.Flags != "" {
		obj["flags"] = e.Flags
	}
	if len(e.RiskReasons) > 0 {
		obj["risk_reasons"] = e.RiskReasons
	}
	if e.ReplayURL != "" {
		obj["replay_url"] = e.ReplayURL
	}
	return json.Marshal(obj)
}

// ── CEF ──────────────────────────────────────────────────────────────────────

// cefEscape escapes backslash, equals, pipe and newlines in CEF extension values.
func cefEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "=", `\=`)
	s = strings.ReplaceAll(s, "|", `\|`)
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", "")
	return s
}

// cefSeverity maps exit code to a CEF severity value (0–10).
func cefSeverity(exitCode int32, incomplete bool) int {
	if incomplete {
		return 6 // Medium-High — abnormal termination
	}
	if exitCode != 0 {
		return 5 // Medium
	}
	return 3 // Low
}

// FormatCEF returns the event as a CEF:0 string.
//
// Format: CEF:0|Vendor|Product|Version|DeviceEventClassID|Name|Severity|Extension
func (e Event) FormatCEF() string {
	sev := cefSeverity(e.ExitCode, e.Incomplete)
	ext := fmt.Sprintf(
		"rt=%d shost=%s suser=%s duser=%s duid=%d dgid=%d dproc=%s "+
			"cs1=%s cs1Label=sessionId cs2=%s cs2Label=cwd "+
			"cn1=%d cn1Label=exitCode cn2=%d cn2Label=durationSec",
		e.StartTime.UnixMilli(),
		cefEscape(e.Host),
		cefEscape(e.User),
		cefEscape(e.RunasUser),
		e.RunasUID,
		e.RunasGID,
		cefEscape(e.Command),
		cefEscape(e.SessionID),
		cefEscape(e.Cwd),
		e.ExitCode,
		int64(e.durationSec()),
	)
	if e.ResolvedCommand != "" {
		ext += " cs3=" + cefEscape(e.ResolvedCommand) + " cs3Label=resolvedCommand"
	}
	if e.Flags != "" {
		ext += " cs4=" + cefEscape(e.Flags) + " cs4Label=flags"
	}
	if e.Incomplete {
		ext += " cs5=incomplete cs5Label=status"
	}
	if e.ReplayURL != "" {
		ext += " cs6=" + cefEscape(e.ReplayURL) + " cs6Label=replayUrl"
	}
	ext += fmt.Sprintf(" cn3=%d cn3Label=riskScore", e.RiskScore)
	if len(e.RiskReasons) > 0 {
		ext += " cs7=" + cefEscape(strings.Join(e.RiskReasons, ",")) + " cs7Label=riskReasons"
	}
	return fmt.Sprintf(
		"CEF:0|sudo-logger|sudo-logger|1.0|sudo-session|Privileged Command Session|%d|%s",
		sev, ext,
	)
}

// ── OCSF ─────────────────────────────────────────────────────────────────────

// FormatOCSF returns the event as an OCSF v1.3.0 Class 3003 (Process Activity)
// JSON object.
func (e Event) FormatOCSF() ([]byte, error) {
	statusID, status := ocsfStatus(e.ExitCode, e.Incomplete)
	sevID, sev := ocsfSeverity(e.ExitCode, e.Incomplete)

	unmapped := map[string]any{
		"session_id": e.SessionID,
		"cwd":        e.Cwd,
		"incomplete": e.Incomplete,
		"risk_score": e.RiskScore,
	}
	if e.Flags != "" {
		unmapped["flags"] = e.Flags
	}
	if len(e.RiskReasons) > 0 {
		unmapped["risk_reasons"] = e.RiskReasons
	}
	if e.ReplayURL != "" {
		unmapped["replay_url"] = e.ReplayURL
	}

	processUser := map[string]any{
		"name": e.RunasUser,
		"uid":  fmt.Sprintf("%d", e.RunasUID),
		"gid":  fmt.Sprintf("%d", e.RunasGID),
	}
	process := map[string]any{
		"cmd_line": e.Command,
		"user":     processUser,
	}
	if e.ResolvedCommand != "" {
		process["file"] = map[string]any{"path": e.ResolvedCommand}
	}

	obj := map[string]any{
		"class_uid":     3003,
		"class_name":    "Process Activity",
		"activity_id":   1,
		"activity_name": "Launch",
		"category_uid":  3,
		"category_name": "System Activity",
		"severity_id":   sevID,
		"severity":      sev,
		"status_id":     statusID,
		"status":        status,
		"time":          e.StartTime.UnixMilli(),
		"end_time":      e.EndTime.UnixMilli(),
		"duration":      e.EndTime.Sub(e.StartTime).Milliseconds(),
		"exit_code":     e.ExitCode,
		"metadata": map[string]any{
			"version": "1.3.0",
			"product": map[string]any{
				"name":        "sudo-logger",
				"vendor_name": "sudo-logger",
				"version":     "1.0",
			},
		},
		"actor": map[string]any{
			"user": map[string]any{
				"name":    e.User,
				"type_id": 1,
				"type":    "User",
			},
		},
		"process": process,
		"device": map[string]any{
			"hostname": e.Host,
		},
		"unmapped": unmapped,
	}
	return json.Marshal(obj)
}

func ocsfStatus(exitCode int32, incomplete bool) (int, string) {
	if incomplete {
		return 99, "Unknown"
	}
	if exitCode == 0 {
		return 1, "Success"
	}
	return 2, "Failure"
}

func ocsfSeverity(exitCode int32, incomplete bool) (int, string) {
	if incomplete {
		return 3, "Medium"
	}
	if exitCode != 0 {
		return 2, "Low"
	}
	return 1, "Informational"
}
