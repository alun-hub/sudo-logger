package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"sudo-logger/internal/iolog"
	"sudo-logger/internal/store"
	"sudo-logger/internal/util"
)

// ReportSummary holds aggregate statistics for a time period.
type ReportSummary struct {
	TotalSessions      int   `json:"total_sessions"`
	UniqueUsers        int   `json:"unique_users"`
	UniqueHosts        int   `json:"unique_hosts"`
	IncompleteSessions  int   `json:"incomplete_sessions"`
	LongSessions        int   `json:"long_sessions"`
	HighRiskSessions    int   `json:"high_risk_sessions"`
	CriticalSessions    int   `json:"critical_sessions"`
	PeriodFrom          int64 `json:"period_from"`
	PeriodTo            int64 `json:"period_to"`
}

// HostCount holds a host name and the number of sessions on that host.
type HostCount struct {
	Host  string `json:"host"`
	Count int    `json:"count"`
}

// UserStat holds per-user aggregate statistics.
type UserStat struct {
	User         string      `json:"user"`
	Sessions     int         `json:"sessions"`
	Hosts        int         `json:"hosts"`
	HostCounts   []HostCount `json:"host_counts"`
	AvgDuration  float64     `json:"avg_duration"`
	TopCommands  []string    `json:"top_commands"`
	Incomplete   int         `json:"incomplete"`
	LongSessions int         `json:"long_sessions"`
	HighRisk     int         `json:"high_risk"`
	Critical     int         `json:"critical"`
}

// Anomaly describes a session that triggered an anomaly rule.
type Anomaly struct {
	Kind      string  `json:"kind"`
	TSID      string  `json:"tsid"`
	User      string  `json:"user"`
	Host      string  `json:"host"`
	Command   string  `json:"command"`
	StartTime int64   `json:"start_time"`
	Duration  float64 `json:"duration"`
	Detail    string  `json:"detail"`
	RiskScore int     `json:"risk_score,omitempty"`
}

// ReportData is the envelope returned by /api/report.
type ReportData struct {
	Summary   ReportSummary `json:"summary"`
	PerUser   []UserStat    `json:"per_user"`
	Anomalies []Anomaly     `json:"anomalies"`
}

// sandboxYAML mirrors the agent's sandboxYAML struct and is used for strict
// schema validation of sandbox configs submitted via the API.
type sandboxYAML struct {
	Enabled *bool `yaml:"enabled"` // nil → true; explicit false disables enforcement
	Features struct {
		DenyNetlink         *bool `yaml:"deny_netlink"`
		DenyMount           *bool `yaml:"deny_mount"`
		DenyPtrace          *bool `yaml:"deny_ptrace"`
		DenyCapAuditControl *bool `yaml:"deny_cap_audit_control"`
		DenyCapNetAdmin     *bool `yaml:"deny_cap_net_admin"`
		DenyCapSysModule    *bool `yaml:"deny_cap_sys_module"`
		DenyCapMacAdmin     *bool `yaml:"deny_cap_mac_admin"`
		DenyCapSysRawio     *bool `yaml:"deny_cap_sys_rawio"`
		DenyCapSysBoot      *bool `yaml:"deny_cap_sys_boot"`
		DenySystemdIPC      *bool `yaml:"deny_systemd_ipc"`
	} `yaml:"features"`
	Protect struct {
		Files     []string `yaml:"files"`
		Forbidden []string `yaml:"forbidden"`
		Noexec    []string `yaml:"noexec"`
		Devices   []string `yaml:"devices"`
		Proc      []string `yaml:"proc"`
		Sockets   []string `yaml:"sockets"`
		Processes []string `yaml:"processes"`
	} `yaml:"protect"`
}

const (
	maxSandboxConfigSize  = 1 << 20 // 1 MB — generous for any sandbox.yaml
	maxSandboxTemplates   = 50
	maxSandboxTemplateLen = 64 * 1024 // 64 KB per template
)

// rulesFileHeader is prepended when the Settings UI writes the rules YAML file.
const rulesFileHeader = `# sudo-replay risk scoring rules
# Managed by sudo-replay-server. Manual edits and Settings UI changes are both supported.
# Changes are detected automatically on each index rebuild — no restart required.
#
# score: points added to session total (capped at 100)
# reason: shown in the UI when this risk-scoring fires
#
# command / content: case-insensitive substring matching against command line / ttyout
#   contains_any  – at least one string must be present (OR)
#   also_any      – AND at least one of these must also be present (AND + OR)
#   Rules with both fields fire if EITHER matches.
`

func handleReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !require(w, r, store.PermSessionsListOwn) {
		return
	}

	var from, to int64
	if v, err := strconv.ParseInt(r.URL.Query().Get("from"), 10, 64); err == nil {
		from = v
	}
	if v, err := strconv.ParseInt(r.URL.Query().Get("to"), 10, 64); err == nil {
		to = v
	}

	// Same ownership scoping as handleListSessions: without sessions:list_all,
	// the report is restricted to the caller's own sessions.
	var ownerFilter string
	if !can(r, store.PermSessionsListAll) {
		ownerFilter = viewerFromContext(r)
		if ownerFilter == "-" {
			ownerFilter = "" // unauthenticated open deployment — show all
		}
	}
	report, err := buildReport(r.Context(), from, to, ownerFilter)
	if err != nil {
		log.Printf("build report: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(report); err != nil {
		log.Printf("encode report: %v", err)
	}
}

// buildReport aggregates sessions in [from, to] into a ReportData. When
// ownerFilter is non-empty, only sessions belonging to that user are
// considered — used to scope the report for callers without sessions:list_all.
func buildReport(ctx context.Context, from, to int64, ownerFilter string) (*ReportData, error) {
	all, err := cache.get(ctx)
	if err != nil {
		return nil, err
	}

	sessions := make([]SessionInfo, 0, len(all))
	for _, s := range all {
		if ownerFilter != "" && s.User != ownerFilter {
			continue
		}
		if from > 0 && s.StartTime < from {
			continue
		}
		if to > 0 && s.StartTime > to {
			continue
		}
		sessions = append(sessions, s)
	}

	// ── Summary ───────────────────────────────────────────────────────────────
	userSet := make(map[string]struct{})
	hostSet := make(map[string]struct{})
	nIncomplete, nLong, nHighRisk, nCritical := 0, 0, 0, 0
	var periodFrom, periodTo int64
	for _, s := range sessions {
		userSet[s.User] = struct{}{}
		hostSet[s.Host] = struct{}{}
		if s.Incomplete {
			nIncomplete++
		}
		if s.Duration > 7200 {
			nLong++
		}
		if s.RiskScore >= 75 {
			nCritical++
		} else if s.RiskScore >= 50 {
			nHighRisk++
		}
		if periodFrom == 0 || s.StartTime < periodFrom {
			periodFrom = s.StartTime
		}
		if s.StartTime > periodTo {
			periodTo = s.StartTime
		}
	}

	// ── Per-user ─────────────────────────────────────────────────────────────
	type userAccum struct {
		sessions     int
		hosts        map[string]int
		totalDur     float64
		commands     map[string]int
		incomplete   int
		longSessions int
		highRisk     int
		critical     int
	}
	accums := make(map[string]*userAccum)
	for _, s := range sessions {
		a, ok := accums[s.User]
		if !ok {
			a = &userAccum{
				hosts:    make(map[string]int),
				commands: make(map[string]int),
			}
			accums[s.User] = a
		}
		a.sessions++
		a.hosts[s.Host]++
		a.totalDur += s.Duration
		if parts := strings.Fields(s.Command); len(parts) > 0 {
			a.commands[filepath.Base(parts[0])]++
		}
		if s.Incomplete {
			a.incomplete++
		}
		if s.Duration > 7200 {
			a.longSessions++
		}
		if s.RiskScore >= 75 {
			a.critical++
		} else if s.RiskScore >= 50 {
			a.highRisk++
		}
	}

	type kv struct {
		k string
		v int
	}
	perUser := make([]UserStat, 0, len(accums))
	for user, a := range accums {
		kvs := make([]kv, 0, len(a.commands))
		for k, v := range a.commands {
			kvs = append(kvs, kv{k, v})
		}
		sort.Slice(kvs, func(i, j int) bool { return kvs[i].v > kvs[j].v })
		top := make([]string, 0, 3)
		for i := 0; i < len(kvs) && i < 3; i++ {
			top = append(top, kvs[i].k)
		}
		avg := 0.0
		if a.sessions > 0 {
			avg = a.totalDur / float64(a.sessions)
		}
		hostKVs := make([]kv, 0, len(a.hosts))
		for h, n := range a.hosts {
			hostKVs = append(hostKVs, kv{h, n})
		}
		sort.Slice(hostKVs, func(i, j int) bool { return hostKVs[i].v > hostKVs[j].v })
		hostCounts := make([]HostCount, len(hostKVs))
		for i, hkv := range hostKVs {
			hostCounts[i] = HostCount{Host: hkv.k, Count: hkv.v}
		}

		perUser = append(perUser, UserStat{
			User:         user,
			Sessions:     a.sessions,
			Hosts:        len(a.hosts),
			HostCounts:   hostCounts,
			AvgDuration:  avg,
			TopCommands:  top,
			Incomplete:   a.incomplete,
			LongSessions: a.longSessions,
			HighRisk:     a.highRisk,
			Critical:     a.critical,
		})
	}
	sort.Slice(perUser, func(i, j int) bool { return perUser[i].Sessions > perUser[j].Sessions })

	// ── Anomalies ─────────────────────────────────────────────────────────────
	anomalies := make([]Anomaly, 0)
	inAnomalies := make(map[string]bool)
	for _, s := range sessions {
		if s.Incomplete {
			anomalies = append(anomalies, Anomaly{
				Kind: "incomplete", TSID: s.TSID, User: s.User, Host: s.Host,
				Command: s.Command, StartTime: s.StartTime, Duration: s.Duration,
				Detail: "agent killed mid-session", RiskScore: s.RiskScore,
			})
			inAnomalies[s.TSID] = true
		}
		t := time.Unix(s.StartTime, 0)
		if h := t.Hour(); h < 6 || h >= 23 {
			anomalies = append(anomalies, Anomaly{
				Kind: "after_hours", TSID: s.TSID, User: s.User, Host: s.Host,
				Command: s.Command, StartTime: s.StartTime, Duration: s.Duration,
				Detail: fmt.Sprintf("%02d:%02d local time", h, t.Minute()), RiskScore: s.RiskScore,
			})
			inAnomalies[s.TSID] = true
		}
		if s.Duration > 7200 {
			anomalies = append(anomalies, Anomaly{
				Kind: "long_session", TSID: s.TSID, User: s.User, Host: s.Host,
				Command: s.Command, StartTime: s.StartTime, Duration: s.Duration,
				Detail: "duration " + fmtDur(s.Duration), RiskScore: s.RiskScore,
			})
			inAnomalies[s.TSID] = true
		}
		if s.Runas == "root" {
			base := ""
			if parts := strings.Fields(s.Command); len(parts) > 0 {
				base = filepath.Base(parts[0])
			}
			switch base {
			case "bash", "sh", "zsh", "fish", "ksh", "tcsh", "csh":
				anomalies = append(anomalies, Anomaly{
					Kind: "root_shell", TSID: s.TSID, User: s.User, Host: s.Host,
					Command: s.Command, StartTime: s.StartTime, Duration: s.Duration,
					Detail: "direct root shell", RiskScore: s.RiskScore,
				})
				inAnomalies[s.TSID] = true
			}
		}
		// Flag high-risk sessions not already captured by other anomaly kinds.
		if s.RiskScore >= 50 && !inAnomalies[s.TSID] {
			detail := strings.Join(s.RiskReasons, "; ")
			anomalies = append(anomalies, Anomaly{
				Kind: "high_risk", TSID: s.TSID, User: s.User, Host: s.Host,
				Command: s.Command, StartTime: s.StartTime, Duration: s.Duration,
				Detail: detail, RiskScore: s.RiskScore,
			})
			inAnomalies[s.TSID] = true
		}
	}
	kindOrder := map[string]int{"incomplete": 0, "high_risk": 1, "root_shell": 2, "after_hours": 3, "long_session": 4}
	sort.Slice(anomalies, func(i, j int) bool {
		if anomalies[i].Kind != anomalies[j].Kind {
			return kindOrder[anomalies[i].Kind] < kindOrder[anomalies[j].Kind]
		}
		if anomalies[i].RiskScore != anomalies[j].RiskScore {
			return anomalies[i].RiskScore > anomalies[j].RiskScore
		}
		return anomalies[i].StartTime > anomalies[j].StartTime
	})

	return &ReportData{
		Summary: ReportSummary{
			TotalSessions:      len(sessions),
			UniqueUsers:        len(userSet),
			UniqueHosts:        len(hostSet),
			IncompleteSessions: nIncomplete,
			LongSessions:       nLong,
			HighRiskSessions:   nHighRisk,
			CriticalSessions:   nCritical,
			PeriodFrom:         periodFrom,
			PeriodTo:           periodTo,
		},
		PerUser:   perUser,
		Anomalies: anomalies,
	}, nil
}

// fmtDur formats a duration in seconds as a human-readable string.
func fmtDur(secs float64) string {
	d := time.Duration(secs) * time.Second
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	if h > 0 {
		return fmt.Sprintf("%dh %dm", h, m)
	}
	return fmt.Sprintf("%dm", m)
}

// ── Rules API ─────────────────────────────────────────────────────────────────

func handleGetRules(w http.ResponseWriter, r *http.Request) {
	if !require(w, r, store.PermConfigRead) {
		return
	}
	content, err := sessionStore.GetConfig(r.Context(), "risk-rules.yaml")
	if err != nil {
		http.Error(w, "read config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	var rs RuleSet
	if content != "" {
		if err := yaml.Unmarshal([]byte(content), &rs); err != nil {
			http.Error(w, "parse rules: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}
	if rs.Rules == nil {
		rs.Rules = []Rule{}
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{
		"rules": rs.Rules,
		"path":  *flagRules,
	}); err != nil {
		log.Printf("encode rules response: %v", err)
	}
}

func handlePutRules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !require(w, r, store.PermConfigWrite) {
		return
	}
	var body struct {
		Rules []Rule `json:"rules"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	yamlBody, err := yaml.Marshal(RuleSet{Rules: body.Rules})
	if err != nil {
		http.Error(w, "marshal yaml: "+err.Error(), http.StatusInternalServerError)
		return
	}
	content := string(rulesFileHeader) + string(yamlBody)
	if err := sessionStore.SetConfig(r.Context(), "risk-rules.yaml", content); err != nil {
		log.Printf("write rules: %v", err)
		http.Error(w, "write failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := loadRulesFromText(content); err != nil {
		log.Printf("reload after write: %v", err)
	}
	// Invalidate session cache so next request re-scores with new rules.
	cache.invalidate()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]bool{"ok": true}); err != nil {
		log.Printf("encode rules response: %v", err)
	}
}

// ── Retention API ──────────────────────────────────────────────────────────────

func handleGetRetention(w http.ResponseWriter, r *http.Request) {
	if !require(w, r, store.PermConfigRead) {
		return
	}
	cfgStr, err := sessionStore.GetConfig(r.Context(), "retention_policy")
	if err != nil {
		http.Error(w, "read failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	var policy store.RetentionPolicy
	if cfgStr != "" {
		_ = json.Unmarshal([]byte(cfgStr), &policy)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(policy)
}

func handlePutRetention(w http.ResponseWriter, r *http.Request) {
	if !require(w, r, store.PermConfigWrite) {
		return
	}
	var policy store.RetentionPolicy
	if err := json.NewDecoder(r.Body).Decode(&policy); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	data, _ := json.Marshal(policy)
	if err := sessionStore.SetConfig(r.Context(), "retention_policy", string(data)); err != nil {
		http.Error(w, "write failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

// ── Redaction config API ──────────────────────────────────────────────────────

func handleGetRedactionConfig(w http.ResponseWriter, r *http.Request) {
	if !require(w, r, store.PermConfigRead) {
		return
	}
	cfgStr, err := sessionStore.GetConfig(r.Context(), "redaction_config")
	if err != nil {
		http.Error(w, "read failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	custom := []string{}
	if cfgStr != "" {
		_ = json.Unmarshal([]byte(cfgStr), &custom)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"system_rules":    iolog.SystemRedactionRules,
		"custom_patterns": custom,
	})
}

func handlePutRedactionConfig(w http.ResponseWriter, r *http.Request) {
	if !require(w, r, store.PermConfigWrite) {
		return
	}
	var body struct {
		CustomPatterns []string `json:"custom_patterns"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	// Sanity check: compile each regex
	for _, p := range body.CustomPatterns {
		if _, err := regexp.Compile(p); err != nil {
			http.Error(w, fmt.Sprintf("invalid regex %q: %v", p, err), http.StatusBadRequest)
			return
		}
	}

	data, _ := json.Marshal(body.CustomPatterns)
	if err := sessionStore.SetConfig(r.Context(), "redaction_config", string(data)); err != nil {
		http.Error(w, "write failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

// ── Sandbox config API ────────────────────────────────────────────────────────

func handleGetSandbox(w http.ResponseWriter, r *http.Request) {
	if !require(w, r, store.PermConfigRead) {
		return
	}
	content, err := sessionStore.GetConfig(r.Context(), "sandbox.yaml")
	if err != nil {
		http.Error(w, "read config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{
		"content": content,
		"path":    *flagSandbox,
	}); err != nil {
		log.Printf("encode sandbox config: %v", err)
	}
}

func handlePutSandbox(w http.ResponseWriter, r *http.Request) {
	if !require(w, r, store.PermConfigWrite) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxSandboxConfigSize)
	var body struct {
		Content string `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	// Validate against the typed schema with strict unknown-field rejection.
	if body.Content != "" {
		dec := yaml.NewDecoder(strings.NewReader(body.Content))
		dec.KnownFields(true)
		var check sandboxYAML
		if err := dec.Decode(&check); err != nil {
			http.Error(w, "invalid sandbox config: "+err.Error(), http.StatusBadRequest)
			return
		}
	}
	if err := sessionStore.SetConfig(r.Context(), "sandbox.yaml", body.Content); err != nil {
		http.Error(w, "write failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

func handleGetSandboxTemplates(w http.ResponseWriter, r *http.Request) {
	if !require(w, r, store.PermConfigRead) {
		return
	}
	content, err := sessionStore.GetConfig(r.Context(), "sandbox_templates")
	if err != nil {
		http.Error(w, "read config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if content == "" {
		content = "{}"
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(content))
}

func handlePutSandboxTemplates(w http.ResponseWriter, r *http.Request) {
	if !require(w, r, store.PermConfigWrite) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxSandboxConfigSize)
	var templates map[string]string
	if err := json.NewDecoder(r.Body).Decode(&templates); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if len(templates) > maxSandboxTemplates {
		http.Error(w, fmt.Sprintf("too many templates (max %d)", maxSandboxTemplates), http.StatusBadRequest)
		return
	}
	for name, content := range templates {
		if len(content) > maxSandboxTemplateLen {
			http.Error(w, fmt.Sprintf("template %q exceeds maximum size", name), http.StatusBadRequest)
			return
		}
		if content == "" {
			continue
		}
		dec := yaml.NewDecoder(strings.NewReader(content))
		dec.KnownFields(true)
		var check sandboxYAML
		if err := dec.Decode(&check); err != nil {
			http.Error(w, fmt.Sprintf("template %q: invalid sandbox config: %s", name, err.Error()), http.StatusBadRequest)
			return
		}
	}
	data, err := json.Marshal(templates)
	if err != nil {
		http.Error(w, "marshal failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := sessionStore.SetConfig(r.Context(), "sandbox_templates", string(data)); err != nil {
		http.Error(w, "write failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

// ── Sudoers API ───────────────────────────────────────────────────────────────

// handleGetSudoersHosts returns the union of hosts that have sent snapshots
// and hosts that have recorded sessions, including their override status.
func handleGetSudoersHosts(w http.ResponseWriter, r *http.Request) {
	if !require(w, r, store.PermConfigRead) {
		return
	}
	snapHosts, err := sessionStore.ListSudoersHosts(r.Context())
	if err != nil {
		http.Error(w, "list hosts: "+err.Error(), http.StatusInternalServerError)
		return
	}
	configs, err := sessionStore.ListSudoersConfigs(r.Context())
	if err != nil {
		log.Printf("sudoers configs list: %v", err)
		configs = make(map[string]bool)
	}

	// Merge with session hosts so operators can stage config before first snapshot.
	sessions := cachedListSessions(r.Context())
	{
		seen := make(map[string]struct{}, len(snapHosts))
		for _, h := range snapHosts {
			seen[h] = struct{}{}
		}
		for _, s := range sessions {
			if _, ok := seen[s.Host]; !ok {
				seen[s.Host] = struct{}{}
				snapHosts = append(snapHosts, s.Host)
			}
		}
	}

	type hostJSON struct {
		Name       string `json:"name"`
		IsOverride bool   `json:"isOverride"`
		Error      string `json:"error,omitempty"`
		InSync     bool   `json:"inSync"`
		IsOffline  bool   `json:"isOffline"`
	}

	defaultCfg, _ := sessionStore.GetConfig(r.Context(), "sudoers/_default")
	cleanDefault := stripSudoersHeader(defaultCfg)
	now := time.Now().Unix()

	var out []hostJSON
	for _, h := range snapHosts {
		if h == "_default" {
			continue
		}
		var errMsg string
		if serr, err := sessionStore.GetSudoersError(r.Context(), h); err == nil && serr != nil {
			errMsg = serr.Error
		}

		staged := cleanDefault
		isOverride := false
		if configs[h] {
			cfg, _ := sessionStore.GetConfig(r.Context(), "sudoers/"+h)
			if cfg != "" {
				staged = stripSudoersHeader(cfg)
				isOverride = true
			}
		}

		inSync := false
		isOffline := true

		// Check last seen activity (heartbeats)
		lastSeen, _ := sessionStore.GetLastSeen(r.Context(), h)

		// Check last sudoers activity
		if snaps, err := sessionStore.ListSudoersSnapshots(r.Context(), h, 1); err == nil && len(snaps) > 0 {
			if snaps[0].UploadedAt > lastSeen {
				lastSeen = snaps[0].UploadedAt
			}
			managed := extractManagedSudoers(snaps[0].Content)
			inSync = (staged == managed)
		}

		// Also check last session activity as fallback
		for _, s := range sessions {
			if s.Host == h {
				ts := s.StartTime + int64(s.Duration)
				if s.Duration == 0 && (now-s.StartTime) < 600 {
					ts = now // session recently started, likely still in progress
				}
				if ts > lastSeen {
					lastSeen = ts
				}
			}
		}

		if lastSeen > 0 {
			isOffline = (now - lastSeen) > 600
		}

		out = append(out, hostJSON{h, isOverride, errMsg, inSync, isOffline})
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(out); err != nil {
		log.Printf("sudoers hosts encode: %v", err)
	}
}

func sha256Sum(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

// handleGetSudoersSnapshots returns the most recent 20 snapshots for a host.
func handleGetSudoersSnapshots(w http.ResponseWriter, r *http.Request) {
	if !require(w, r, store.PermConfigRead) {
		return
	}
	host := r.URL.Query().Get("host")
	if host == "" {
		http.Error(w, "host required", http.StatusBadRequest)
		return
	}
	snaps, err := sessionStore.ListSudoersSnapshots(r.Context(), host, 20)
	if err != nil {
		http.Error(w, "list snapshots: "+err.Error(), http.StatusInternalServerError)
		return
	}
	type snapJSON struct {
		SHA256     string `json:"sha256"`
		UploadedAt int64  `json:"uploaded_at"`
		Content    string `json:"content"`
	}
	var out []snapJSON
	for _, s := range snaps {
		out = append(out, snapJSON{s.SHA256, s.UploadedAt, s.Content})
	}
	if out == nil {
		out = []snapJSON{}
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{"host": host, "snapshots": out}); err != nil {
		log.Printf("sudoers snapshots encode: %v", err)
	}
}

// handleGetSudoersConfig returns the staged (desired) config for a host,
// falling back to the _default template if no host-specific config is set.
func handleGetSudoersConfig(w http.ResponseWriter, r *http.Request) {
	if !require(w, r, store.PermConfigRead) {
		return
	}
	host := r.URL.Query().Get("host")
	key := "sudoers/_default"
	isOverride := false
	if host != "" {
		key = "sudoers/" + host
	}
	content, err := sessionStore.GetConfig(r.Context(), key)
	if err != nil {
		http.Error(w, "get config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if host != "" && content == "" {
		// No host-specific config — fall back to _default.
		content, err = sessionStore.GetConfig(r.Context(), "sudoers/_default")
		if err != nil {
			http.Error(w, "get default config: "+err.Error(), http.StatusInternalServerError)
			return
		}
	} else if host != "" && content != "" {
		isOverride = true
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{
		"host":        host,
		"content":     content,
		"is_override": isOverride,
	}); err != nil {
		log.Printf("sudoers config encode: %v", err)
	}
}

// handlePutSudoersConfig stores a desired sudoers config for a host (or the
// global _default when host is empty).
func handlePutSudoersConfig(w http.ResponseWriter, r *http.Request) {
	if !require(w, r, store.PermConfigWrite) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, int64(256*1024))
	var body struct {
		Content string `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Validate sudoers syntax before saving
	if body.Content != "" {
		if err := validateSudoers(body.Content); err != nil {
			http.Error(w, "invalid sudoers syntax: "+err.Error(), http.StatusBadRequest)
			return
		}
	}

	host := r.URL.Query().Get("host")
	if host != "" && !util.ValidAgentHost(host) {
		http.Error(w, "invalid host", http.StatusBadRequest)
		return
	}
	key := "sudoers/_default"
	if host != "" {
		key = "sudoers/" + host
	}
	if err := sessionStore.SetConfig(r.Context(), key, body.Content); err != nil {
		http.Error(w, "set config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	log.Printf("sudoers: config updated key=%s by %s", key, viewerFromContext(r))
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

// validateSudoers checks the syntax of content using visudo -c.
func validateSudoers(content string) error {
	tmpFile, err := os.CreateTemp("", "sudoers-valid-*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	if _, err := tmpFile.WriteString(content); err != nil {
		return fmt.Errorf("write temp: %w", err)
	}
	_ = tmpFile.Close()

	// visudo -c -f <file> checks syntax without affecting the system.
	cmd := exec.Command("visudo", "-c", "-f", tmpFile.Name())
	out, err := cmd.CombinedOutput()
	if err != nil {
		// Clean up output to remove the temp filename and just show the error.
		msg := strings.ReplaceAll(string(out), tmpFile.Name(), "sudoers")
		msg = strings.TrimSpace(msg)
		return errors.New(msg)
	}
	return nil
}

func stripSudoersHeader(text string) string {
	lines := strings.Split(text, "\n")
	var out []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" ||
			strings.HasPrefix(trimmed, "# Managed by sudo-logger") ||
			strings.HasPrefix(trimmed, "# Generated:") ||
			strings.HasPrefix(trimmed, "# ---") {
			continue
		}
		// Normalize line: internal spacing and redundant (ALL)
		l := strings.Join(strings.Fields(trimmed), " ")
		l = strings.ReplaceAll(l, "(ALL) ", "")
		l = strings.ReplaceAll(l, "(ALL:ALL) ", "")
		l = strings.ReplaceAll(l, "(ALL)", "")
		l = strings.ReplaceAll(l, "(ALL:ALL)", "")
		// Strip spaces around operators to match visudo variations
		l = strings.ReplaceAll(l, " = ", "=")
		l = strings.ReplaceAll(l, "= ", "=")
		l = strings.ReplaceAll(l, " =", "=")
		l = strings.ReplaceAll(l, " : ", ":")
		l = strings.ReplaceAll(l, ": ", ":")
		l = strings.ReplaceAll(l, " :", ":")
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}

func extractManagedSudoers(full string) string {
	marker := "# --- /etc/sudoers.d/sudo-logger-managed ---"
	idx := strings.Index(full, marker)
	if idx == -1 {
		return ""
	}
	content := full[idx+len(marker):]
	if endIdx := strings.Index(content, "# --- "); endIdx != -1 {
		content = content[:endIdx]
	}
	return stripSudoersHeader(content)
}

// handleDeleteSudoersConfig removes a host-specific config override, causing
// the agent to fall back to the _default template.
func handleDeleteSudoersConfig(w http.ResponseWriter, r *http.Request) {
	if !require(w, r, store.PermConfigWrite) {
		return
	}
	host := r.URL.Query().Get("host")
	if host == "" {
		http.Error(w, "host required for delete", http.StatusBadRequest)
		return
	}
	if !util.ValidAgentHost(host) {
		http.Error(w, "invalid host", http.StatusBadRequest)
		return
	}
	if err := sessionStore.SetConfig(r.Context(), "sudoers/"+host, ""); err != nil {
		http.Error(w, "delete config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	log.Printf("sudoers: config deleted for host=%s by %s", host, viewerFromContext(r))
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}
