package main

// Tests for the reporting engine: fmtDur and buildReport's anomaly
// detection / summary aggregation.

import (
	"strings"
	"testing"
	"time"
)

// ── fmtDur ────────────────────────────────────────────────────────────────────

func TestFmtDur(t *testing.T) {
	tests := []struct {
		secs float64
		want string
	}{
		// Sub-minute durations round UP to "1m" (the +1 in the else branch),
		// so even a 0-second duration displays as "1m", not "0m".
		{0, "1m"},
		{30, "1m"},
		{59, "1m"},
		// A full 60-second duration still takes the h==0 branch (m+1), so it
		// displays as "2m" rather than "1m" — a real quirk of the rounding,
		// documented here rather than silently "corrected".
		{60, "2m"},
		{3600, "1h 0m"},
		{3661, "1h 1m"},
		{7199, "1h 59m"},
	}
	for _, tt := range tests {
		if got := fmtDur(tt.secs); got != tt.want {
			t.Errorf("fmtDur(%v) = %q, want %q", tt.secs, got, tt.want)
		}
	}
}

// ── buildReport ───────────────────────────────────────────────────────────────

// seedCache installs sessions directly into the package-level session cache,
// bypassing the store entirely — buildReport reads from cache.get(), so this
// is the fastest way to exercise its pure aggregation logic.
func seedCache(t *testing.T, sessions []SessionInfo) {
	t.Helper()
	cache.mu.Lock()
	cache.sessions = sessions
	cache.built = true
	cache.lastScan = time.Now()
	cache.mu.Unlock()
	t.Cleanup(func() {
		cache.mu.Lock()
		cache.built = false
		cache.sessions = nil
		cache.mu.Unlock()
	})
}

// daytime returns a StartTime that is never after-hours (noon local), so
// tests targeting a different anomaly kind don't accidentally also trigger
// "after_hours".
func daytime() int64 {
	return time.Date(2026, 1, 1, 12, 0, 0, 0, time.Local).Unix()
}

func findAnomaly(anomalies []Anomaly, tsid, kind string) *Anomaly {
	for i := range anomalies {
		if anomalies[i].TSID == tsid && anomalies[i].Kind == kind {
			return &anomalies[i]
		}
	}
	return nil
}

func TestBuildReport_IncompleteAnomaly(t *testing.T) {
	seedCache(t, []SessionInfo{
		{TSID: "u/h_1", User: "alice", Host: "h1", Command: "vim", StartTime: daytime(), Duration: 60, Incomplete: true},
	})
	report, err := buildReport(t.Context(), 0, 0, "")
	if err != nil {
		t.Fatalf("buildReport: %v", err)
	}
	if findAnomaly(report.Anomalies, "u/h_1", "incomplete") == nil {
		t.Error("expected an 'incomplete' anomaly")
	}
	if report.Summary.IncompleteSessions != 1 {
		t.Errorf("IncompleteSessions = %d, want 1", report.Summary.IncompleteSessions)
	}
}

func TestBuildReport_AfterHoursAnomaly(t *testing.T) {
	night := time.Date(2026, 1, 1, 3, 0, 0, 0, time.Local).Unix()
	seedCache(t, []SessionInfo{
		{TSID: "u/h_1", User: "alice", Host: "h1", Command: "vim", StartTime: night, Duration: 60},
	})
	report, err := buildReport(t.Context(), 0, 0, "")
	if err != nil {
		t.Fatalf("buildReport: %v", err)
	}
	if findAnomaly(report.Anomalies, "u/h_1", "after_hours") == nil {
		t.Error("expected an 'after_hours' anomaly")
	}
}

func TestBuildReport_LongSessionAnomaly(t *testing.T) {
	seedCache(t, []SessionInfo{
		{TSID: "u/h_1", User: "alice", Host: "h1", Command: "vim", StartTime: daytime(), Duration: 7201},
	})
	report, err := buildReport(t.Context(), 0, 0, "")
	if err != nil {
		t.Fatalf("buildReport: %v", err)
	}
	a := findAnomaly(report.Anomalies, "u/h_1", "long_session")
	if a == nil {
		t.Fatal("expected a 'long_session' anomaly")
		return
	}
	if !strings.Contains(a.Detail, "2h") {
		t.Errorf("long_session detail = %q, want it to mention the duration", a.Detail)
	}
	if report.Summary.LongSessions != 1 {
		t.Errorf("LongSessions = %d, want 1", report.Summary.LongSessions)
	}
}

func TestBuildReport_RootShellAnomaly(t *testing.T) {
	seedCache(t, []SessionInfo{
		{TSID: "u/h_1", User: "alice", Host: "h1", Command: "bash", Runas: "root", StartTime: daytime(), Duration: 60},
	})
	report, err := buildReport(t.Context(), 0, 0, "")
	if err != nil {
		t.Fatalf("buildReport: %v", err)
	}
	if findAnomaly(report.Anomalies, "u/h_1", "root_shell") == nil {
		t.Error("expected a 'root_shell' anomaly")
	}
}

func TestBuildReport_RootNonShellCommandNoAnomaly(t *testing.T) {
	// Runas=root alone shouldn't flag root_shell unless the command base is
	// an actual interactive shell.
	seedCache(t, []SessionInfo{
		{TSID: "u/h_1", User: "alice", Host: "h1", Command: "systemctl status", Runas: "root", StartTime: daytime(), Duration: 60},
	})
	report, err := buildReport(t.Context(), 0, 0, "")
	if err != nil {
		t.Fatalf("buildReport: %v", err)
	}
	if findAnomaly(report.Anomalies, "u/h_1", "root_shell") != nil {
		t.Error("systemctl as root should not be flagged as root_shell")
	}
}

func TestBuildReport_HighRiskAnomaly(t *testing.T) {
	seedCache(t, []SessionInfo{
		{TSID: "u/h_1", User: "alice", Host: "h1", Command: "vim", StartTime: daytime(), Duration: 60,
			RiskScore: 60, RiskReasons: []string{"reason one", "reason two"}},
	})
	report, err := buildReport(t.Context(), 0, 0, "")
	if err != nil {
		t.Fatalf("buildReport: %v", err)
	}
	a := findAnomaly(report.Anomalies, "u/h_1", "high_risk")
	if a == nil {
		t.Fatal("expected a 'high_risk' anomaly")
		return
	}
	if a.Detail != "reason one; reason two" {
		t.Errorf("high_risk detail = %q, want joined risk reasons", a.Detail)
	}
	if report.Summary.HighRiskSessions != 1 {
		t.Errorf("HighRiskSessions = %d, want 1", report.Summary.HighRiskSessions)
	}
}

func TestBuildReport_CriticalCountedSeparatelyFromHighRisk(t *testing.T) {
	seedCache(t, []SessionInfo{
		{TSID: "u/h_1", User: "alice", Host: "h1", Command: "vim", StartTime: daytime(), Duration: 60, RiskScore: 80},
	})
	report, err := buildReport(t.Context(), 0, 0, "")
	if err != nil {
		t.Fatalf("buildReport: %v", err)
	}
	if report.Summary.CriticalSessions != 1 {
		t.Errorf("CriticalSessions = %d, want 1", report.Summary.CriticalSessions)
	}
	if report.Summary.HighRiskSessions != 0 {
		t.Errorf("HighRiskSessions = %d, want 0 (score >=75 counts as critical, not high_risk)", report.Summary.HighRiskSessions)
	}
}

// TestBuildReport_IncompleteHighRiskNotDoubleCounted verifies the
// dedup guard: a session that is both incomplete AND high-risk should only
// produce the higher-priority "incomplete" anomaly, not also "high_risk".
func TestBuildReport_IncompleteHighRiskNotDoubleCounted(t *testing.T) {
	seedCache(t, []SessionInfo{
		{TSID: "u/h_1", User: "alice", Host: "h1", Command: "vim", StartTime: daytime(), Duration: 60,
			Incomplete: true, RiskScore: 60, RiskReasons: []string{"x"}},
	})
	report, err := buildReport(t.Context(), 0, 0, "")
	if err != nil {
		t.Fatalf("buildReport: %v", err)
	}
	var count int
	for _, a := range report.Anomalies {
		if a.TSID == "u/h_1" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 anomaly for a session that is both incomplete and high-risk, got %d", count)
	}
	if findAnomaly(report.Anomalies, "u/h_1", "incomplete") == nil {
		t.Error("expected the 'incomplete' anomaly to take priority")
	}
}

func TestBuildReport_SummaryAggregation(t *testing.T) {
	seedCache(t, []SessionInfo{
		{TSID: "alice/h1_1", User: "alice", Host: "h1", Command: "vim", StartTime: 1000, Duration: 60},
		{TSID: "alice/h2_1", User: "alice", Host: "h2", Command: "vim", StartTime: 2000, Duration: 60},
		{TSID: "bob/h1_1", User: "bob", Host: "h1", Command: "vim", StartTime: 3000, Duration: 60},
	})
	report, err := buildReport(t.Context(), 0, 0, "")
	if err != nil {
		t.Fatalf("buildReport: %v", err)
	}
	if report.Summary.TotalSessions != 3 {
		t.Errorf("TotalSessions = %d, want 3", report.Summary.TotalSessions)
	}
	if report.Summary.UniqueUsers != 2 {
		t.Errorf("UniqueUsers = %d, want 2", report.Summary.UniqueUsers)
	}
	if report.Summary.UniqueHosts != 2 {
		t.Errorf("UniqueHosts = %d, want 2", report.Summary.UniqueHosts)
	}
	if report.Summary.PeriodFrom != 1000 || report.Summary.PeriodTo != 3000 {
		t.Errorf("period = [%d, %d], want [1000, 3000]", report.Summary.PeriodFrom, report.Summary.PeriodTo)
	}
	if len(report.PerUser) != 2 {
		t.Fatalf("PerUser entries = %d, want 2", len(report.PerUser))
	}
	// alice has 2 sessions, bob has 1 — sorted by session count descending.
	if report.PerUser[0].User != "alice" || report.PerUser[0].Sessions != 2 {
		t.Errorf("top user = %+v, want alice with 2 sessions", report.PerUser[0])
	}
}

func TestBuildReport_TimeRangeFilter(t *testing.T) {
	seedCache(t, []SessionInfo{
		{TSID: "u/h_1", User: "alice", Host: "h1", Command: "vim", StartTime: 1000, Duration: 60},
		{TSID: "u/h_2", User: "alice", Host: "h1", Command: "vim", StartTime: 5000, Duration: 60},
	})
	report, err := buildReport(t.Context(), 2000, 6000, "")
	if err != nil {
		t.Fatalf("buildReport: %v", err)
	}
	if report.Summary.TotalSessions != 1 {
		t.Fatalf("TotalSessions = %d, want 1 (only the session inside [2000,6000])", report.Summary.TotalSessions)
	}
	if report.Summary.PeriodFrom != 5000 || report.Summary.PeriodTo != 5000 {
		t.Errorf("period = [%d, %d], want [5000, 5000] (only the surviving session)", report.Summary.PeriodFrom, report.Summary.PeriodTo)
	}
}
