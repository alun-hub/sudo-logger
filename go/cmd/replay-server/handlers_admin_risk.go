package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// computeRulesHash returns a short FNV-32 hex hash of the YAML content.
func computeRulesHash(data []byte) string {
	h := fnv.New32a()
	h.Write(data)
	return fmt.Sprintf("%08x", h.Sum32())
}

// loadRules reads and parses the rules YAML file, updating the globals
// only when the content hash has changed.
func loadRules(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read rules file %s: %w", path, err)
	}
	hash := computeRulesHash(data)
	rulesMu.RLock()
	unchanged := hash == globalRulesHash
	rulesMu.RUnlock()
	if unchanged {
		return nil
	}
	var rs RuleSet
	if err := yaml.Unmarshal(data, &rs); err != nil {
		return fmt.Errorf("parse rules file: %w", err)
	}
	rulesMu.Lock()
	globalRules = rs.Rules
	globalRulesHash = hash
	rulesMu.Unlock()
	log.Printf(`{"time":%q,"event":"config_reload","config":"risk-rules.yaml","sha256":%q,"rules":%d}`,
		time.Now().UTC().Format(time.RFC3339), hash, len(rs.Rules))
	return nil
}

// loadRulesFromText parses YAML rules from an in-memory string.
// A empty text is treated as "no rules" and is a no-op.
func loadRulesFromText(text string) error {
	if text == "" {
		return nil
	}
	data := []byte(text)
	hash := computeRulesHash(data)
	rulesMu.RLock()
	unchanged := hash == globalRulesHash
	rulesMu.RUnlock()
	if unchanged {
		return nil
	}
	var rs RuleSet
	if err := yaml.Unmarshal(data, &rs); err != nil {
		return fmt.Errorf("parse rules: %w", err)
	}
	rulesMu.Lock()
	globalRules = rs.Rules
	globalRulesHash = hash
	rulesMu.Unlock()
	log.Printf(`{"time":%q,"event":"config_reload","config":"risk-rules.yaml","sha256":%q,"rules":%d}`,
		time.Now().UTC().Format(time.RFC3339), hash, len(rs.Rules))
	return nil
}

// containsAny reports whether text contains at least one of terms.
func containsAny(text string, terms []string) bool {
	for _, s := range terms {
		if strings.Contains(text, strings.ToLower(s)) {
			return true
		}
	}
	return false
}

// matchPattern returns true when text satisfies both ContainsAny and AlsoAny.
// When both groups are set, at least one ContainsAny term and at least one
// AlsoAny term must appear on the same line of text. Matching each group
// independently against the whole blob would let unrelated lines (e.g. an
// `ls` line naming "sudo-log" and an unrelated `dmesg` line containing
// "stop") jointly satisfy a rule meant to catch a single command or a single
// block of terminal output.
func matchPattern(p *MatchPattern, text string) bool {
	switch {
	case p == nil:
		return false
	case len(p.ContainsAny) == 0 && len(p.AlsoAny) == 0:
		return true
	case len(p.AlsoAny) == 0:
		return containsAny(text, p.ContainsAny)
	case len(p.ContainsAny) == 0:
		return containsAny(text, p.AlsoAny)
	}
	for _, line := range strings.Split(text, "\n") {
		if containsAny(line, p.ContainsAny) && containsAny(line, p.AlsoAny) {
			return true
		}
	}
	return false
}

// matchesRule returns true when all conditions in the rule are satisfied.
// Metadata conditions (runas, incomplete, after_hours, min_duration) are ANDed.
// command_base_any, command, and content are ORed with each other — at least
// one must match if any of the three is specified. This allows a single rule
// to catch both "sudo visudo" (command_base_any matches) and "sudo bash →
// type visudo" (content matches) without requiring separate rules.
func matchesRule(rule Rule, s *SessionInfo, cmd, cmdBase string, getContent func() string) bool {
	if rule.Source != "" && s.Source != rule.Source {
		return false
	}
	if rule.ExitCode != nil && s.ExitCode != *rule.ExitCode {
		return false
	}
	if rule.Incomplete != nil {
		// A freeze-timeout is a network event, not a security incident — treat
		// it as "not unexpectedly terminated" for risk scoring purposes so it
		// doesn't accumulate the same score as a agent-killed session.
		incompleteForSecurity := s.Incomplete && !s.NetworkOutage
		if *rule.Incomplete != incompleteForSecurity {
			return false
		}
	}
	if rule.AfterHours != nil {
		t := time.Unix(s.StartTime, 0)
		h := t.Hour()
		isAfterHours := h < 6 || h >= 23
		if *rule.AfterHours != isAfterHours {
			return false
		}
	}
	if rule.MinDuration > 0 && s.Duration < rule.MinDuration {
		return false
	}
	if rule.Runas != "" && !strings.EqualFold(s.Runas, rule.Runas) {
		return false
	}
	// command_base_any, command, and content are all ORed — at least one must
	// match if any is specified.
	hasCmdBase := len(rule.CommandBaseAny) > 0
	hasCmd := rule.Command != nil
	hasCon := rule.Content != nil
	if hasCmdBase || hasCmd || hasCon {
		cmdBaseMatch := false
		if hasCmdBase {
			for _, b := range rule.CommandBaseAny {
				if cmdBase == strings.ToLower(b) {
					cmdBaseMatch = true
					break
				}
			}
		}
		cmdMatch := hasCmd && matchPattern(rule.Command, cmd)
		conMatch := hasCon && matchPattern(rule.Content, getContent())
		if !cmdBaseMatch && !cmdMatch && !conMatch {
			return false
		}
	}
	return true
}

// stripANSI removes ANSI CSI escape sequences (ESC [ ... <letter>) from s.
func stripANSI(s string) string {
	out := make([]byte, 0, len(s))
	i := 0
	for i < len(s) {
		if s[i] == '\x1b' && i+1 < len(s) && s[i+1] == '[' {
			// CSI: ESC [ ... final byte in 0x40-0x7e
			i += 2
			for i < len(s) && (s[i] < 0x40 || s[i] > 0x7e) {
				i++
			}
			if i < len(s) {
				i++ // consume the final command byte
			}
		} else if s[i] == '\x1b' && i+1 < len(s) && (s[i+1] == ']' || s[i+1] == 'P') {
			// OSC (]) / DCS (P): ESC <type> ... terminated by BEL or ST (ESC \)
			// so title-setting/hyperlink/etc. payloads (which can carry
			// arbitrary text) don't leak into risk-rule matching.
			i += 2
			for i < len(s) {
				if s[i] == '\x07' {
					i++
					break
				}
				if s[i] == '\x1b' && i+1 < len(s) && s[i+1] == '\\' {
					i += 2
					break
				}
				i++
			}
		} else {
			out = append(out, s[i])
			i++
		}
	}
	return string(out)
}

// loadTtyOut reads "o" (output) events via the store up to maxTtyOutBytes,
// strips ANSI codes, and returns lowercase text for pattern matching.
func loadTtyOut(ctx context.Context, tsid string) string {
	rc, err := sessionStore.OpenCast(ctx, tsid)
	if err != nil {
		return ""
	}
	defer rc.Close()

	return parseTtyOut(rc)
}

// parseTtyOut extracts and lowercases terminal output from a cast reader.
func parseTtyOut(r io.Reader) string {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 2*1024*1024), 2*1024*1024)
	// Skip header line.
	if !scanner.Scan() {
		return ""
	}

	var sb strings.Builder
	for scanner.Scan() {
		if sb.Len() >= maxTtyOutBytes {
			break
		}
		line := scanner.Bytes()
		if len(line) == 0 || line[0] != '[' {
			continue
		}
		var raw [3]json.RawMessage
		if json.Unmarshal(line, &raw) != nil {
			continue
		}
		var kind, data string
		if json.Unmarshal(raw[1], &kind) != nil || kind != "o" {
			continue
		}
		if json.Unmarshal(raw[2], &data) != nil {
			continue
		}
		sb.WriteString(data)
	}
	return strings.ToLower(stripANSI(sb.String()))
}

func hasViolation(ctx context.Context, tsid string) bool {
	violation, _ := sessionStore.HasSandboxViolation(ctx, tsid)
	return violation
}

// scoreSession computes a risk score (0–100) for a session using the globally
// loaded rules.  Results are cached via sessionStore so ttyout is only read
// once per session per rules version.
func scoreSession(s *SessionInfo) (int, []string) {
	rulesMu.RLock()
	rules := globalRules
	rulesHash := globalRulesHash
	rulesMu.RUnlock()

	ctx := context.Background()

	// Sandbox violation check must run before the cache — a violation can be
	// recorded after the session was first scored and cached.
	if s.TSID != "" && hasViolation(ctx, s.TSID) {
		return 100, []string{"Sandbox Violation"}
	}

	if cached, _ := sessionStore.GetRiskCache(ctx, s.TSID, rulesHash); cached != nil {
		return cached.Score, cached.Reasons
	}

	cmd := strings.ToLower(s.Command)
	cmdBase := ""
	if parts := strings.Fields(s.Command); len(parts) > 0 {
		cmdBase = strings.ToLower(filepath.Base(parts[0]))
	}

	// Lazy ttyout loader — only read from store if a content rule is evaluated.
	var contentOnce sync.Once
	var contentText string
	getContent := func() string {
		contentOnce.Do(func() { contentText = loadTtyOut(ctx, s.TSID) })
		return contentText
	}

	score := 0
	var reasons []string

	for _, rule := range rules {
		if score >= 100 {
			break
		}
		if !matchesRule(rule, s, cmd, cmdBase, getContent) {
			continue
		}
		pts := rule.Score
		if score+pts > 100 {
			pts = 100 - score
		}
		score += pts
		reasons = append(reasons, rule.Reason)
	}

	_ = sessionStore.SaveRiskCache(ctx, s.TSID, rulesHash, score, reasons)
	return score, reasons
}
