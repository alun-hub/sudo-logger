package main

import (
	"regexp"
	"sync"
)

// validRoleName matches safe role names: lowercase letters, digits, hyphens, underscores; 1–64 chars.
var validRoleName = regexp.MustCompile(`^[a-z0-9_-]{1,64}$`)

// MatchPattern holds substring conditions for a rule's command or content field.
// ContainsAny items are ORed; AlsoAny items are ORed — both groups must match (AND).
type MatchPattern struct {
	ContainsAny []string `yaml:"contains_any" json:"contains_any,omitempty"`
	AlsoAny     []string `yaml:"also_any"     json:"also_any,omitempty"`
}

// Rule is a single risk-scoring rule loaded from the rules YAML file.
// Metadata conditions are ANDed; command_base_any, command, and content are ORed with each other.
type Rule struct {
	ID             string        `yaml:"id"               json:"id"`
	Score          int           `yaml:"score"            json:"score"`
	Reason         string        `yaml:"reason"           json:"reason"`
	Command        *MatchPattern `yaml:"command"          json:"command,omitempty"`
	Content        *MatchPattern `yaml:"content"          json:"content,omitempty"`
	CommandBaseAny []string      `yaml:"command_base_any" json:"command_base_any,omitempty"`
	Runas          string        `yaml:"runas"            json:"runas,omitempty"`
	Incomplete     *bool         `yaml:"incomplete"       json:"incomplete,omitempty"`
	AfterHours     *bool         `yaml:"after_hours"      json:"after_hours,omitempty"`
	MinDuration    float64       `yaml:"min_duration"     json:"min_duration,omitempty"`
	// Source filters by session source ("plugin", "ebpf-tty", "ebpf-pkexec", "dbus-polkit").
	// Empty means the rule applies to all sources.
	Source   string `yaml:"source"    json:"source,omitempty"`
	// ExitCode, when non-nil, requires an exact exit-code match.
	ExitCode *int32 `yaml:"exit_code" json:"exit_code,omitempty"`
}

// RuleSet is the top-level structure of the risk-rules YAML file.
type RuleSet struct {
	Rules []Rule `yaml:"rules"`
}

// Global rule state — reloaded from disk when the rules file changes.
var (
	globalRules     []Rule
	globalRulesHash string
	rulesMu         sync.RWMutex
)

// maxTtyOutBytes is the maximum number of ttyout bytes read for content scanning.
const maxTtyOutBytes = 512 * 1024
