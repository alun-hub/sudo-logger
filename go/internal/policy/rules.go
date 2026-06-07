// Package policy implements OPA-based JIT session authorization.
// Structured rules are compiled to Rego; an optional raw_rego field
// lets advanced operators append arbitrary Rego to the generated module.
package policy

import (
	"fmt"
	"strings"
)

// Rule is one row in the policy table.
type Rule struct {
	ID       string   `json:"id"`
	Comment  string   `json:"comment,omitempty"`
	Users    []string `json:"users"`    // glob patterns; [] or ["*"] = all
	Hosts    []string `json:"hosts"`    // glob patterns
	Commands []string `json:"commands"` // glob patterns
	Runas    []string `json:"runas"`    // glob patterns
	HourFrom int      `json:"hour_from"` // 0-23; -1 = no time constraint
	HourTo   int      `json:"hour_to"`   // exclusive; -1 = no constraint
	Action   string   `json:"action"`    // "allow" | "challenge" | "deny"
}

// Policy is the full JIT authorization configuration.
type Policy struct {
	Rules         []Rule `json:"rules"`
	DefaultAction string `json:"default_action"` // "allow" | "challenge"
	RawRego       string `json:"raw_rego,omitempty"`
}

// DefaultPolicy returns a safe starting policy (challenge everything).
func DefaultPolicy() Policy {
	return Policy{DefaultAction: "challenge", Rules: []Rule{}}
}

// Validate returns an error if the policy is structurally invalid.
func (p *Policy) Validate() error {
	for i, r := range p.Rules {
		switch r.Action {
		case "allow", "challenge", "deny":
		default:
			return fmt.Errorf("rule %d (%s): unknown action %q", i, r.ID, r.Action)
		}
	}
	switch p.DefaultAction {
	case "allow", "challenge", "":
	default:
		return fmt.Errorf("invalid default_action %q", p.DefaultAction)
	}
	return nil
}

// CompileToRego generates a self-contained OPA v1 Rego module from the policy.
//
// Priority: deny > allow > default (challenge).
// OR-semantics within each field are expressed via:
//
//	some p in {"pat1", "pat2"}; glob.match(p, [], field)
//
// The raw_rego field is appended verbatim after the generated rules.
func CompileToRego(p *Policy) string {
	var b strings.Builder

	b.WriteString("package sudo_logger.jit\n\n")

	def := "challenge"
	if p.DefaultAction == "allow" {
		def = "allow"
	}
	fmt.Fprintf(&b, "default decision := %q\n\n", def)

	// Top-level decision rules — deny wins over allow.
	b.WriteString("decision := \"deny\" if _any_deny\n")
	b.WriteString("decision := \"allow\" if {\n\tnot _any_deny\n\t_any_allow\n}\n\n")

	// _any_deny clauses
	denyRules := rulesFor(p.Rules, "deny")
	if len(denyRules) == 0 {
		b.WriteString("_any_deny if false\n\n")
	} else {
		for i, r := range denyRules {
			emitClause(&b, "_any_deny", i, r)
		}
	}

	// _any_allow clauses
	allowRules := rulesFor(p.Rules, "allow")
	if len(allowRules) == 0 {
		b.WriteString("_any_allow if false\n\n")
	} else {
		for i, r := range allowRules {
			emitClause(&b, "_any_allow", i, r)
		}
	}

	// challenge rules reach the default — just add comments for auditability.
	for _, r := range rulesFor(p.Rules, "challenge") {
		cmt := r.ID
		if r.Comment != "" {
			cmt = r.Comment
		}
		fmt.Fprintf(&b, "# challenge rule %q — falls through to default\n\n", cmt)
	}

	if raw := strings.TrimSpace(p.RawRego); raw != "" {
		b.WriteString("# ── User-defined Rego ─────────────────────────────────────\n")
		b.WriteString(raw)
		b.WriteString("\n")
	}

	return b.String()
}

func rulesFor(rules []Rule, action string) []Rule {
	var out []Rule
	for _, r := range rules {
		if r.Action == action {
			out = append(out, r)
		}
	}
	return out
}

// emitClause writes one `name if { ... }` block for the given rule.
// OR within a field is expressed as: some p in {pats}; glob.match(p, [], field)
func emitClause(b *strings.Builder, name string, idx int, r Rule) {
	cmt := r.Comment
	if cmt == "" {
		cmt = r.ID
	}
	if cmt != "" {
		fmt.Fprintf(b, "# %s\n", cmt)
	}

	var body strings.Builder
	writeFieldMatch(&body, "input.user", r.Users)
	writeFieldMatch(&body, "input.host", r.Hosts)
	writeFieldMatch(&body, "input.runas", r.Runas)
	writeFieldMatch(&body, "input.command", r.Commands)
	writeTimeMatch(&body, r)

	if body.Len() == 0 {
		// All-wildcard rule matches unconditionally.
		fmt.Fprintf(b, "%s if { true } # %s_%d (all-wildcard)\n\n", name, name, idx)
	} else {
		fmt.Fprintf(b, "%s if {\n%s} # %s_%d\n\n", name, body.String(), name, idx)
	}
}

// writeFieldMatch emits Rego for one field constraint (OR across patterns).
func writeFieldMatch(b *strings.Builder, field string, patterns []string) {
	effective := effectivePatterns(patterns)
	if len(effective) == 0 {
		return // wildcard or empty → no constraint
	}
	if len(effective) == 1 {
		p := effective[0]
		if strings.ContainsAny(p, "*?") {
			fmt.Fprintf(b, "\tglob.match(%q, [], %s)\n", p, field)
		} else {
			fmt.Fprintf(b, "\t%s == %q\n", field, p)
		}
		return
	}
	// Multiple patterns: some p in {set}; glob.match(p, [], field)
	// glob.match handles both exact and glob patterns correctly.
	fmt.Fprintf(b, "\tsome _p_%s in {%s}\n\tglob.match(_p_%s, [], %s)\n",
		safeField(field), quotedSet(effective), safeField(field), field)
}

// effectivePatterns removes wildcard-only entries. Returns nil if all patterns are "*".
func effectivePatterns(patterns []string) []string {
	var out []string
	for _, p := range patterns {
		if p != "*" && p != "" {
			out = append(out, p)
		}
	}
	return out
}

func writeTimeMatch(b *strings.Builder, r Rule) {
	if r.HourFrom < 0 || r.HourTo < 0 {
		return
	}
	if r.HourFrom <= r.HourTo {
		// Normal range, e.g. 8..18 = business hours
		fmt.Fprintf(b, "\tinput.hour >= %d\n\tinput.hour < %d\n", r.HourFrom, r.HourTo)
	} else {
		// Overnight, e.g. 18..8 = outside business hours
		fmt.Fprintf(b, "\t# overnight range %d..%d\n", r.HourFrom, r.HourTo)
		fmt.Fprintf(b, "\t(input.hour >= %d or input.hour < %d)\n", r.HourFrom, r.HourTo)
	}
}

func quotedSet(ss []string) string {
	parts := make([]string, len(ss))
	for i, s := range ss {
		parts[i] = fmt.Sprintf("%q", s)
	}
	return strings.Join(parts, ", ")
}

// safeField turns "input.user" → "user" for use as a Rego variable suffix.
func safeField(field string) string {
	if i := strings.LastIndex(field, "."); i >= 0 {
		return field[i+1:]
	}
	return field
}
