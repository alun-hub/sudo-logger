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
	ID        string   `json:"id"`
	Comment   string   `json:"comment,omitempty"`
	Users     []string `json:"users"`                // glob patterns or @groupname; [] or ["*"] = all
	Hosts     []string `json:"hosts"`                // glob patterns or @groupname
	Commands  []string `json:"commands"`             // glob patterns
	Runas     []string `json:"runas"`                // glob patterns or @groupname
	SysGroups []string `json:"sys_groups,omitempty"` // user must be member of ALL these groups (LDAP/AD via input.groups)
	Weekdays  []int    `json:"weekdays,omitempty"`   // 0=Sun..6=Sat; empty = all days
	HourFrom  int      `json:"hour_from"`            // 0-23; -1 = no time constraint
	HourTo    int      `json:"hour_to"`              // exclusive; -1 = no constraint
	Action    string   `json:"action"`               // "allow" | "challenge" | "deny"
}

// Policy is the full JIT authorization configuration.
type Policy struct {
	Groups        map[string][]string `json:"groups,omitempty"` // local group definitions: name → member patterns
	Rules         []Rule              `json:"rules"`
	DefaultAction string              `json:"default_action"` // "allow" | "challenge"
	RawRego       string              `json:"raw_rego,omitempty"`
}

// DefaultPolicy returns a safe starting policy (challenge everything).
func DefaultPolicy() Policy {
	return Policy{DefaultAction: "challenge", Rules: []Rule{}}
}

// Validate returns an error if the policy is structurally invalid.
func (p *Policy) Validate() error {
	for i, r := range p.Rules {
		if strings.ContainsAny(r.ID, "\r\n") {
			return fmt.Errorf("rule %d: ID cannot contain newline characters", i)
		}
		if strings.ContainsAny(r.Comment, "\r\n") {
			return fmt.Errorf("rule %d (%s): comment cannot contain newline characters", i, r.ID)
		}
		switch r.Action {
		case "allow", "challenge", "deny":
		default:
			return fmt.Errorf("rule %d (%s): unknown action %q", i, r.ID, r.Action)
		}
		// Verify all @groupname references exist.
		for _, field := range [][]string{r.Users, r.Hosts, r.Runas} {
			for _, pat := range field {
				if strings.HasPrefix(pat, "@") {
					name := pat[1:]
					if _, ok := p.Groups[name]; !ok {
						return fmt.Errorf("rule %d (%s): unknown group %q", i, r.ID, pat)
					}
				}
			}
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
//
// Local groups (Policy.Groups) are emitted as _group_<name>(v) helpers.
// Rules can reference them with "@groupname" in Users/Hosts/Runas fields.
// System groups (Rule.SysGroups) are checked against input.groups (populated
// by the agent via NSS — covers local, SSSD, LDAP, AD, winbind groups).
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

	// Emit local group helpers.
	if len(p.Groups) > 0 {
		b.WriteString("# ── Local group definitions ────────────────────────────────\n")
		for name, members := range p.Groups {
			effective := effectivePatterns(members)
			safe := safeGroupName(name)
			if len(effective) == 0 {
				fmt.Fprintf(&b, "_group_%s(_) if false\n\n", safe)
				continue
			}
			if len(effective) == 1 {
				m := effective[0]
				if strings.ContainsAny(m, "*?") {
					fmt.Fprintf(&b, "_group_%s(v) if { glob.match(%q, [], v) }\n\n", safe, m)
				} else {
					fmt.Fprintf(&b, "_group_%s(v) if { v == %q }\n\n", safe, m)
				}
			} else {
				fmt.Fprintf(&b, "_group_%s(v) if { some _p in {%s}; glob.match(_p, [], v) }\n\n",
					safe, quotedSet(effective))
			}
		}
	}

	// _any_deny clauses
	denyRules := rulesFor(p.Rules, "deny")
	if len(denyRules) == 0 {
		b.WriteString("_any_deny if false\n\n")
	} else {
		for i, r := range denyRules {
			emitRuleHelpers(&b, i, "deny", r, p.Groups)
			emitClause(&b, "_any_deny", i, "deny", r, p.Groups)
		}
	}

	// _any_allow clauses
	allowRules := rulesFor(p.Rules, "allow")
	if len(allowRules) == 0 {
		b.WriteString("_any_allow if false\n\n")
	} else {
		for i, r := range allowRules {
			emitRuleHelpers(&b, i, "allow", r, p.Groups)
			emitClause(&b, "_any_allow", i, "allow", r, p.Groups)
		}
	}

	// Challenge rules reach the default — add comment for auditability.
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

// emitRuleHelpers emits per-rule field-matcher helpers when a field mixes
// @groupname references with literal patterns (OR semantics need multiple clauses).
// Also emits an overnight time-window helper when hour_from > hour_to.
func emitRuleHelpers(b *strings.Builder, idx int, action string, r Rule, groups map[string][]string) {
	for _, fd := range []struct {
		name     string
		patterns []string
	}{
		{"user", r.Users},
		{"host", r.Hosts},
		{"runas", r.Runas},
	} {
		if needsHelper(fd.patterns) {
			emitFieldHelper(b, idx, action, fd.name, fd.patterns)
		}
	}
	// Overnight time ranges need a helper because OPA v1 does not allow
	// inline `or` inside a rule body.
	if r.HourFrom >= 0 && r.HourTo >= 0 && r.HourFrom > r.HourTo {
		name := fmt.Sprintf("_time_ok_%s_%d", action, idx)
		fmt.Fprintf(b, "%s if { input.hour >= %d }\n", name, r.HourFrom)
		fmt.Fprintf(b, "%s if { input.hour < %d }\n\n", name, r.HourTo)
	}
}

// needsHelper returns true when patterns mix @-refs with literals.
func needsHelper(patterns []string) bool {
	hasRef, hasLit := false, false
	for _, p := range patterns {
		if p == "*" || p == "" {
			continue
		}
		if strings.HasPrefix(p, "@") {
			hasRef = true
		} else {
			hasLit = true
		}
	}
	return hasRef && hasLit // only need helper for mixed
}

// emitFieldHelper emits `_match_<field>_<action>_<idx>(v)` with one clause per pattern.
func emitFieldHelper(b *strings.Builder, idx int, action, field string, patterns []string) {
	name := fmt.Sprintf("_match_%s_%s_%d", field, action, idx)
	for _, p := range patterns {
		if p == "*" || p == "" {
			// Wildcard: helper always succeeds.
			fmt.Fprintf(b, "%s(_) if { true }\n", name)
			return
		}
		if strings.HasPrefix(p, "@") {
			safe := safeGroupName(p[1:])
			fmt.Fprintf(b, "%s(v) if { _group_%s(v) }\n", name, safe)
		} else if strings.ContainsAny(p, "*?") {
			fmt.Fprintf(b, "%s(v) if { glob.match(%q, [], v) }\n", name, p)
		} else {
			fmt.Fprintf(b, "%s(v) if { v == %q }\n", name, p)
		}
	}
	b.WriteString("\n")
}

// emitClause writes the main `_any_deny/_any_allow if { ... }` block.
func emitClause(b *strings.Builder, name string, idx int, action string, r Rule, groups map[string][]string) {
	cmt := r.Comment
	if cmt == "" {
		cmt = r.ID
	}
	cmt = strings.ReplaceAll(cmt, "\n", " ")
	cmt = strings.ReplaceAll(cmt, "\r", " ")
	if cmt != "" {
		fmt.Fprintf(b, "# %s\n", cmt)
	}

	var body strings.Builder
	writeFieldConstraint(&body, idx, action, "user", "input.user", r.Users)
	writeFieldConstraint(&body, idx, action, "host", "input.host", r.Hosts)
	writeFieldConstraint(&body, idx, action, "runas", "input.runas", r.Runas)
	writeFieldMatch(&body, "input.command", r.Commands) // commands never use @groups
	writeSysGroupsMatch(&body, r.SysGroups)
	writeWeekdayMatch(&body, r.Weekdays)
	writeTimeMatch(&body, idx, action, r)

	if body.Len() == 0 {
		fmt.Fprintf(b, "%s if { true } # %s_%d (all-wildcard)\n\n", name, name, idx)
	} else {
		fmt.Fprintf(b, "%s if {\n%s} # %s_%d\n\n", name, body.String(), name, idx)
	}
}

// writeFieldConstraint handles a single field, routing to helper or inline.
func writeFieldConstraint(b *strings.Builder, idx int, action, fieldName, regoField string, patterns []string) {
	effective := effectivePatterns(patterns)
	if len(effective) == 0 {
		return
	}

	refs, lits := splitGroupRefs(effective)

	switch {
	case len(refs) > 0 && len(lits) > 0:
		// Mixed: use generated helper for OR semantics.
		helperName := fmt.Sprintf("_match_%s_%s_%d", fieldName, action, idx)
		fmt.Fprintf(b, "\t%s(%s)\n", helperName, regoField)

	case len(refs) > 0 && len(lits) == 0:
		// Only @group refs.
		if len(refs) == 1 {
			fmt.Fprintf(b, "\t_group_%s(%s)\n", safeGroupName(refs[0]), regoField)
		} else {
			// Multiple groups — need a helper for OR semantics.
			helperName := fmt.Sprintf("_match_%s_%s_%d", fieldName, action, idx)
			fmt.Fprintf(b, "\t%s(%s)\n", helperName, regoField)
		}

	default:
		// No @group refs — use inline matcher.
		writeFieldMatch(b, regoField, lits)
	}
}

// writeFieldMatch emits an inline field constraint (no @-refs).
func writeFieldMatch(b *strings.Builder, field string, patterns []string) {
	effective := effectivePatterns(patterns)
	if len(effective) == 0 {
		return
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
	fmt.Fprintf(b, "\tsome _p_%s in {%s}\n\tglob.match(_p_%s, [], %s)\n",
		safeField(field), quotedSet(effective), safeField(field), field)
}

// writeSysGroupsMatch emits Rego to check that the user belongs to all listed system groups.
// input.groups is populated by the agent via NSS (covers SSSD, LDAP, winbind, local).
func writeSysGroupsMatch(b *strings.Builder, sysGroups []string) {
	for _, g := range sysGroups {
		g = strings.TrimSpace(g)
		if g == "" {
			continue
		}
		fmt.Fprintf(b, "\t%q in input.groups\n", g)
	}
}

// writeWeekdayMatch emits a weekday constraint using an OPA set literal.
// Empty or all-7 slice = no constraint. 0=Sun, 1=Mon, …, 6=Sat.
func writeWeekdayMatch(b *strings.Builder, weekdays []int) {
	if len(weekdays) == 0 || len(weekdays) >= 7 {
		return
	}
	parts := make([]string, len(weekdays))
	for i, d := range weekdays {
		parts[i] = fmt.Sprintf("%d", d)
	}
	fmt.Fprintf(b, "\tinput.weekday in {%s}\n", strings.Join(parts, ", "))
}

func writeTimeMatch(b *strings.Builder, idx int, action string, r Rule) {
	if r.HourFrom < 0 || r.HourTo < 0 {
		return
	}
	if r.HourFrom <= r.HourTo {
		fmt.Fprintf(b, "\tinput.hour >= %d\n\tinput.hour < %d\n", r.HourFrom, r.HourTo)
	} else {
		// Overnight range: helper emitted by emitRuleHelpers.
		fmt.Fprintf(b, "\t_time_ok_%s_%d\n", action, idx)
	}
}

func splitGroupRefs(patterns []string) (refs, lits []string) {
	for _, p := range patterns {
		if strings.HasPrefix(p, "@") {
			refs = append(refs, p[1:]) // strip @
		} else {
			lits = append(lits, p)
		}
	}
	return
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

func effectivePatterns(patterns []string) []string {
	var out []string
	for _, p := range patterns {
		if p != "*" && p != "" {
			out = append(out, p)
		}
	}
	return out
}

func quotedSet(ss []string) string {
	parts := make([]string, len(ss))
	for i, s := range ss {
		parts[i] = fmt.Sprintf("%q", s)
	}
	return strings.Join(parts, ", ")
}

func safeField(field string) string {
	if i := strings.LastIndex(field, "."); i >= 0 {
		return field[i+1:]
	}
	return field
}

// safeGroupName makes a group name safe for use as a Rego identifier.
func safeGroupName(name string) string {
	var b strings.Builder
	for _, c := range name {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			b.WriteRune(c)
		} else {
			b.WriteRune('_')
		}
	}
	return b.String()
}
