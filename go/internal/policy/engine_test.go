package policy_test

import (
	"context"
	"strings"
	"testing"

	"sudo-logger/internal/policy"
)

func TestEngine_BasicDecisions(t *testing.T) {
	p := &policy.Policy{
		DefaultAction: "challenge",
		Rules: []policy.Rule{
			{
				ID:      "allow-sre",
				Comment: "SRE team always allowed",
				Users:   []string{"alice", "bob"},
				Hosts:   []string{"*"},
				Action:  "allow",
				HourFrom: -1, HourTo: -1,
			},
			{
				ID:      "deny-contractors",
				Comment: "Contractors always blocked",
				Users:   []string{"contractor-*"},
				Action:  "deny",
				HourFrom: -1, HourTo: -1,
			},
		},
	}

	eng, err := policy.NewEngine(p)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	ctx := context.Background()

	cases := []struct {
		user string
		want policy.Decision
	}{
		{"alice", policy.DecisionAllow},
		{"bob", policy.DecisionAllow},
		{"contractor-foo", policy.DecisionDeny},
		{"charlie", policy.DecisionChallenge},
	}

	for _, c := range cases {
		got := eng.Eval(ctx, policy.Input{User: c.user, Host: "prod-01", Runas: "root", Command: "/bin/bash"})
		if got != c.want {
			t.Errorf("user=%s: got %s, want %s", c.user, got, c.want)
		}
	}
}

func TestEngine_GlobPatterns(t *testing.T) {
	p := &policy.Policy{
		DefaultAction: "challenge",
		Rules: []policy.Rule{
			{
				ID:     "allow-dev",
				Users:  []string{"*"},
				Hosts:  []string{"dev-*"},
				Action: "allow",
				HourFrom: -1, HourTo: -1,
			},
		},
	}

	eng, err := policy.NewEngine(p)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	ctx := context.Background()

	if got := eng.Eval(ctx, policy.Input{User: "alice", Host: "dev-01"}); got != policy.DecisionAllow {
		t.Errorf("dev-01: want allow, got %s", got)
	}
	if got := eng.Eval(ctx, policy.Input{User: "alice", Host: "prod-01"}); got != policy.DecisionChallenge {
		t.Errorf("prod-01: want challenge, got %s", got)
	}
}

func TestEngine_DenyOverridesAllow(t *testing.T) {
	p := &policy.Policy{
		DefaultAction: "challenge",
		Rules: []policy.Rule{
			{ID: "allow-all", Users: []string{"*"}, Action: "allow", HourFrom: -1, HourTo: -1},
			{ID: "deny-root", Runas: []string{"root"}, Action: "deny", HourFrom: -1, HourTo: -1},
		},
	}
	eng, err := policy.NewEngine(p)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	ctx := context.Background()

	if got := eng.Eval(ctx, policy.Input{User: "alice", Runas: "root"}); got != policy.DecisionDeny {
		t.Errorf("root: want deny, got %s", got)
	}
	if got := eng.Eval(ctx, policy.Input{User: "alice", Runas: "www-data"}); got != policy.DecisionAllow {
		t.Errorf("www-data: want allow, got %s", got)
	}
}

func TestEngine_Update(t *testing.T) {
	p := &policy.Policy{DefaultAction: "challenge", Rules: nil}
	eng, err := policy.NewEngine(p)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	ctx := context.Background()

	if got := eng.Eval(ctx, policy.Input{User: "alice"}); got != policy.DecisionChallenge {
		t.Errorf("before update: want challenge, got %s", got)
	}

	p2 := &policy.Policy{
		DefaultAction: "challenge",
		Rules: []policy.Rule{
			{ID: "allow-all", Users: []string{"*"}, Action: "allow", HourFrom: -1, HourTo: -1},
		},
	}
	if err := eng.Update(p2); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if got := eng.Eval(ctx, policy.Input{User: "alice"}); got != policy.DecisionAllow {
		t.Errorf("after update: want allow, got %s", got)
	}
}

func TestCompileToRego_Valid(t *testing.T) {
	p := &policy.Policy{
		DefaultAction: "challenge",
		Rules: []policy.Rule{
			{ID: "r1", Users: []string{"alice", "bob"}, Hosts: []string{"prod-*"}, Action: "deny", HourFrom: -1, HourTo: -1},
			{ID: "r2", Users: []string{"*"}, Action: "allow", HourFrom: 8, HourTo: 18},
		},
		RawRego: "# custom comment\n",
	}
	src := policy.CompileToRego(p)
	if src == "" {
		t.Fatal("CompileToRego returned empty string")
	}
	// Should contain the package declaration
	if !strings.Contains(src, "package sudo_logger.jit") {
		t.Error("missing package declaration")
	}
}
