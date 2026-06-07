package policy

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	opaRego "github.com/open-policy-agent/opa/v1/rego"
)

// Decision is the outcome of an OPA policy evaluation.
type Decision string

const (
	DecisionAllow     Decision = "allow"
	DecisionChallenge Decision = "challenge"
	DecisionDeny      Decision = "deny"
)

// Input is the session context sent to OPA for each SESSION_START.
type Input struct {
	User    string `json:"user"`
	Host    string `json:"host"`
	Runas   string `json:"runas"`
	Command string `json:"command"`
	Cwd     string `json:"cwd"`
}

// Engine evaluates JIT authorization using an embedded OPA instance.
// Safe for concurrent use. Call Update to hot-reload the policy.
type Engine struct {
	mu     sync.RWMutex
	query  *opaRego.PreparedEvalQuery
	source string // compiled Rego source, for export
}

// NewEngine compiles a Policy and returns a ready Engine.
// Returns an error if the Rego is syntactically invalid.
func NewEngine(p *Policy) (*Engine, error) {
	e := &Engine{}
	if err := e.compile(p); err != nil {
		return nil, err
	}
	return e, nil
}

// Update hot-reloads the policy. On error the previous policy remains active.
func (e *Engine) Update(p *Policy) error {
	return e.compile(p)
}

// Source returns the last successfully compiled Rego module source.
func (e *Engine) Source() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.source
}

func (e *Engine) compile(p *Policy) error {
	src := CompileToRego(p)
	pq, err := opaRego.New(
		opaRego.Query("data.sudo_logger.jit.decision"),
		opaRego.Module("sudo_logger_jit.rego", src),
	).PrepareForEval(context.Background())
	if err != nil {
		return fmt.Errorf("compile OPA policy: %w", err)
	}

	e.mu.Lock()
	e.query = &pq
	e.source = src
	e.mu.Unlock()
	return nil
}

// Eval evaluates the policy for a session and returns the decision.
// Falls back to DecisionChallenge on any evaluation error so that
// the approval flow (request justification) is preserved.
func (e *Engine) Eval(ctx context.Context, in Input) Decision {
	if e == nil {
		return DecisionChallenge
	}

	now := time.Now()
	inputDoc := map[string]any{
		"user":    in.User,
		"host":    in.Host,
		"runas":   in.Runas,
		"command": in.Command,
		"cwd":     in.Cwd,
		"hour":    now.Hour(),
		"weekday": int(now.Weekday()), // 0 = Sunday
	}

	e.mu.RLock()
	q := e.query
	e.mu.RUnlock()

	if q == nil {
		return DecisionChallenge
	}

	rs, err := q.Eval(ctx, opaRego.EvalInput(inputDoc))
	if err != nil {
		log.Printf("policy: OPA eval error: %v", err)
		return DecisionChallenge
	}
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return DecisionChallenge
	}

	switch d, _ := rs[0].Expressions[0].Value.(string); d {
	case "allow":
		return DecisionAllow
	case "deny":
		return DecisionDeny
	default:
		return DecisionChallenge
	}
}

// ValidateRego compiles the given raw Rego source and returns any error.
// Used by the API endpoint to validate user-provided raw_rego before saving.
func ValidateRego(raw string) error {
	p := &Policy{DefaultAction: "challenge", RawRego: raw}
	src := CompileToRego(p)
	_, err := opaRego.New(
		opaRego.Query("data.sudo_logger.jit.decision"),
		opaRego.Module("sudo_logger_jit.rego", src),
	).PrepareForEval(context.Background())
	if err != nil {
		return fmt.Errorf("invalid Rego: %w", err)
	}
	return nil
}
