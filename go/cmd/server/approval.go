// approval.go — JIT sudo approval system.
//
// Flow:
//   1. SESSION_START arrives → ApprovalManager.Check() is called.
//   2. If feature disabled or user exempt → returns ApprovalResultAllow.
//   3. If an active window exists for user@host → returns ApprovalResultAllow.
//   4. If justification provided → creates pending request, fires webhook,
//      returns ApprovalResultPending (SESSION_DENIED with request ID).
//   5. If no justification → returns ApprovalResultNeedReason (SESSION_DENIED
//      asking user to provide a reason).
//
// REST API (mounted on -health-listen):
//
//	GET  /api/approvals                       — list pending requests
//	POST /api/approvals/{id}/approve?window=  — grant a time window
//	POST /api/approvals/{id}/deny             — deny (optional reason in body)
package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"sudo-logger/internal/store"
)

// ── Policy ────────────────────────────────────────────────────────────────────

type approvalPolicy struct {
	Enabled       bool              `yaml:"enabled"`
	DefaultWindow time.Duration     `yaml:"default_window"`
	PendingTTL    time.Duration     `yaml:"pending_ttl"`
	Exempt        []exemptRule      `yaml:"exempt"`
	Notifications approvalNotifyCfg `yaml:"notifications"`
}

type exemptRule struct {
	User  string   `yaml:"user"`
	Hosts []string `yaml:"hosts"` // empty = all hosts
}

type approvalNotifyCfg struct {
	WebhookURL    string `yaml:"webhook_url"`
	WebhookSecret string `yaml:"webhook_secret"`
	MentionUser   bool   `yaml:"mention_user"`
}

func (p *approvalPolicy) setDefaults() {
	if p.DefaultWindow == 0 {
		p.DefaultWindow = 30 * time.Minute
	}
	if p.PendingTTL == 0 {
		p.PendingTTL = 24 * time.Hour
	}
}

func (p *approvalPolicy) isExempt(user, host string) bool {
	for _, rule := range p.Exempt {
		if rule.User != user {
			continue
		}
		if len(rule.Hosts) == 0 {
			return true
		}
		for _, h := range rule.Hosts {
			if matchGlob(h, host) {
				return true
			}
		}
	}
	return false
}

// ── Result types ──────────────────────────────────────────────────────────────

// ApprovalResult is returned by ApprovalManager.Check.
type ApprovalResult int

const (
	ApprovalResultAllow      ApprovalResult = iota // proceed normally
	ApprovalResultPending                          // request created; SESSION_DENIED with request ID
	ApprovalResultNeedReason                       // SESSION_DENIED asking for justification
)

// CheckResult carries the outcome of ApprovalManager.Check.
type CheckResult struct {
	Result    ApprovalResult
	RequestID string // set when Result == ApprovalResultPending
}

// ── Manager ───────────────────────────────────────────────────────────────────

// ApprovalManager handles the JIT approval lifecycle.
// State persistence is delegated to the store.ApprovalStore backend so that
// both local (YAML) and distributed (PostgreSQL) deployments are supported.
type ApprovalManager struct {
	policyPath string
	backend    store.ApprovalStore

	mu     sync.RWMutex
	policy approvalPolicy
}

func newApprovalManager(policyPath string, backend store.ApprovalStore) *ApprovalManager {
	m := &ApprovalManager{
		policyPath: policyPath,
		backend:    backend,
	}
	if err := m.loadPolicy(); err != nil {
		log.Printf("approval: policy initial load: %v", err)
	}
	go m.reloadLoop()
	return m
}

func (m *ApprovalManager) reloadLoop() {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for range t.C {
		if err := m.loadPolicy(); err != nil {
			log.Printf("approval: policy reload: %v", err)
		}
	}
}

func (m *ApprovalManager) loadPolicy() error {
	data, err := os.ReadFile(m.policyPath)
	if os.IsNotExist(err) {
		m.mu.Lock()
		m.policy = approvalPolicy{}
		m.mu.Unlock()
		return nil
	}
	if err != nil {
		return err
	}
	var p approvalPolicy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return fmt.Errorf("parse approval policy: %w", err)
	}
	p.setDefaults()
	m.mu.Lock()
	m.policy = p
	m.mu.Unlock()
	log.Printf("approval: loaded policy from %s (enabled=%v, exempt=%d)",
		m.policyPath, p.Enabled, len(p.Exempt))
	return nil
}

// ── Check ─────────────────────────────────────────────────────────────────────

// Check evaluates whether the SESSION_START should be allowed, pending, or denied.
// Returns ApprovalResultAllow immediately if the manager is nil (feature not configured).
func (m *ApprovalManager) Check(user, host, command, justification, notifyVia string) CheckResult {
	if m == nil {
		return CheckResult{Result: ApprovalResultAllow}
	}
	m.mu.RLock()
	policy := m.policy
	m.mu.RUnlock()

	if !policy.Enabled {
		return CheckResult{Result: ApprovalResultAllow}
	}
	if policy.isExempt(user, host) {
		return CheckResult{Result: ApprovalResultAllow}
	}

	ctx := context.Background()
	hasWindow, err := m.backend.HasApprovalWindow(ctx, user, host)
	if err != nil {
		log.Printf("approval: HasApprovalWindow: %v", err)
	}
	if hasWindow {
		return CheckResult{Result: ApprovalResultAllow}
	}

	if strings.TrimSpace(justification) == "" {
		return CheckResult{Result: ApprovalResultNeedReason}
	}

	id := newRequestID()
	now := time.Now()
	req := store.ApprovalRequest{
		ID:            id,
		User:          user,
		Host:          host,
		Command:       command,
		Justification: justification,
		NotifyVia:     notifyVia,
		SubmittedAt:   now,
		ExpiresAt:     now.Add(policy.PendingTTL),
	}
	if err := m.backend.CreateApprovalRequest(ctx, req); err != nil {
		log.Printf("approval: CreateApprovalRequest: %v", err)
	}

	go m.sendWebhook("requested", &req, "", policy.Notifications)
	return CheckResult{Result: ApprovalResultPending, RequestID: id}
}

// RetryMessage returns the SESSION_DENIED message shown when user retries sudo.
func (m *ApprovalManager) RetryMessage(user, host string) string {
	if m == nil {
		return ""
	}
	reqs, err := m.backend.ListApprovalRequests(context.Background())
	if err != nil {
		return ""
	}
	now := time.Now()
	for _, r := range reqs {
		if r.User == user && r.Host == host && r.ExpiresAt.After(now) {
			age := now.Sub(r.SubmittedAt).Round(time.Second)
			return fmt.Sprintf("sudo-logger: approval request %s still pending (submitted %s ago). Retry when notified.", r.ID, age)
		}
	}
	return ""
}

// ── Approve / Deny ────────────────────────────────────────────────────────────

// Approve grants a time window for user@host and removes the pending request.
func (m *ApprovalManager) Approve(id, decidedBy string, window time.Duration) error {
	ctx := context.Background()
	req, err := m.backend.DeleteApprovalRequest(ctx, id)
	if err != nil {
		return fmt.Errorf("delete request: %w", err)
	}
	if req == nil {
		return fmt.Errorf("request %s not found", id)
	}

	m.mu.RLock()
	policy := m.policy
	m.mu.RUnlock()
	if window == 0 {
		window = policy.DefaultWindow
	}

	expiresAt := time.Now().Add(window)
	if err := m.backend.CreateApprovalWindow(ctx, req.User, req.Host, decidedBy, expiresAt); err != nil {
		return fmt.Errorf("create window: %w", err)
	}

	go m.sendWebhook("approved", req, decidedBy, policy.Notifications)
	log.Printf("approval: request %s approved by %s (window %s) for %s@%s",
		id, decidedBy, window, req.User, req.Host)
	return nil
}

// Deny removes the pending request and notifies the user.
func (m *ApprovalManager) Deny(id, decidedBy, reason string) error {
	ctx := context.Background()
	req, err := m.backend.DeleteApprovalRequest(ctx, id)
	if err != nil {
		return fmt.Errorf("delete request: %w", err)
	}
	if req == nil {
		return fmt.Errorf("request %s not found", id)
	}

	m.mu.RLock()
	notif := m.policy.Notifications
	m.mu.RUnlock()
	go m.sendWebhookDeny(req, decidedBy, reason, notif)
	log.Printf("approval: request %s denied by %s for %s@%s", id, decidedBy, req.User, req.Host)
	return nil
}

// ListPending returns all unexpired pending requests.
func (m *ApprovalManager) ListPending() []store.ApprovalRequest {
	reqs, err := m.backend.ListApprovalRequests(context.Background())
	if err != nil {
		log.Printf("approval: ListApprovalRequests: %v", err)
		return nil
	}
	return reqs
}

// ── Webhook ───────────────────────────────────────────────────────────────────

type slackPayload struct {
	Text        string            `json:"text"`
	Username    string            `json:"username"`
	IconEmoji   string            `json:"icon_emoji"`
	Attachments []slackAttachment `json:"attachments,omitempty"`
}

type slackAttachment struct {
	Color  string       `json:"color"`
	Fields []slackField `json:"fields"`
	Footer string       `json:"footer,omitempty"`
}

type slackField struct {
	Title string `json:"title"`
	Value string `json:"value"`
	Short bool   `json:"short"`
}

func (m *ApprovalManager) sendWebhook(event string, req *store.ApprovalRequest, decidedBy string, cfg approvalNotifyCfg) {
	if cfg.WebhookURL == "" {
		return
	}
	var color, header, footer string
	var fields []slackField
	switch event {
	case "requested":
		color = "#ff9900"
		header = ":lock: *Sudo approval request*"
		mention := req.User
		if cfg.MentionUser && req.NotifyVia != "" {
			mention = "@" + req.NotifyVia
		}
		fields = []slackField{
			{Title: "User", Value: mention, Short: true},
			{Title: "Host", Value: req.Host, Short: true},
			{Title: "Command", Value: "`" + req.Command + "`"},
			{Title: "Reason", Value: req.Justification},
			{Title: "Request ID", Value: req.ID, Short: true},
			{Title: "Expires", Value: req.ExpiresAt.Format(time.RFC3339), Short: true},
		}
		footer = "Approve or deny in sudo-logger UI"
	case "approved":
		color = "#36a64f"
		target := req.User
		if cfg.MentionUser && req.NotifyVia != "" {
			target = "@" + req.NotifyVia
		}
		header = fmt.Sprintf(":white_check_mark: %s — sudo approved on *%s*", target, req.Host)
		fields = []slackField{
			{Title: "Approved by", Value: decidedBy, Short: true},
			{Title: "Request ID", Value: req.ID, Short: true},
		}
	}
	m.postSlack(cfg, header, color, fields, footer)
}

func (m *ApprovalManager) sendWebhookDeny(req *store.ApprovalRequest, decidedBy, reason string, cfg approvalNotifyCfg) {
	if cfg.WebhookURL == "" {
		return
	}
	target := req.User
	if cfg.MentionUser && req.NotifyVia != "" {
		target = "@" + req.NotifyVia
	}
	header := fmt.Sprintf(":x: %s — sudo request denied on *%s*", target, req.Host)
	fields := []slackField{
		{Title: "Denied by", Value: decidedBy, Short: true},
		{Title: "Request ID", Value: req.ID, Short: true},
	}
	if reason != "" {
		fields = append(fields, slackField{Title: "Reason", Value: reason})
	}
	m.postSlack(cfg, header, "#cc0000", fields, "")
}

func (m *ApprovalManager) postSlack(cfg approvalNotifyCfg, text, color string, fields []slackField, footer string) {
	p := slackPayload{
		Text:      text,
		Username:  "sudo-logger",
		IconEmoji: ":lock:",
		Attachments: []slackAttachment{
			{Color: color, Fields: fields, Footer: footer},
		},
	}
	body, err := json.Marshal(p)
	if err != nil {
		log.Printf("approval: webhook marshal: %v", err)
		return
	}
	hreq, err := http.NewRequest(http.MethodPost, cfg.WebhookURL, bytes.NewReader(body))
	if err != nil {
		log.Printf("approval: webhook request: %v", err)
		return
	}
	hreq.Header.Set("Content-Type", "application/json")
	if cfg.WebhookSecret != "" {
		mac := hmac.New(sha256.New, []byte(cfg.WebhookSecret))
		mac.Write(body)
		hreq.Header.Set("X-Sudo-Logger-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(hreq)
	if err != nil {
		log.Printf("approval: webhook post: %v", err)
		return
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		log.Printf("approval: webhook returned %d", resp.StatusCode)
	}
}

// ── REST API ──────────────────────────────────────────────────────────────────

// RegisterApprovalAPI mounts the approval REST endpoints on mux.
// token is a shared secret (Authorization: Bearer). If empty, endpoints are not registered.
func (m *ApprovalManager) RegisterApprovalAPI(mux *http.ServeMux, token string) {
	if token == "" {
		log.Printf("approval: WARNING: -approval-token not set — approval REST API disabled. " +
			"Set -approval-token to enable the UI approval panel.")
		return
	}
	auth := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer "+token {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			next(w, r)
		}
	}
	mux.HandleFunc("/api/approvals", auth(m.handleList))
	mux.HandleFunc("/api/approvals/", auth(m.handleDecision))
}

func (m *ApprovalManager) handleList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	pending := m.ListPending()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(pending)
}

func (m *ApprovalManager) handleDecision(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) != 4 {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}
	id, action := parts[2], parts[3]
	// X-Sudo-Logger-Decided-By is set by the replay-server from its authenticated
	// session identity — never forwarded from the browser request.
	decidedBy := r.Header.Get("X-Sudo-Logger-Decided-By")
	if decidedBy == "" {
		decidedBy = "unknown"
	}

	switch action {
	case "approve":
		var window time.Duration
		if s := r.URL.Query().Get("window"); s != "" {
			var err error
			window, err = time.ParseDuration(s)
			if err != nil {
				http.Error(w, "invalid window duration", http.StatusBadRequest)
				return
			}
		}
		if err := m.Approve(id, decidedBy, window); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
	case "deny":
		var body struct {
			Reason string `json:"reason"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		if err := m.Deny(id, decidedBy, body.Reason); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
	default:
		http.Error(w, "unknown action", http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func newRequestID() string {
	b := make([]byte, 4)
	rand.Read(b)
	return strings.ToUpper(hex.EncodeToString(b))
}

func matchGlob(pattern, s string) bool {
	if pattern == "*" {
		return true
	}
	if !strings.Contains(pattern, "*") {
		return pattern == s
	}
	parts := strings.SplitN(pattern, "*", 2)
	return strings.HasPrefix(s, parts[0]) && strings.HasSuffix(s, parts[1])
}
