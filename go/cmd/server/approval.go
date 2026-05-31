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
//   GET  /api/approvals                       — list pending requests
//   POST /api/approvals/{id}/approve?window=  — grant a time window
//   POST /api/approvals/{id}/deny             — deny (optional reason in body)
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// ── Policy ────────────────────────────────────────────────────────────────────

type approvalPolicy struct {
	Enabled       bool              `yaml:"enabled"`
	DefaultWindow time.Duration     `yaml:"default_window"` // how long an approval lasts
	PendingTTL    time.Duration     `yaml:"pending_ttl"`    // how long a request waits before auto-deny
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

// ── In-memory state ───────────────────────────────────────────────────────────

// ApprovalRequest is a pending sudo approval waiting for an admin decision.
type ApprovalRequest struct {
	ID            string    `json:"id"             yaml:"id"`
	User          string    `json:"user"           yaml:"user"`
	Host          string    `json:"host"           yaml:"host"`
	Command       string    `json:"command"        yaml:"command"`
	Justification string    `json:"justification"  yaml:"justification"`
	NotifyVia     string    `json:"notify_via"     yaml:"notify_via"`
	SubmittedAt   time.Time `json:"submitted_at"   yaml:"submitted_at"`
	ExpiresAt     time.Time `json:"expires_at"     yaml:"expires_at"`
}

type approvalWindow struct {
	User      string    `yaml:"user"`
	Host      string    `yaml:"host"`
	GrantedBy string    `yaml:"granted_by"`
	ExpiresAt time.Time `yaml:"expires_at"`
}

type approvalStore struct {
	Pending []ApprovalRequest `yaml:"pending"`
	Windows []approvalWindow  `yaml:"windows"`
}

// ApprovalResult is returned by ApprovalManager.Check.
type ApprovalResult int

const (
	ApprovalResultAllow      ApprovalResult = iota // proceed normally
	ApprovalResultPending                          // request created; SESSION_DENIED with request ID
	ApprovalResultNeedReason                       // SESSION_DENIED asking for justification
)

// ── Manager ───────────────────────────────────────────────────────────────────

// ApprovalManager handles the full JIT approval lifecycle.
type ApprovalManager struct {
	policyPath string
	storePath  string

	mu      sync.RWMutex
	policy  approvalPolicy
	pending map[string]*ApprovalRequest // id → request
	windows []approvalWindow
}

func newApprovalManager(policyPath, storePath string) *ApprovalManager {
	m := &ApprovalManager{
		policyPath: policyPath,
		storePath:  storePath,
		pending:    make(map[string]*ApprovalRequest),
	}
	if err := m.loadPolicy(); err != nil {
		log.Printf("approval: policy initial load: %v", err)
	}
	if err := m.loadStore(); err != nil {
		log.Printf("approval: store initial load: %v", err)
	}
	go m.reloadLoop()
	go m.expireLoop()
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

func (m *ApprovalManager) expireLoop() {
	t := time.NewTicker(60 * time.Second)
	defer t.Stop()
	for range t.C {
		m.expireOld()
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

func (m *ApprovalManager) loadStore() error {
	data, err := os.ReadFile(m.storePath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var s approvalStore
	if err := yaml.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("parse approval store: %w", err)
	}
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range s.Pending {
		r := r
		if r.ExpiresAt.After(now) {
			m.pending[r.ID] = &r
		}
	}
	for _, w := range s.Windows {
		if w.ExpiresAt.After(now) {
			m.windows = append(m.windows, w)
		}
	}
	log.Printf("approval: loaded store from %s (%d pending, %d windows)",
		m.storePath, len(m.pending), len(m.windows))
	return nil
}

func (m *ApprovalManager) saveStore() {
	m.mu.RLock()
	s := approvalStore{}
	for _, r := range m.pending {
		s.Pending = append(s.Pending, *r)
	}
	s.Windows = append(s.Windows, m.windows...)
	m.mu.RUnlock()

	data, err := yaml.Marshal(s)
	if err != nil {
		log.Printf("approval: marshal store: %v", err)
		return
	}
	tmp := m.storePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		log.Printf("approval: write store: %v", err)
		return
	}
	if err := os.Rename(tmp, m.storePath); err != nil {
		log.Printf("approval: rename store: %v", err)
	}
}

func (m *ApprovalManager) expireOld() {
	now := time.Now()
	m.mu.Lock()
	changed := false
	for id, r := range m.pending {
		if !r.ExpiresAt.After(now) {
			log.Printf("approval: request %s for %s@%s expired", id, r.User, r.Host)
			delete(m.pending, id)
			changed = true
		}
	}
	newW := m.windows[:0]
	for _, w := range m.windows {
		if w.ExpiresAt.After(now) {
			newW = append(newW, w)
		} else {
			changed = true
		}
	}
	m.windows = newW
	m.mu.Unlock()
	if changed {
		m.saveStore()
	}
}

// ── Check ─────────────────────────────────────────────────────────────────────

// CheckResult carries the outcome of ApprovalManager.Check.
type CheckResult struct {
	Result    ApprovalResult
	RequestID string // set when Result == ApprovalResultPending
}

// Check evaluates whether the SESSION_START should be allowed, pending, or denied.
// user, host, command and justification come from the SESSION_START payload.
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
	if m.hasActiveWindow(user, host) {
		return CheckResult{Result: ApprovalResultAllow}
	}
	if strings.TrimSpace(justification) == "" {
		return CheckResult{Result: ApprovalResultNeedReason}
	}

	// Create pending request.
	id := newRequestID()
	now := time.Now()
	req := &ApprovalRequest{
		ID:            id,
		User:          user,
		Host:          host,
		Command:       command,
		Justification: justification,
		NotifyVia:     notifyVia,
		SubmittedAt:   now,
		ExpiresAt:     now.Add(policy.PendingTTL),
	}
	m.mu.Lock()
	m.pending[id] = req
	m.mu.Unlock()
	m.saveStore()

	go m.sendWebhook("requested", req, "", policy.Notifications)
	return CheckResult{Result: ApprovalResultPending, RequestID: id}
}

func (m *ApprovalManager) hasActiveWindow(user, host string) bool {
	now := time.Now()
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, w := range m.windows {
		if w.User == user && w.Host == host && w.ExpiresAt.After(now) {
			return true
		}
	}
	return false
}

// RetryMessage returns the SESSION_DENIED message shown when user retries sudo.
// It reflects the current state of any pending request for user@host.
func (m *ApprovalManager) RetryMessage(user, host string) string {
	if m == nil {
		return ""
	}
	now := time.Now()
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, r := range m.pending {
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
	m.mu.Lock()
	req, ok := m.pending[id]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("request %s not found", id)
	}
	if window == 0 {
		m.mu.RLock()
		window = m.policy.DefaultWindow
		m.mu.RUnlock()
	}
	w := approvalWindow{
		User:      req.User,
		Host:      req.Host,
		GrantedBy: decidedBy,
		ExpiresAt: time.Now().Add(window),
	}
	m.windows = append(m.windows, w)
	delete(m.pending, id)
	reqCopy := *req
	m.mu.Unlock()
	m.saveStore()

	m.mu.RLock()
	notif := m.policy.Notifications
	m.mu.RUnlock()
	go m.sendWebhook("approved", &reqCopy, decidedBy, notif)
	log.Printf("approval: request %s approved by %s (window %s) for %s@%s",
		id, decidedBy, window, reqCopy.User, reqCopy.Host)
	return nil
}

// Deny removes the pending request and notifies the user.
func (m *ApprovalManager) Deny(id, decidedBy, reason string) error {
	m.mu.Lock()
	req, ok := m.pending[id]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("request %s not found", id)
	}
	reqCopy := *req
	delete(m.pending, id)
	m.mu.Unlock()
	m.saveStore()

	m.mu.RLock()
	notif := m.policy.Notifications
	m.mu.RUnlock()
	go m.sendWebhookDeny(&reqCopy, decidedBy, reason, notif)
	log.Printf("approval: request %s denied by %s for %s@%s",
		id, decidedBy, reqCopy.User, reqCopy.Host)
	return nil
}

// ListPending returns a snapshot of all pending requests.
func (m *ApprovalManager) ListPending() []ApprovalRequest {
	now := time.Now()
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]ApprovalRequest, 0, len(m.pending))
	for _, r := range m.pending {
		if r.ExpiresAt.After(now) {
			out = append(out, *r)
		}
	}
	return out
}

// ── Webhook ───────────────────────────────────────────────────────────────────

type webhookPayload struct {
	Event         string `json:"event"`
	RequestID     string `json:"request_id"`
	User          string `json:"user"`
	Host          string `json:"host"`
	Command       string `json:"command,omitempty"`
	Justification string `json:"justification,omitempty"`
	NotifyVia     string `json:"notify_via,omitempty"`
	SubmittedAt   string `json:"submitted_at,omitempty"`
	ExpiresAt     string `json:"expires_at,omitempty"`
	DecidedBy     string `json:"decided_by,omitempty"`
	WindowExpires string `json:"window_expires,omitempty"`
	Reason        string `json:"reason,omitempty"`
}

// slackAttachment is the Slack/Mattermost incoming webhook format.
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

func (m *ApprovalManager) sendWebhook(event string, req *ApprovalRequest, decidedBy string, cfg approvalNotifyCfg) {
	if cfg.WebhookURL == "" {
		return
	}
	var (
		color  string
		header string
		fields []slackField
		footer string
	)
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

func (m *ApprovalManager) sendWebhookDeny(req *ApprovalRequest, decidedBy, reason string, cfg approvalNotifyCfg) {
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

	req, err := http.NewRequest(http.MethodPost, cfg.WebhookURL, bytes.NewReader(body))
	if err != nil {
		log.Printf("approval: webhook request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if cfg.WebhookSecret != "" {
		mac := hmac.New(sha256.New, []byte(cfg.WebhookSecret))
		mac.Write(body)
		req.Header.Set("X-Sudo-Logger-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
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
// token is a shared secret that callers must supply as "Authorization: Bearer <token>".
// If token is empty the endpoints are not registered and a warning is logged —
// the approval API must not be exposed unauthenticated.
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
	// Path: /api/approvals/{id}/approve or /api/approvals/{id}/deny
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) != 3 {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}
	id, action := parts[1], parts[2]
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

// matchGlob matches a simple glob pattern (only * wildcard) against s.
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

// defaultApprovalStorePath returns the path next to the policy file.
func defaultApprovalStorePath(policyPath string) string {
	dir := filepath.Dir(policyPath)
	return filepath.Join(dir, "approval-store.yaml")
}
