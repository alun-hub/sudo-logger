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
	Enabled            bool              `yaml:"enabled" json:"enabled"`
	DefaultWindow      time.Duration     `yaml:"default_window" json:"default_window"`
	PendingTTL         time.Duration     `yaml:"pending_ttl" json:"pending_ttl"`
	MaxSessionDuration time.Duration     `yaml:"max_session_duration" json:"max_session_duration"`
	Exempt             []exemptRule      `yaml:"exempt" json:"exempt"`
	Notifications      approvalNotifyCfg `yaml:"notifications" json:"notifications"`
}

type exemptRule struct {
	User  string   `yaml:"user" json:"user"`
	Hosts []string `yaml:"hosts" json:"hosts"` // empty = all hosts
}

type approvalNotifyCfg struct {
	WebhookURL      string `yaml:"webhook_url" json:"webhook_url"`
	WebhookSecret   string `yaml:"webhook_secret" json:"webhook_secret"`
	MentionUser     bool   `yaml:"mention_user" json:"mention_user"`
	RequestChannel  string `yaml:"request_channel" json:"request_channel"`
	ReplayWebAppURL string `yaml:"replay_web_app_url" json:"replay_web_app_url"`
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
	ApprovalResultChallenge                        // MSG_SESSION_CHALLENGE asking for justification
)

// CheckResult carries the outcome of ApprovalManager.Check.
type CheckResult struct {
	Result     ApprovalResult
	RequestID  string // set when Result == ApprovalResultPending
	HasWebhook bool   // set when Result == ApprovalResultChallenge or ApprovalResultNeedReason
	SessionTTL int64  // seconds the session may live; 0 = unlimited
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
	ctx := context.Background()
	var data []byte
	var source string

	// Prefer store-backed config (DB in distributed mode).
	cfgStr, err := m.backend.GetConfig(ctx, "approval-policy.yaml")
	if err == nil && cfgStr != "" {
		data = []byte(cfgStr)
		source = "store"
	} else {
		// Fallback to local file.
		data, err = os.ReadFile(m.policyPath)
		if os.IsNotExist(err) {
			m.mu.Lock()
			m.policy = approvalPolicy{}
			m.mu.Unlock()
			return nil
		}
		if err != nil {
			return err
		}
		source = m.policyPath
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
		source, p.Enabled, len(p.Exempt))
	return nil
}

// HasWebhook reports whether the policy has a webhook configured.
func (m *ApprovalManager) HasWebhook() bool {
	if m == nil {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.policy.Notifications.WebhookURL != ""
}

// ── Check ─────────────────────────────────────────────────────────────────────

// Check evaluates whether the SESSION_START should be allowed, pending, or denied.
// Returns ApprovalResultAllow immediately if the manager is nil (feature not configured).
func (m *ApprovalManager) Check(user, host, command, justification string) CheckResult {
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
		ttl := sessionTTL(time.Time{}, policy.MaxSessionDuration)
		return CheckResult{Result: ApprovalResultAllow, SessionTTL: ttl}
	}

	ctx := context.Background()
	windowExp, hasWindow, err := m.backend.HasApprovalWindow(ctx, user, host)
	if err != nil {
		log.Printf("approval: HasApprovalWindow: %v", err)
	}
	if hasWindow {
		ttl := sessionTTL(windowExp, policy.MaxSessionDuration)
		return CheckResult{Result: ApprovalResultAllow, SessionTTL: ttl}
	}

	if strings.TrimSpace(justification) == "" {
		if m.RetryMessage(user, host) != "" {
			return CheckResult{Result: ApprovalResultNeedReason, HasWebhook: policy.Notifications.WebhookURL != ""}
		}
		return CheckResult{Result: ApprovalResultChallenge, HasWebhook: policy.Notifications.WebhookURL != ""}
	}

	id := newRequestID()
	now := time.Now()
	req := store.ApprovalRequest{
		ID:            id,
		User:          user,
		Host:          host,
		Command:       command,
		Justification: justification,
		SubmittedAt:   now,
		ExpiresAt:     now.Add(policy.PendingTTL),
	}
	if err := m.backend.CreateApprovalRequest(ctx, req); err != nil {
		log.Printf("approval: CreateApprovalRequest: %v", err)
	}

	go m.sendWebhook("requested", &req, "", policy.Notifications)
	return CheckResult{Result: ApprovalResultPending, RequestID: id, HasWebhook: policy.Notifications.WebhookURL != ""}
}

// sessionTTL returns the session lifetime in seconds given the window expiry and
// an optional max-session cap. Zero means unlimited.
func sessionTTL(windowExp time.Time, maxDur time.Duration) int64 {
	var ttl int64
	if !windowExp.IsZero() {
		remaining := time.Until(windowExp)
		if remaining > 0 {
			ttl = int64(remaining.Seconds())
		} else {
			ttl = 1
		}
	}
	if maxDur > 0 {
		cap := int64(maxDur.Seconds())
		if ttl == 0 || cap < ttl {
			ttl = cap
		}
	}
	return ttl
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

	go m.sendWebhookApproved(req, decidedBy, window, expiresAt, policy.Notifications)
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
	Channel     string            `json:"channel,omitempty"`
	Text        string            `json:"text"`
	Username    string            `json:"username"`
	IconEmoji   string            `json:"icon_emoji"`
	Attachments []slackAttachment `json:"attachments,omitempty"`
}

type slackIntegration struct {
	URL     string            `json:"url"`
	Context map[string]string `json:"context"`
}

type slackAction struct {
	ID          string           `json:"id"`
	Name        string           `json:"name"`
	Integration slackIntegration `json:"integration"`
}

type slackAttachment struct {
	Color   string        `json:"color"`
	Fields  []slackField  `json:"fields"`
	Footer  string        `json:"footer,omitempty"`
	Actions []slackAction `json:"actions,omitempty"`
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
	var color, header, footer, channel string
	var fields []slackField
	var actions []slackAction

	switch event {
	case "requested":
		color = "#ff9900"
		header = ":lock: *Sudo approval request*"
		mention := req.User
		if cfg.MentionUser {
			mention = "@" + req.User
		}
		fields = []slackField{
			{Title: "User", Value: mention, Short: true},
			{Title: "Host", Value: req.Host, Short: true},
			{Title: "Command", Value: "`" + req.Command + "`"},
			{Title: "Reason", Value: req.Justification},
			{Title: "Request ID", Value: req.ID, Short: true},
			{Title: "Expires", Value: req.ExpiresAt.Format("2006-01-02 15:04:05"), Short: true},
		}
		footer = "Approve or deny in sudo-logger UI"
		if cfg.ReplayWebAppURL != "" {
			footer = fmt.Sprintf("[Approve or deny in sudo-logger UI](%s/approvals)", strings.TrimSuffix(cfg.ReplayWebAppURL, "/"))
		}
		channel = cfg.RequestChannel

		if cfg.WebhookURL != "" && cfg.ReplayWebAppURL != "" {
			callbackURL := strings.TrimSuffix(cfg.ReplayWebAppURL, "/") + "/api/approvals/callback"
			actions = []slackAction{
				{
					ID:   "approve",
					Name: "Approve",
					Integration: slackIntegration{
						URL: callbackURL,
						Context: map[string]string{
							"action":     "approve",
							"request_id": req.ID,
							"token":      m.generateActionToken(req.ID, "approve", cfg.WebhookSecret),
						},
					},
				},
				{
					ID:   "deny",
					Name: "Deny",
					Integration: slackIntegration{
						URL: callbackURL,
						Context: map[string]string{
							"action":     "deny",
							"request_id": req.ID,
							"token":      m.generateActionToken(req.ID, "deny", cfg.WebhookSecret),
						},
					},
				},
			}
		}
	}
	m.postSlack(cfg, channel, header, color, fields, footer, actions)
}

func (m *ApprovalManager) sendWebhookApproved(req *store.ApprovalRequest, decidedBy string, window time.Duration, expiresAt time.Time, cfg approvalNotifyCfg) {
	if cfg.WebhookURL == "" {
		return
	}
	var channel string
	target := req.User
	if cfg.MentionUser {
		channel = "@" + req.User
		target = "@" + req.User
	}
	header := fmt.Sprintf(":white_check_mark: %s — sudo approved on *%s*", target, req.Host)
	fields := []slackField{
		{Title: "Approved by", Value: decidedBy, Short: true},
		{Title: "Window", Value: window.String(), Short: true},
		{Title: "Session expires", Value: expiresAt.Format("2006-01-02 15:04:05"), Short: true},
		{Title: "Notification", Value: "Mattermost webhook", Short: true},
	}
	m.postSlack(cfg, channel, header, "#36a64f", fields, "", nil)
}

func (m *ApprovalManager) sendWebhookDeny(req *store.ApprovalRequest, decidedBy, reason string, cfg approvalNotifyCfg) {
	if cfg.WebhookURL == "" {
		return
	}
	var channel string
	target := req.User
	if cfg.MentionUser {
		channel = "@" + req.User
		target = "@" + req.User
	}
	header := fmt.Sprintf(":x: %s — sudo request denied on *%s*", target, req.Host)
	fields := []slackField{
		{Title: "Denied by", Value: decidedBy, Short: true},
		{Title: "Request ID", Value: req.ID, Short: true},
	}
	if reason != "" {
		fields = append(fields, slackField{Title: "Reason", Value: reason})
	}
	m.postSlack(cfg, channel, header, "#cc0000", fields, "", nil)
}
func (m *ApprovalManager) postSlack(cfg approvalNotifyCfg, channel, text, color string, fields []slackField, footer string, actions []slackAction) {
	url := strings.TrimSpace(cfg.WebhookURL)
	if url == "" {
		return
	}
	if channel != "" {
		log.Printf("approval: posting webhook to channel %q", channel)
	}
	p := slackPayload{
		Channel:   channel,
		Text:      text,
		Username:  "sudo-logger",
		IconEmoji: ":lock:",
		Attachments: []slackAttachment{
			{Color: color, Fields: fields, Footer: footer, Actions: actions},
		},
	}
	body, err := json.Marshal(p)
	if err != nil {
		log.Printf("approval: webhook marshal: %v", err)
		return
	}

	hreq, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
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
	mux.HandleFunc("/api/approvals/callback", m.handleCallback)
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
	mux.HandleFunc("/api/approval-config", auth(m.handleConfig))
}

func (m *ApprovalManager) handleConfig(w http.ResponseWriter, r *http.Request) {
	// Internal struct for JSON roundtrip because time.Duration in JSON is nanoseconds (int64)
	// whereas UI and YAML want strings like "30m".
	type policyJSON struct {
		Enabled       bool   `json:"enabled"`
		DefaultWindow string `json:"default_window"`
		PendingTTL    string `json:"pending_ttl"`
		Exempt        []exemptRule      `json:"exempt"`
		Notifications approvalNotifyCfg `json:"notifications"`
	}

	switch r.Method {
	case http.MethodGet:
		m.mu.RLock()
		p := m.policy
		m.mu.RUnlock()

		pj := policyJSON{
			Enabled:       p.Enabled,
			DefaultWindow: p.DefaultWindow.String(),
			PendingTTL:    p.PendingTTL.String(),
			Exempt:        p.Exempt,
			Notifications: p.Notifications,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"config": pj,
			"path":   m.policyPath,
		})
	case http.MethodPut:
		var req struct {
			Config policyJSON `json:"config"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Map back to real policy to validate durations
		p := approvalPolicy{
			Enabled:       req.Config.Enabled,
			Exempt:        req.Config.Exempt,
			Notifications: req.Config.Notifications,
		}
		var err error
		if req.Config.DefaultWindow != "" {
			p.DefaultWindow, err = time.ParseDuration(req.Config.DefaultWindow)
			if err != nil {
				http.Error(w, "invalid default_window: "+err.Error(), http.StatusBadRequest)
				return
			}
		}
		if req.Config.PendingTTL != "" {
			p.PendingTTL, err = time.ParseDuration(req.Config.PendingTTL)
			if err != nil {
				http.Error(w, "invalid pending_ttl: "+err.Error(), http.StatusBadRequest)
				return
			}
		}

		data, err := yaml.Marshal(p)
		if err != nil {
			http.Error(w, "yaml marshal: "+err.Error(), http.StatusInternalServerError)
			return
		}
		// Save to store (DB if distributed, file if local)
		if err := m.backend.SetConfig(r.Context(), "approval-policy.yaml", string(data)); err != nil {
			log.Printf("approval: set config: %v", err)
			http.Error(w, "write failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		// Success — the reloadLoop will pick it up, or we can force it now:
		if err := m.loadPolicy(); err != nil {
			log.Printf("approval: reload after API update: %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
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

func (m *ApprovalManager) handleCallback(w http.ResponseWriter, r *http.Request) {
	log.Printf("approval: callback: method=%s, content-type=%s", r.Method, r.Header.Get("Content-Type"))
	var payload struct {
		UserName string            `json:"user_name"`
		Context  map[string]string `json:"context"`
	}

	contentType := r.Header.Get("Content-Type")
	if strings.HasPrefix(contentType, "application/x-www-form-urlencoded") {
		if err := r.ParseForm(); err != nil {
			log.Printf("approval: callback: parse form error: %v", err)
			http.Error(w, "invalid form data", http.StatusBadRequest)
			return
		}
		payload.UserName = r.FormValue("user_name")
		ctxJSON := r.FormValue("context")
		if ctxJSON != "" {
			if err := json.Unmarshal([]byte(ctxJSON), &payload.Context); err != nil {
				log.Printf("approval: callback: unmarshal context from form error: %v", err)
			}
		}
	} else {
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			log.Printf("approval: callback: decode json error: %v", err)
			http.Error(w, "invalid payload", http.StatusBadRequest)
			return
		}
	}

	reqID := payload.Context["request_id"]
	action := payload.Context["action"]
	token := payload.Context["token"]

	decidedBy := "@" + payload.UserName + " (via Mattermost)"
	log.Printf("approval: callback received: user=%s, request=%s, action=%s, decidedBy=%s", payload.UserName, reqID, action, decidedBy)

	m.mu.RLock()
	secret := m.policy.Notifications.WebhookSecret // pragma: allowlist secret
	m.mu.RUnlock()

	// Verify HMAC
	expected := m.generateActionToken(reqID, action, secret)
	if secret == "" || token == "" || !hmac.Equal([]byte(token), []byte(expected)) {
		log.Printf("approval: callback unauthorized: token mismatch for request %s. expected=%s, got=%s", reqID, expected, token)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var err error
	verb := "denied"
	if action == "approve" {
		verb = "approved"
		err = m.Approve(reqID, decidedBy, 0)
	} else {
		err = m.Deny(reqID, decidedBy, "Denied via Mattermost")
	}

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Response to Mattermost to update the message
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"update": map[string]interface{}{
			"message": fmt.Sprintf("Request %s %s by @%s.", reqID, verb, payload.UserName),
		},
	})
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func newRequestID() string {
	b := make([]byte, 4)
	rand.Read(b)
	return strings.ToUpper(hex.EncodeToString(b))
}

func (m *ApprovalManager) generateActionToken(requestID, action, secret string) string {
	if secret == "" {
		return ""
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(requestID + ":" + action))
	return hex.EncodeToString(mac.Sum(nil))
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
