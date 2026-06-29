package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
	"unicode"

	"golang.org/x/crypto/bcrypt"

	"sudo-logger/internal/siem"
)

// loginSession holds server-side state for one authenticated browser session.
// The session ID (a random 32-byte token) is the only thing stored in the cookie;
// username and role are never trusted from the client.
type loginSession struct {
	username  string
	role      Role
	idToken   string // OIDC id_token kept for RP-Initiated Logout; empty for local auth
	expiresAt time.Time
}

type loginSessionStore struct {
	mu   sync.Mutex
	data map[string]*loginSession
}

func newLoginSessionStore() *loginSessionStore {
	return &loginSessionStore{data: make(map[string]*loginSession)}
}

func (s *loginSessionStore) create(username string, role Role, idToken string) string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	sid := base64.RawURLEncoding.EncodeToString(b)
	s.mu.Lock()
	s.data[sid] = &loginSession{
		username:  username,
		role:      role,
		idToken:   idToken,
		expiresAt: time.Now().Add(24 * time.Hour),
	}
	s.mu.Unlock()
	return sid
}

func (s *loginSessionStore) lookup(sid string) *loginSession {
	if sid == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.data[sid]
	if !ok || time.Now().After(sess.expiresAt) {
		delete(s.data, sid)
		return nil
	}
	return sess
}

func (s *loginSessionStore) delete(sid string) {
	s.mu.Lock()
	delete(s.data, sid)
	s.mu.Unlock()
}

func (s *loginSessionStore) purgeExpired() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for sid, sess := range s.data {
		if now.After(sess.expiresAt) {
			delete(s.data, sid)
		}
	}
}

var loginSessions = newLoginSessionStore()

var dummyHash = func() []byte {
	h, _ := bcrypt.GenerateFromPassword([]byte("dummy"), bcrypt.MinCost)
	return h
}()

// authenticate returns true if username and password match a stored entry.
// Always runs bcrypt even for unknown users to prevent timing-based
// username enumeration.
func authenticate(ctx context.Context, username, password string) bool {
	u, err := sessionStore.GetUser(ctx, username)
	if err != nil || u == nil || u.Source != "local" || u.PasswordHash == "" {
		bcrypt.CompareHashAndPassword(dummyHash, []byte(password)) //nolint:errcheck
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)) == nil
}

func validatePassword(password string) error {
	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters long")
	}
	var (
		hasUpper   = false
		hasLower   = false
		hasNumber  = false
		hasSpecial = false
	)
	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsDigit(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}
	if !hasUpper {
		return fmt.Errorf("password must contain at least one uppercase letter")
	}
	if !hasLower {
		return fmt.Errorf("password must contain at least one lowercase letter")
	}
	if !hasNumber {
		return fmt.Errorf("password must contain at least one number")
	}
	if !hasSpecial {
		return fmt.Errorf("password must contain at least one special character")
	}
	return nil
}

func handleLocalLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	if !authenticate(r.Context(), req.Username, req.Password) {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	u, _ := sessionStore.GetUser(r.Context(), req.Username)
	if u == nil {
		http.Error(w, "user not found in store", http.StatusInternalServerError)
		return
	}

	sid := loginSessions.create(u.Username, u.Role, "")
	go siem.SendAudit("user_login", map[string]any{
		"user":   u.Username,
		"role":   u.Role,
		"source": "local",
		"addr":   r.RemoteAddr,
	})
	secure := r.Header.Get("X-Forwarded-Proto") == "https" || r.TLS != nil

	http.SetCookie(w, &http.Cookie{
		Name:     "sudo_session",
		Value:    sid,
		MaxAge:   3600 * 24, // 24 hours
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	})

	w.WriteHeader(http.StatusNoContent)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	cfg, _ := sessionStore.GetAuthConfig(r.Context())

	// If OIDC, use the specific OIDC logout handler
	if cfg.Source == "oidc" {
		handleOIDCLogout(w, r)
		return
	}

	// Local/Proxy logout: invalidate server-side session and clear cookie.
	user := "-"
	if c, err := r.Cookie("sudo_session"); err == nil {
		if sess := loginSessions.lookup(c.Value); sess != nil {
			user = sess.username
		}
		loginSessions.delete(c.Value)
	}
	if user != "-" {
		go siem.SendAudit("user_logout", map[string]any{
			"user": user,
			"addr": r.RemoteAddr,
		})
	}
	secure := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
	http.SetCookie(w, &http.Cookie{
		Name:     "sudo_session",
		Value:    "",
		MaxAge:   -1,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/login", http.StatusFound)
}
