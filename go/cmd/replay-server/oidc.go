package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"sudo-logger/internal/siem"
	"sudo-logger/internal/store"
)

var (
	oidcMu           sync.RWMutex
	cachedIssuer     string
	cachedProvider   *oidc.Provider
	cachedVerifier   *oidc.IDTokenVerifier
	cachedOAuth2Conf *oauth2.Config
)

// getOIDCConfig fetches the dynamic auth configuration and initializes the OIDC
// provider if it hasn't been initialized or if the issuer has changed.
func getOIDCConfig(ctx context.Context, r *http.Request) (store.AuthConfig, *oidc.Provider, *oidc.IDTokenVerifier, *oauth2.Config, error) {
	cfg, err := sessionStore.GetAuthConfig(ctx)
	if err != nil {
		return cfg, nil, nil, nil, fmt.Errorf("failed to get auth config: %w", err)
	}

	if cfg.Source != "oidc" || cfg.OIDC.Issuer == "" || cfg.OIDC.ClientID == "" {
		return cfg, nil, nil, nil, fmt.Errorf("OIDC is not fully configured (missing issuer or client ID)")
	}

	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	redirectURL := scheme + "://" + r.Host + "/api/oidc/callback"

	oidcMu.RLock()
	iss := cachedIssuer
	p := cachedProvider
	v := cachedVerifier
	o := cachedOAuth2Conf
	oidcMu.RUnlock()

	// If already initialized for this issuer, just return it.
	if iss == cfg.OIDC.Issuer && p != nil {
		// Update oauth2 config dynamically in case secrets/redirect changed
		newOAuth := *o
		newOAuth.ClientID = cfg.OIDC.ClientID
		newOAuth.ClientSecret = cfg.OIDC.ClientSecret // pragma: allowlist secret
		newOAuth.RedirectURL = redirectURL
		return cfg, p, v, &newOAuth, nil
	}

	// Needs initialization
	oidcMu.Lock()
	defer oidcMu.Unlock()

	// Double check
	if cachedIssuer == cfg.OIDC.Issuer && cachedProvider != nil {
		newOAuth := *cachedOAuth2Conf
		newOAuth.ClientID = cfg.OIDC.ClientID
		newOAuth.ClientSecret = cfg.OIDC.ClientSecret // pragma: allowlist secret
		newOAuth.RedirectURL = redirectURL
		return cfg, cachedProvider, cachedVerifier, &newOAuth, nil
	}

	provider, err := oidc.NewProvider(ctx, cfg.OIDC.Issuer)
	if err != nil {
		return cfg, nil, nil, nil, fmt.Errorf("failed to get provider: %w", err)
	}

	cachedProvider = provider
	cachedVerifier = provider.Verifier(&oidc.Config{ClientID: cfg.OIDC.ClientID})
	cachedIssuer = cfg.OIDC.Issuer
	cachedOAuth2Conf = &oauth2.Config{
		ClientID:     cfg.OIDC.ClientID,
		ClientSecret: cfg.OIDC.ClientSecret, // pragma: allowlist secret
		RedirectURL:  redirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email", "groups"},
	}

	return cfg, cachedProvider, cachedVerifier, cachedOAuth2Conf, nil
}

// generateState creates a random state parameter for CSRF protection.
func generateState() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// handleOIDCLogin redirects the user to the OIDC provider's login page.
func handleOIDCLogin(w http.ResponseWriter, r *http.Request) {
	_, _, _, oauthConf, err := getOIDCConfig(r.Context(), r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	state := generateState()
	// Store state with a short expiry in a cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "oidc_state",
		Value:    state,
		MaxAge:   300, // 5 minutes
		HttpOnly: true,
		Secure:   strings.HasPrefix(oauthConf.RedirectURL, "https://"),
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	})

	url := oauthConf.AuthCodeURL(state, oauth2.AccessTypeOnline)
	http.Redirect(w, r, url, http.StatusFound)
}

// handleOIDCCallback processes the response from the OIDC provider.
func handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	cfg, _, verifier, oauthConf, err := getOIDCConfig(r.Context(), r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Verify state
	stateCookie, err := r.Cookie("oidc_state")
	if err != nil {
		http.Error(w, "invalid or missing state (cookie not found)", http.StatusBadRequest)
		return
	}
	if r.URL.Query().Get("state") != stateCookie.Value {
		http.Error(w, fmt.Sprintf("invalid or missing state (mismatch: got %q, expected %q)", r.URL.Query().Get("state"), stateCookie.Value), http.StatusBadRequest)
		return
	}

	oauth2Token, err := oauthConf.Exchange(r.Context(), r.URL.Query().Get("code"))
	if err != nil {
		http.Error(w, "failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "no id_token field in oauth2 token", http.StatusInternalServerError)
		return
	}

	idToken, err := verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		http.Error(w, "failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Extract claims
	var claims struct {
		Email             string   `json:"email"`
		PreferredUsername string   `json:"preferred_username"`
		Name              string   `json:"name"`
		Groups            []string `json:"groups"` // Assuming 'groups' claim is available
	}
	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, "failed to parse claims", http.StatusInternalServerError)
		return
	}

	username := claims.PreferredUsername
	if username == "" {
		username = claims.Email
	}

	// 1. Resolve role from group claims using GroupMappings then AdminGroups fallback.
	role := resolveRoleFromGroups(claims.Groups, cfg)

	// 2. Create a server-side session; store only the opaque session ID in the cookie.
	// The id_token is kept server-side for RP-Initiated Logout and never sent to the client.
	sid := loginSessions.create(username, role, rawIDToken)

	go siem.SendAudit("user_login", map[string]any{
		"user":   username,
		"role":   role,
		"source": "oidc",
		"addr":   r.RemoteAddr,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "sudo_session",
		Value:    sid,
		MaxAge:   3600 * 24, // 24 hours
		HttpOnly: true,
		Secure:   strings.HasPrefix(oauthConf.RedirectURL, "https://"),
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	})

	// Redirect back to main page
	http.Redirect(w, r, "/", http.StatusFound)
}

// handleOIDCLogout clears the local session and redirects to the OIDC end_session_endpoint
func handleOIDCLogout(w http.ResponseWriter, r *http.Request) {
	_, provider, _, oauthConf, err := getOIDCConfig(r.Context(), r)
	if err != nil {
		// Just clear cookie and go home if provider is gone
		http.SetCookie(w, &http.Cookie{Name: "sudo_session", Value: "", MaxAge: -1, Path: "/"})
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	// Retrieve id_token from the server-side session, then invalidate it.
	var idToken string
	user := "-"
	if c, err := r.Cookie("sudo_session"); err == nil {
		if sess := loginSessions.lookup(c.Value); sess != nil {
			idToken = sess.idToken
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

	// Clear local session cookie
	http.SetCookie(w, &http.Cookie{Name: "sudo_session", Value: "", MaxAge: -1, Path: "/"})

	// Try to get end_session_endpoint from provider discovery claims
	var claims struct {
		EndSessionEndpoint string `json:"end_session_endpoint"`
	}
	if err := provider.Claims(&claims); err != nil || claims.EndSessionEndpoint == "" {
		// Fallback to local redirect if provider doesn't support RP-Initiated Logout
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	// Construct logout URL
	logoutURL := claims.EndSessionEndpoint
	// Use the pre-configured RedirectURL to derive the base URL for the redirect
	// instead of trusting the Host header.
	redirectURI := "/"
	if u, err := url.Parse(oauthConf.RedirectURL); err == nil {
		redirectURI = u.Scheme + "://" + u.Host + "/"
	}

	if idToken != "" {
		logoutURL += "?id_token_hint=" + idToken + "&post_logout_redirect_uri=" + redirectURI
	}

	http.Redirect(w, r, logoutURL, http.StatusFound)
}
