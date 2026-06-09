package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

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
func getOIDCConfig(ctx context.Context, reqHost string) (store.AuthConfig, *oidc.Provider, *oidc.IDTokenVerifier, *oauth2.Config, error) {
	cfg, err := sessionStore.GetAuthConfig(ctx)
	if err != nil {
		return cfg, nil, nil, nil, fmt.Errorf("failed to get auth config: %w", err)
	}

	if cfg.Source != "oidc" || cfg.OIDC.Issuer == "" || cfg.OIDC.ClientID == "" {
		return cfg, nil, nil, nil, fmt.Errorf("OIDC is not fully configured (missing issuer or client ID)")
	}

	redirectURL := "https://" + reqHost + "/api/oidc/callback"

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
	_, _, _, oauthConf, err := getOIDCConfig(r.Context(), r.Host)
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
	cfg, _, verifier, oauthConf, err := getOIDCConfig(r.Context(), r.Host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Verify state
	stateCookie, err := r.Cookie("oidc_state")
	if err != nil || r.URL.Query().Get("state") != stateCookie.Value {
		http.Error(w, "invalid or missing state", http.StatusBadRequest)
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

	// 1. Check if user is mapped to admin via groups
	role := RoleViewer
	for _, g := range claims.Groups {
		for _, adminGroup := range cfg.AdminGroups {
			if g == adminGroup {
				role = RoleAdmin
				break
			}
		}
		if role == RoleAdmin {
			break
		}
	}

	// 2. Set session cookie
	sessionData := fmt.Sprintf("%s:%s", username, role)
	encodedSession := base64.URLEncoding.EncodeToString([]byte(sessionData))

	http.SetCookie(w, &http.Cookie{
		Name:     "sudo_session",
		Value:    encodedSession,
		MaxAge:   3600 * 24, // 24 hours
		HttpOnly: true,
		Secure:   strings.HasPrefix(oauthConf.RedirectURL, "https://"),
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	})

	// Redirect back to main page
	http.Redirect(w, r, "/", http.StatusFound)
}
