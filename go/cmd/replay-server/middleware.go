package main

import (
	"context"
	"log"
	"net/http"
	"strings"

	"sudo-logger/internal/store"
	"sudo-logger/internal/util"
)

// ctxKey is the unexported type for context keys in this package.
type ctxKey int

const ctxViewer ctxKey = 0

// viewerFromContext returns the authenticated username stored in ctx,
// or "-" if none was set.
func viewerFromContext(r *http.Request) string {
	if v, ok := r.Context().Value(ctxViewer).(string); ok && v != "" {
		return v
	}
	return "-"
}

// loggingResponseWriter captures the HTTP status code for access logging.
type loggingResponseWriter struct {
	http.ResponseWriter
	status int
}

func (lrw *loggingResponseWriter) WriteHeader(code int) {
	lrw.status = code
	lrw.ResponseWriter.WriteHeader(code)
}

// securityHeadersMiddleware adds standard security headers to all responses.
func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		// CSP: local scripts only (the built UI has no inline <script> or
		// dangerouslySetInnerHTML-injected script, and index.html is served
		// statically with no server-side templating, so 'unsafe-inline' is
		// not needed for script-src); inline styles, data images, and WASM
		// for the terminal player remain allowed.
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self';")

		// Add HSTS if TLS is enabled or we are behind a proxy that terminated TLS
		if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}

		next.ServeHTTP(w, r)
	})
}

// accessLogMiddleware logs every request with the authenticated username,
// resolved from the dynamic AuthConfig (proxy mode, OIDC, or Basic Auth).
func accessLogMiddleware(next http.Handler, trustedHeader string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := "-"
		role := RoleViewer

		cfg, err := sessionStore.GetAuthConfig(r.Context())
		if err != nil {
			// Logging-only path (not an auth gate) — proceed with the
			// zero-value config, but note the failure so it isn't silent.
			log.Printf("accessLogMiddleware: GetAuthConfig: %v", err)
		}

		if cfg.Source == "proxy" {
			header := cfg.Proxy.UserHeader
			if header == "" {
				header = trustedHeader
			}
			if header != "" && r.Header.Get(header) != "" {
				user = r.Header.Get(header)

				// Map groups to roles: explicit GroupMappings take priority, then AdminGroups fallback.
				if cfg.Proxy.GroupsHeader != "" {
					groupsRaw := r.Header.Get(cfg.Proxy.GroupsHeader)
					var groups []string
					for _, g := range strings.Split(groupsRaw, ",") {
						if g = strings.TrimSpace(g); g != "" {
							groups = append(groups, g)
						}
					}
					role = resolveRoleFromGroups(groups, cfg)
				}
			}
		}

		if user == "-" && (cfg.Source == "oidc" || cfg.Source == "local" || cfg.Source == "") {
			if c, err := r.Cookie("sudo_session"); err == nil {
				if sess := loginSessions.lookup(c.Value); sess != nil {
					user = sess.username
					role = sess.role
				}
			}
		}

		if user == "-" && (cfg.Source == "local" || cfg.Source == "") {
			if u, _, ok := r.BasicAuth(); ok {
				user = u
			}
		}

		// Fallback for legacy trusted header if source is explicitly set to proxy
		if user == "-" && cfg.Source == "proxy" && trustedHeader != "" {
			if v := r.Header.Get(trustedHeader); v != "" {
				user = v
			}
		}

		if user != "-" && role == RoleViewer {
			if u, err := sessionStore.GetUser(r.Context(), user); err == nil && u != nil {
				role = u.Role
			} else if *flagHTPasswd != "" && isHTPasswdUser(user) { // pragma: allowlist secret
				// The legacy -htpasswd file predates per-user roles and has
				// always been a single flat auth tier — anyone in it gets
				// full access, matching that mode's historical behavior.
				role = RoleAdmin
			}
		}

		if isBootstrapMode(r) {
			role = RoleAdmin
		}

		// Build a temporary request with viewer/role already in context so that
		// resolveRolePerms (which calls sessionStore.GetRole) can use r.Context().
		tmpCtx := context.WithValue(r.Context(), ctxViewer, user)
		tmpCtx = context.WithValue(tmpCtx, ctxRole, role)
		tmpR := r.WithContext(tmpCtx)
		perms := resolveRolePerms(tmpR, role)

		lrw := &loggingResponseWriter{ResponseWriter: w, status: http.StatusOK}
		ctx := context.WithValue(r.Context(), ctxViewer, user)
		ctx = context.WithValue(ctx, ctxRole, role)
		ctx = context.WithValue(ctx, ctxPermissions, perms)
		next.ServeHTTP(lrw, r.WithContext(ctx))
		log.Printf("access identity=%s role=%s addr=%s method=%s path=%s status=%d",
			"***", role, r.RemoteAddr, r.Method, util.SanitizeForLog(r.URL.Path), lrw.status)
	})
}

// resolveRoleFromGroups maps a set of group names to a role using GroupMappings
// (first match wins) with AdminGroups as a fallback (maps to "admin").
// Returns RoleViewer if no group matches.
func resolveRoleFromGroups(groups []string, cfg store.AuthConfig) Role {
	for _, g := range groups {
		for _, m := range cfg.GroupMappings {
			if g == m.Group {
				return m.Role
			}
		}
	}
	for _, g := range groups {
		for _, adminGroup := range cfg.AdminGroups {
			if g == adminGroup {
				return RoleAdmin
			}
		}
	}
	return RoleViewer
}

// basicAuthMiddleware enforces HTTP Basic Auth using the SessionStore.
// In bootstrap mode (no users exist), it allows all requests to pass through
// so that the first admin can be created.
func basicAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isBootstrapMode(r) {
			next.ServeHTTP(w, r)
			return
		}

		// In OIDC mode, a (re)load of the local login page should go straight to the
		// identity provider instead of showing the unusable local username/password form.
		if r.URL.Path == "/login" {
			cfg, _ := sessionStore.GetAuthConfig(r.Context())
			if cfg.Source == "oidc" {
				if c, err := r.Cookie("sudo_session"); err != nil || loginSessions.lookup(c.Value) == nil {
					http.Redirect(w, r, "/api/oidc/login", http.StatusFound)
					return
				}
			}
			next.ServeHTTP(w, r)
			return
		}

		// Allow OIDC endpoints, health checks, and static assets to bypass auth.
		// Use anchored prefix/exact checks only — never suffix checks, which can be smuggled
		// past API routes (e.g. /api/admin/export.js would bypass auth with a suffix allowlist).
		// JS/CSS are all under /assets/; root-level SVGs are listed explicitly.
		if strings.HasPrefix(r.URL.Path, "/api/oidc/") || r.URL.Path == "/api/login" ||
			r.URL.Path == "/healthz" || r.URL.Path == "/metrics" ||
			strings.HasPrefix(r.URL.Path, "/assets/") ||
			strings.HasPrefix(r.URL.Path, "/docs/") ||
			r.URL.Path == "/favicon.svg" || r.URL.Path == "/icons.svg" ||
			r.URL.Path == "/logo.svg" || r.URL.Path == "/logo-icon-72.svg" {
			next.ServeHTTP(w, r)
			return
		}

		cfg, err := sessionStore.GetAuthConfig(r.Context())
		if err != nil {
			// Fail closed: a store error must never be interpreted as "no
			// auth config" (Source == ""), which the local-mode branch below
			// would otherwise treat as an open deployment.
			log.Printf("SECURITY: GetAuthConfig failed, denying request: %v", err)
			http.Error(w, "service unavailable", http.StatusServiceUnavailable)
			return
		}

		// Auto-detect legacy proxy config if source is not yet saved
		if cfg.Source == "" || cfg.Source == "local" {
			if *flagTrustedUserHeader != "" {
				cfg.Source = "proxy"
			}
		}

		if cfg.Source == "oidc" {
			if c, err := r.Cookie("sudo_session"); err == nil && loginSessions.lookup(c.Value) != nil {
				next.ServeHTTP(w, r)
				return
			}
			// For API requests, return 401 instead of redirecting to login page
			if strings.HasPrefix(r.URL.Path, "/api/") {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			// Redirect unauthenticated OIDC users to login instead of showing Basic Auth prompt
			http.Redirect(w, r, "/api/oidc/login", http.StatusFound)
			return
		}

		if cfg.Source == "proxy" {
			header := cfg.Proxy.UserHeader
			if header == "" {
				header = *flagTrustedUserHeader
			}
			if header != "" && r.Header.Get(header) != "" {
				next.ServeHTTP(w, r)
				return
			}
			// Fail closed: proxy mode is configured but this request carries
			// no trusted-header credential (misconfigured/bypassed reverse
			// proxy). Do NOT fall through — accessLogMiddleware would treat
			// the resulting viewer=="-" the same as a genuinely open,
			// unauthenticated deployment and serve every user's sessions to
			// an anonymous caller. Same fail-closed principle already
			// applied to the GetAuthConfig/ListUsers error paths above.
			if strings.HasPrefix(r.URL.Path, "/api/") {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			http.Error(w, "unauthorized: reverse proxy did not set the trusted user header", http.StatusUnauthorized)
			return
		}

		// Local mode: only enforce Auth if there is actually a user with a password,
		// OR if the legacy htpasswd flag was provided.
		// If no one has a password, we treat it as an open deployment.
		hasLocalPasswords := *flagHTPasswd != "" // pragma: allowlist secret
		if !hasLocalPasswords {
			users, err := sessionStore.ListUsers(r.Context())
			if err != nil {
				// Fail closed: a store error must not be interpreted as
				// "no local users have passwords" (open deployment).
				log.Printf("SECURITY: ListUsers failed, denying request: %v", err)
				http.Error(w, "service unavailable", http.StatusServiceUnavailable)
				return
			}
			for _, u := range users {
				if u.PasswordHash != "" { // pragma: allowlist secret
					hasLocalPasswords = true // pragma: allowlist secret
					break
				}
			}
		}

		if !hasLocalPasswords {
			next.ServeHTTP(w, r)
			return
		}

		// Check for a valid server-side session cookie (set by /api/login).
		if c, err := r.Cookie("sudo_session"); err == nil && loginSessions.lookup(c.Value) != nil {
			next.ServeHTTP(w, r)
			return
		}

		// Fallback to Basic Auth (for API clients/legacy)
		u, p, ok := r.BasicAuth()
		if ok && authenticate(r.Context(), u, p) {
			next.ServeHTTP(w, r)
			return
		}

		// If we reach here, the user is unauthenticated.
		// For API requests, return 401.
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("WWW-Authenticate", `Basic realm="sudo-replay"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// For UI requests, redirect to the new custom login page
		http.Redirect(w, r, "/login", http.StatusFound)
	})
}
