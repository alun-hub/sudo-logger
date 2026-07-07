package main

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"

	"sudo-logger/internal/config"
	"sudo-logger/internal/siem"
	"sudo-logger/internal/store"
)

// registerRoutes sets up all the HTTP routes on the given mux.
func registerRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, "ok")
	})
	mux.HandleFunc("/api/sessions", handleListSessions)
	mux.HandleFunc("/api/session/events", handleSessionEvents)
	mux.HandleFunc("/api/session/cast", handleSessionCast)
	mux.HandleFunc("/api/access-log", handleAccessLog)
	mux.HandleFunc("/metrics", handleMetrics)
	mux.HandleFunc("/api/report", handleReport)
	mux.HandleFunc("/api/rules", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handleGetRules(w, r)
		case http.MethodPut:
			handlePutRules(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/api/siem-config", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handleGetSiemConfig(w, r)
		case http.MethodPut:
			handlePutSiemConfig(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/api/siem-cert", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		handleUploadSiemCert(w, r)
	})

	if *flagLogServerAdmin != "" {
		adminBase := strings.TrimRight(*flagLogServerAdmin, "/")
		adminToken, err := config.ResolveSecret(*flagLogServerAdminToken, *flagLogServerAdminTokenFile, "SUDO_LOGGER_ADMIN_TOKEN")
		if err != nil {
			log.Fatalf("admin token: %v", err)
		}
		mux.HandleFunc("/api/approvals", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				if !require(w, r, store.PermApprovalsRead) {
					return
				}
			} else {
				if !require(w, r, store.PermApprovalsDecide) {
					return
				}
			}
			proxyToLogServer(w, r, adminBase+"/api/approvals", adminToken, viewerFromContext(r))
		})
		mux.HandleFunc("/api/approvals/", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				if !require(w, r, store.PermApprovalsRead) {
					return
				}
			} else {
				if !require(w, r, store.PermApprovalsDecide) {
					return
				}
			}
			tail := strings.TrimPrefix(r.URL.Path, "/api/approvals/")
			proxyToLogServer(w, r, adminBase+"/api/approvals/"+tail, adminToken, viewerFromContext(r))
		})
		mux.HandleFunc("/api/approvals/callback", func(w http.ResponseWriter, r *http.Request) {
			// No decidedBy passed — identity is in the callback payload verified by HMAC
			proxyToLogServer(w, r, adminBase+"/api/approvals/callback", adminToken, "")
		})
		mux.HandleFunc("/api/approval-config", func(w http.ResponseWriter, r *http.Request) {
			if !require(w, r, store.PermApprovalsDecide) {
				return
			}
			proxyToLogServer(w, r, adminBase+"/api/approval-config", adminToken, viewerFromContext(r))
		})
		mux.HandleFunc("/api/jit-policy", func(w http.ResponseWriter, r *http.Request) {
			if !require(w, r, store.PermApprovalsDecide) {
				return
			}
			proxyToLogServer(w, r, adminBase+"/api/jit-policy", adminToken, viewerFromContext(r))
		})
		mux.HandleFunc("/api/sessions/", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodDelete {
				http.NotFound(w, r)
				return
			}
			if !require(w, r, store.PermSessionsDelete) {
				return
			}
			tsid := strings.TrimPrefix(r.URL.Path, "/api/sessions/")
			viewer := viewerFromContext(r)
			lrw := &loggingResponseWriter{ResponseWriter: w, status: http.StatusOK}
			proxyToLogServer(lrw, r, adminBase+r.URL.Path, adminToken, viewer)
			if lrw.status == http.StatusNoContent {
				go siem.SendAudit("session_deleted", map[string]any{
					"tsid":       tsid,
					"deleted_by": viewer,
				})
			}
		})
	}

	mux.HandleFunc("/api/blocked-users", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handleGetBlockedUsers(w, r)
		case http.MethodPut:
			handlePutBlockedUsers(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/api/whitelisted-users", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handleGetWhitelistedUsers(w, r)
		case http.MethodPut:
			handlePutWhitelistedUsers(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/api/retention", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handleGetRetention(w, r)
		case http.MethodPut:
			handlePutRetention(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/api/sandbox", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handleGetSandbox(w, r)
		case http.MethodPut:
			handlePutSandbox(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/api/redaction-config", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handleGetRedactionConfig(w, r)
		case http.MethodPut:
			handlePutRedactionConfig(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/api/sandbox/templates", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handleGetSandboxTemplates(w, r)
		case http.MethodPut:
			handlePutSandboxTemplates(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/api/hosts", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		handleGetHosts(w, r)
	})
	mux.HandleFunc("/api/users", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handleGetUsers(w, r)
		case http.MethodPut, http.MethodPost:
			handlePutUser(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/api/users/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.NotFound(w, r)
			return
		}
		handleDeleteUser(w, r)
	})
	mux.HandleFunc("/api/roles", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			if !require(w, r, store.PermUsersRead) {
				return
			}
			roles, err := sessionStore.GetRoles(r.Context())
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(roles)
		case http.MethodPost, http.MethodPut:
			if !require(w, r, store.PermUsersWrite) {
				return
			}
			var def store.RoleDefinition
			if err := json.NewDecoder(r.Body).Decode(&def); err != nil {
				http.Error(w, "invalid JSON", http.StatusBadRequest)
				return
			}
			if !validRoleName.MatchString(def.Name) {
				http.Error(w, "role name must match ^[a-z0-9_-]{1,64}$", http.StatusBadRequest)
				return
			}
			if !requirePermissionsContained(w, r, def.Permissions) {
				return
			}
			if err := sessionStore.UpsertRole(r.Context(), def); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/api/roles/", func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/api/roles/")
		if !validRoleName.MatchString(name) {
			http.Error(w, "role name must match ^[a-z0-9_-]{1,64}$", http.StatusBadRequest)
			return
		}
		switch r.Method {
		case http.MethodGet:
			if !require(w, r, store.PermUsersRead) {
				return
			}
			def, err := sessionStore.GetRole(r.Context(), name)
			if err != nil || def.Name == "" {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(def)
		case http.MethodPut:
			if !require(w, r, store.PermUsersWrite) {
				return
			}
			var def store.RoleDefinition
			if err := json.NewDecoder(r.Body).Decode(&def); err != nil {
				http.Error(w, "invalid JSON", http.StatusBadRequest)
				return
			}
			def.Name = name
			if !requirePermissionsContained(w, r, def.Permissions) {
				return
			}
			if err := sessionStore.UpsertRole(r.Context(), def); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		case http.MethodDelete:
			if !require(w, r, store.PermUsersWrite) {
				return
			}
			if err := sessionStore.DeleteRole(r.Context(), name); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/api/auth-config", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			if !require(w, r, store.PermConfigRead) {
				return
			}
			cfg, err := sessionStore.GetAuthConfig(r.Context())
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			// Mask the secret before sending to client
			if cfg.OIDC.ClientSecret != "" {
				cfg.OIDC.ClientSecret = "***"
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"config": cfg})
			return
		}

		if r.Method == http.MethodPut {
			if !require(w, r, store.PermConfigWrite) {
				return
			}
			var body struct {
				Config store.AuthConfig `json:"config"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, "invalid JSON", http.StatusBadRequest)
				return
			}

			oldCfg, _ := sessionStore.GetAuthConfig(r.Context())

			// If client sends "***" or empty, keep the existing secret
			if body.Config.OIDC.ClientSecret == "***" || body.Config.OIDC.ClientSecret == "" { // pragma: allowlist secret
				body.Config.OIDC.ClientSecret = oldCfg.OIDC.ClientSecret // pragma: allowlist secret
			}

			// Keep existing admin_groups unless client explicitly sends them
			if body.Config.AdminGroups == nil {
				body.Config.AdminGroups = oldCfg.AdminGroups
			}

			if err := sessionStore.SetAuthConfig(r.Context(), body.Config); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	})
	mux.HandleFunc("/api/auth-mapping", func(w http.ResponseWriter, r *http.Request) {
		if !require(w, r, store.PermConfigWrite) {
			return
		}
		if r.Method == http.MethodPut {
			var body struct {
				AdminGroups []string `json:"admin_groups"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, "invalid JSON", http.StatusBadRequest)
				return
			}

			cfg, _ := sessionStore.GetAuthConfig(r.Context())
			cfg.AdminGroups = body.AdminGroups
			if err := sessionStore.SetAuthConfig(r.Context(), cfg); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	})
	mux.HandleFunc("/api/oidc/login", handleOIDCLogin)
	mux.HandleFunc("/api/oidc/callback", handleOIDCCallback)
	mux.HandleFunc("/api/oidc/logout", handleLogout) // Redirect to unified logout
	mux.HandleFunc("/api/login", handleLocalLogin)
	mux.HandleFunc("/api/stepup", handleStepUp)
	mux.HandleFunc("/logout", handleLogout)
	mux.HandleFunc("/api/me", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		user := viewerFromContext(r)
		if user == "-" {
			user = ""
		}

		cfg, _ := sessionStore.GetAuthConfig(r.Context())
		logoutURL := ""
		if cfg.Source == "oidc" {
			logoutURL = "/api/oidc/logout"
		} else if *flagTrustedUserHeader != "" || cfg.Source == "proxy" {
			logoutURL = "/oauth2/sign_out"
		}

		perms := permsFromContext(r)
		permList := make([]string, 0, len(perms))
		for p := range perms {
			permList = append(permList, string(p))
		}
		sort.Strings(permList)
		permJSON, _ := json.Marshal(permList)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"user":%q,"logoutUrl":%q,"role":%q,"permissions":%s}`, user, logoutURL, roleFromContext(r), permJSON)
	})

	mux.HandleFunc("/api/sudoers/hosts", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		handleGetSudoersHosts(w, r)
	})
	mux.HandleFunc("/api/sudoers/snapshots", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		handleGetSudoersSnapshots(w, r)
	})
	mux.HandleFunc("/api/sudoers/config", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handleGetSudoersConfig(w, r)
		case http.MethodPut:
			handlePutSudoersConfig(w, r)
		case http.MethodDelete:
			handleDeleteSudoersConfig(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	staticFS, err := fs.Sub(staticFiles, "static")
	if err != nil {
		log.Fatalf("embed static: %v", err)
	}
	fileServer := http.FileServer(http.FS(staticFS))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Let the file server handle real static assets (JS, CSS, images).
		// For all other non-API paths, serve index.html so React Router works.
		if _, statErr := fs.Stat(staticFS, strings.TrimPrefix(r.URL.Path, "/")); statErr == nil {
			fileServer.ServeHTTP(w, r)
			return
		}
		idx, err := staticFS.Open("index.html")
		if err != nil {
			http.Error(w, "index.html not found — rebuild the UI first", http.StatusInternalServerError)
			return
		}
		defer idx.Close()
		http.ServeContent(w, r, "index.html", time.Time{}, idx.(io.ReadSeeker))
	})
}
