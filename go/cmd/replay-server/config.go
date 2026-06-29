package main

import (
	"flag"
)

var (
	flagVersion                 = flag.Bool("version", false, "Print version and exit")
	flagListen                  = flag.String("listen", ":8080", "Listen address")
	flagLogDir                  = flag.String("logdir", "/var/log/sudoreplay", "Base directory for session logs")
	flagRules                   = flag.String("rules", "/etc/sudo-logger/risk-rules.yaml", "Risk scoring rules file")
	flagSandbox                 = flag.String("sandbox", "/etc/sudo-logger/sandbox.yaml", "Process sandbox config file (served to agents)")
	flagSandboxTemplates        = flag.String("sandbox-templates", "/etc/sudo-logger/sandbox-templates.json", "Sandbox templates file (LocalStore only)")
	flagSiemConfig              = flag.String("siem-config", "/etc/sudo-logger/siem.yaml", "SIEM forwarding config file (shared with log server)")
	flagBlockedUsers            = flag.String("blocked-users", "/etc/sudo-logger/blocked-users.yaml", "Blocked users config file (shared with log server)")
	flagWhitelistedUsers        = flag.String("whitelisted-users", "/etc/sudo-logger/whitelisted-users.yaml", "Whitelisted users config file — these users bypass JIT approval (shared with log server)")
	flagLogServerAdmin          = flag.String("logserver-admin", "", "Log server admin address for approval API (e.g. http://localhost:9877); empty disables approvals tab")
	flagLogServerAdminToken     = flag.String("logserver-admin-token", "", "Shared bearer token for the log server approval API (must match -approval-token on the log server)")
	flagLogServerAdminTokenFile = flag.String("logserver-admin-token-file", "", "File containing the log server admin bearer token (alternative to -logserver-admin-token; env SUDO_LOGGER_ADMIN_TOKEN also accepted)")
	flagTLSCert                 = flag.String("tls-cert", "", "TLS certificate file (enables HTTPS)")
	flagTLSKey                  = flag.String("tls-key", "", "TLS private key file (enables HTTPS)")
	flagHTPasswd                = flag.String("htpasswd", "", "Path to htpasswd file for HTTP Basic Auth (bcrypt hashes only; reload with SIGHUP)")
	flagTrustedUserHeader       = flag.String("trusted-user-header", "", "Header containing pre-authenticated username (e.g. X-Forwarded-User)")
	flagAdminUsers              = flag.String("admin-users", "", "Comma-separated list of usernames granted admin role (can view all sessions, approve, delete)")

	// ── OIDC (Enterprise) ───────────────────────────────────────────────────
	flagOIDCIssuer   = flag.String("oidc-issuer", "", "OIDC provider issuer URL (e.g. https://accounts.google.com)")
	flagOIDCClientID = flag.String("oidc-client-id", "", "OIDC client ID")
	flagOIDCSecret   = flag.String("oidc-client-secret", "", "OIDC client secret")
	flagOIDCRedirect = flag.String("oidc-redirect-url", "", "OIDC redirect URL (e.g. https://replay.example.com/api/oidc/callback)")

	// Storage backend flags.
	// NOTE: these flags are intentionally duplicated in cmd/server/main.go.
	// If you change a default or description here, update that file too.
	flagStorage     = flag.String("storage", "local", "Storage backend: local|distributed")
	flagS3Bucket    = flag.String("s3-bucket", "", "S3 bucket name (distributed storage)")
	flagS3Region    = flag.String("s3-region", "us-east-1", "S3 region (distributed storage)")
	flagS3Prefix    = flag.String("s3-prefix", "sessions/", "S3 key prefix (distributed storage)")
	flagS3Endpoint  = flag.String("s3-endpoint", "", "S3-compatible endpoint URL, e.g. https://minio.internal:9000")
	flagS3PathStyle = flag.Bool("s3-path-style", false, "Use path-style S3 URLs (required for MinIO/StorageGRID)")
	flagS3AccessKey = flag.String("s3-access-key", "", "Static S3 access key (leave empty to use IAM/env)")
	flagS3SecretKey = flag.String("s3-secret-key", "", "Static S3 secret key (leave empty to use IAM/env)")
	flagDBURL       = flag.String("db-url", "", "PostgreSQL DSN (distributed storage)")
	flagBufferDir   = flag.String("buffer-dir", "/var/lib/sudo-logger/buffer", "Local write-buffer dir for S3 uploads")
)
