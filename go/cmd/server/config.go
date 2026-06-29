package main

import (
	"flag"
)

var (
	flagListen         = flag.String("listen", ":9876", "Listen address (TLS)")
	flagLogDir         = flag.String("logdir", "/var/log/sudoreplay", "Base directory for session logs")
	flagCert           = flag.String("cert", "/etc/sudo-logger/server.crt", "Server TLS certificate")
	flagKey            = flag.String("key", "/etc/sudo-logger/server.key", "Server TLS key")
	flagCA             = flag.String("ca", "/etc/sudo-logger/ca.crt", "CA certificate (for client auth)")
	flagSignKey        = flag.String("signkey", "/etc/sudo-logger/ack-sign.key", "ed25519 private key for ACK signing (PEM)")
	flagStrictCertHost = flag.Bool("strict-cert-host", false,
		"Reject sessions where the claimed host does not match the client certificate CN/SAN. "+
			"Requires per-machine client certificates. Off by default to support shared-cert setups.")
	flagBlockedUsers = flag.String("blocked-users", "/etc/sudo-logger/blocked-users.yaml",
		"Blocked users config file (managed by sudo-replay GUI; reloaded every 30 s)")
	flagWhitelistedUsers = flag.String("whitelisted-users", "/etc/sudo-logger/whitelisted-users.yaml",
		"Whitelisted users config file — these users bypass JIT approval (managed by sudo-replay GUI; reloaded every 30 s)")
	flagApprovalPolicy = flag.String("approval-policy", "/etc/sudo-logger/approval-policy.yaml",
		"JIT approval policy file (reloaded every 30 s; feature disabled when file absent)")
	flagApprovalToken = flag.String("approval-token", "",
		"Shared secret for the approval REST API (Bearer token); required to enable /api/approvals endpoints")
	flagApprovalTokenFile = flag.String("approval-token-file", "",
		"File containing the approval REST API bearer token (alternative to -approval-token; env SUDO_LOGGER_APPROVAL_TOKEN also accepted)")
	flagSandbox = flag.String("sandbox", "/etc/sudo-logger/sandbox.yaml",
		"Process sandbox config file (served to agents)")
	flagSandboxTemplates = flag.String("sandbox-templates", "/etc/sudo-logger/sandbox-templates.json",
		"Sandbox templates file (LocalStore only)")

	// Storage backend flags.
	// NOTE: these flags are intentionally duplicated in cmd/replay-server/main.go.
	// If you change a default or description here, update that file too.
	flagStorage      = flag.String("storage", "local", "Storage backend: local|distributed")
	flagS3Bucket     = flag.String("s3-bucket", "", "S3 bucket name (distributed storage)")
	flagS3Region     = flag.String("s3-region", "us-east-1", "S3 region (distributed storage)")
	flagS3Prefix     = flag.String("s3-prefix", "sessions/", "S3 key prefix (distributed storage)")
	flagS3Endpoint   = flag.String("s3-endpoint", "", "S3-compatible endpoint URL, e.g. https://minio.internal:9000")
	flagS3PathStyle  = flag.Bool("s3-path-style", false, "Use path-style S3 URLs (required for MinIO/StorageGRID)")
	flagS3AccessKey  = flag.String("s3-access-key", "", "Static S3 access key (leave empty to use IAM/env)")
	flagS3SecretKey  = flag.String("s3-secret-key", "", "Static S3 secret key (leave empty to use IAM/env)")
	flagDBURL        = flag.String("db-url", "", "PostgreSQL DSN (distributed storage)")
	flagBufferDir    = flag.String("buffer-dir", "/var/lib/sudo-logger/buffer", "Local write-buffer dir for S3 uploads")
	flagHealthListen = flag.String("health-listen", "", "Plain HTTP address for /healthz and /metrics (e.g. :9877); disabled when empty")
)
