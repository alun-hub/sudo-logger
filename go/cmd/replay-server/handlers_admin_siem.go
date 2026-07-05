package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"sudo-logger/internal/siem"
	"sudo-logger/internal/store"
)

// handleGetSiemConfig reads the siem config from the store and returns it as JSON.
// Using the store (rather than siem.Get()) ensures the response reflects the
// persisted state even before the background reload cycle fires.
func handleGetSiemConfig(w http.ResponseWriter, r *http.Request) {
	if !require(w, r, store.PermConfigRead) {
		return
	}
	text, err := sessionStore.GetConfig(r.Context(), "siem.yaml")
	if err != nil {
		http.Error(w, "read config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	var cfg siem.Config
	if text != "" {
		if err := yaml.Unmarshal([]byte(text), &cfg); err != nil {
			http.Error(w, "parse config: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{
		"path":   *flagSiemConfig,
		"config": cfg,
	}); err != nil {
		log.Printf("encode siem config: %v", err)
	}
}

// validateTLSPaths returns an error if any non-empty path in c is not an
// absolute path or contains a ".." component.
func validateTLSPaths(label string, c siem.TLSCfg) error {
	for _, p := range []string{c.CA, c.Cert, c.Key} {
		if p == "" {
			continue
		}
		if !filepath.IsAbs(p) {
			return fmt.Errorf("%s TLS path %q must be absolute", label, p)
		}
		// Check the raw path before cleaning — filepath.Clean resolves traversal
		// components (e.g. /a/b/../../etc/passwd → /etc/passwd), which would
		// silently accept the traversal attempt.
		if strings.Contains(p, "..") {
			return fmt.Errorf("%s TLS path %q must not contain '..'", label, p)
		}
	}
	return nil
}

// handlePutSiemConfig validates and persists an updated SIEM config.
// Both servers reload within 30 s (file poller for local, DB poll for distributed).
func handlePutSiemConfig(w http.ResponseWriter, r *http.Request) {
	if !require(w, r, store.PermConfigWrite) {
		return
	}
	var body struct {
		Config siem.Config `json:"config"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	cfg := body.Config

	// Validate transport and format values to avoid writing garbage.
	switch cfg.Transport {
	case "", "https", "syslog", "stdout": // ok
	default:
		http.Error(w, "transport must be https, syslog, or stdout", http.StatusBadRequest)
		return
	}
	switch cfg.Format {
	case "", "json", "cef", "ocsf": // ok
	default:
		http.Error(w, "format must be json, cef, or ocsf", http.StatusBadRequest)
		return
	}

	// Validate TLS certificate file paths to prevent path traversal.
	if err := validateTLSPaths("https", cfg.HTTPS.TLS); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := validateTLSPaths("syslog", cfg.Syslog.TLS); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	yamlBytes, err := yaml.Marshal(cfg)
	if err != nil {
		http.Error(w, "marshal yaml: "+err.Error(), http.StatusInternalServerError)
		return
	}
	content := "# SIEM forwarding configuration — managed by sudo-replay GUI\n" +
		"# Reload cycle: 30 s (file poller for local, DB poll for distributed).\n\n" +
		string(yamlBytes)
	if err := sessionStore.SetConfig(r.Context(), "siem.yaml", content); err != nil {
		log.Printf("write siem config: %v", err)
		http.Error(w, "write failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// Apply immediately so this replica doesn't wait for the next reload cycle.
	siem.Set(cfg)
	log.Printf("siem: config updated via GUI (enabled=%v transport=%s format=%s)",
		cfg.Enabled, cfg.Transport, cfg.Format)
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]bool{"ok": true}); err != nil {
		log.Printf("encode siem response: %v", err)
	}
}

// handleUploadSiemCert accepts a PEM file upload (multipart field "file") and
// saves it under /etc/sudo-logger/ with a validated filename.
//
// Only filenames matching [a-zA-Z0-9._-]{1,64}\.(crt|pem|key) are accepted.
// The file must contain at least one PEM block and be ≤ 64 KB.
// Saved with mode 0640 (root:sudologger) so the log server can read it.
func handleUploadSiemCert(w http.ResponseWriter, r *http.Request) {
	if !require(w, r, store.PermConfigWrite) {
		return
	}
	if *flagStorage == "distributed" {
		http.Error(w,
			"cert upload is not supported in distributed mode; "+
				"mount certificates via Kubernetes Secrets instead",
			http.StatusNotImplemented)
		return
	}

	const maxSize = 64 * 1024 // 64 KB
	r.Body = http.MaxBytesReader(w, r.Body, maxSize+1024)

	if err := r.ParseMultipartForm(maxSize); err != nil {
		http.Error(w, "file too large or bad multipart: "+err.Error(), http.StatusBadRequest)
		return
	}

	f, hdr, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "missing file field", http.StatusBadRequest)
		return
	}
	defer f.Close()

	name := filepath.Base(hdr.Filename)
	if !validCertName.MatchString(name) {
		http.Error(w, "filename must match [a-zA-Z0-9._-]{1,64}.(crt|pem|key)", http.StatusBadRequest)
		return
	}

	data := make([]byte, maxSize+1)
	n, err := f.Read(data)
	if err != nil && n == 0 {
		http.Error(w, "read file: "+err.Error(), http.StatusBadRequest)
		return
	}
	if n > maxSize {
		http.Error(w, "file exceeds 64 KB limit", http.StatusRequestEntityTooLarge)
		return
	}
	data = data[:n]

	if !containsPEMBlock(data) {
		http.Error(w, "file does not contain a valid PEM block", http.StatusBadRequest)
		return
	}

	destDir := filepath.Dir(*flagSiemConfig) // same dir as siem.yaml, e.g. /etc/sudo-logger
	dest := filepath.Join(destDir, name)

	// Path traversal guard — dest must stay inside destDir.
	if filepath.Dir(dest) != destDir {
		http.Error(w, "invalid filename", http.StatusBadRequest)
		return
	}

	if err := os.WriteFile(dest, data, 0o640); err != nil {
		log.Printf("siem cert upload: write %s: %v", dest, err)
		http.Error(w, "write failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	log.Printf("siem: cert uploaded → %s (%d bytes)", dest, n)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{"path": dest}); err != nil {
		log.Printf("encode cert upload response: %v", err)
	}
}

// validCertName accepts safe filenames with a .crt, .pem, or .key extension.
var validCertName = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,64}\.(crt|pem|key)$`)

// containsPEMBlock returns true if data contains at least one valid PEM block.
func containsPEMBlock(data []byte) bool {
	return bytes.Contains(data, []byte("-----BEGIN "))
}

// sendSiemEvent looks up the completed session by tsid and forwards it to the
// configured SIEM.
func sendSiemEvent(tsid string) {
	ctx := context.Background()

	// Invalidate the cache so the completed session is visible, then find it.
	cache.invalidate()
	all, err := cache.get(ctx)
	if err != nil {
		log.Printf("siem: list sessions for %s: %v", tsid, err)
		return
	}
	var info *SessionInfo
	for i := range all {
		if all[i].TSID == tsid {
			info = &all[i]
			break
		}
	}
	if info == nil {
		log.Printf("siem: session %s not found after completion", tsid)
		return
	}

	startTime := time.Unix(info.StartTime, 0)
	endTime := startTime.Add(time.Duration(info.Duration * float64(time.Second)))

	siem.Send(siem.Event{
		SessionID:       info.SessionID,
		TSID:            tsid,
		User:            info.User,
		Host:            info.Host,
		RunasUser:       info.Runas,
		RunasUID:        info.RunasUID,
		RunasGID:        info.RunasGID,
		Cwd:             info.Cwd,
		Command:         info.Command,
		ResolvedCommand: info.ResolvedCommand,
		Flags:           info.Flags,
		StartTime:       startTime,
		EndTime:         endTime,
		ExitCode:        info.ExitCode,
		Incomplete:      info.Incomplete,
		RiskScore:       info.RiskScore,
		RiskReasons:     info.RiskReasons,
	})
}
