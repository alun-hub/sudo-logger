package siem

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Send encodes and forwards e to the configured SIEM endpoint.
// It is safe to call as a goroutine; all errors are logged and discarded
// so that a SIEM outage never blocks session close.
func Send(e Event) {
	cfg := Get()
	if !cfg.Enabled {
		return
	}

	if cfg.ReplayURLBase != "" && e.TSID != "" {
		// TSID format: user/host_YYYYmmdd-HHMMSS — same as ?tsid= in the replay GUI
		base := strings.TrimRight(cfg.ReplayURLBase, "/")
		e.ReplayURL = base + "/?tsid=" + url.QueryEscape(e.TSID)
	}

	body, contentType, err := encodeEvent(e, cfg.Format)
	if err != nil {
		log.Printf("siem: encode (%s): %v", cfg.Format, err)
		return
	}

	switch cfg.Transport {
	case "https":
		if err := sendHTTPS(cfg, e, body, contentType); err != nil {
			log.Printf("siem: [%s] HTTPS error: %v", e.SessionID, err)
		} else {
			log.Printf("siem: [%s] sent user=%s host=%s cmd=%q format=%s transport=https replay_url=%q",
				e.SessionID, e.User, e.Host, truncate(e.Command, 60), cfg.Format, e.ReplayURL)
		}
	case "syslog":
		if err := sendSyslog(cfg, e, body); err != nil {
			log.Printf("siem: [%s] syslog error: %v", e.SessionID, err)
		} else {
			log.Printf("siem: [%s] sent user=%s host=%s cmd=%q format=%s transport=%s replay_url=%q",
				e.SessionID, e.User, e.Host, truncate(e.Command, 60), cfg.Format, cfg.Syslog.Protocol, e.ReplayURL)
		}
	case "stdout":
		// Write a single line to stdout for container log collectors
		// (Fluentd, Promtail, Vector, etc.).  No TLS or endpoint config needed.
		fmt.Fprintf(os.Stdout, "%s\n", bytes.TrimRight(body, "\n"))
		log.Printf("siem: [%s] stdout user=%s host=%s cmd=%q format=%s replay_url=%q",
			e.SessionID, e.User, e.Host, truncate(e.Command, 60), cfg.Format, e.ReplayURL)
	default:
		log.Printf("siem: unknown transport %q — use https, syslog, or stdout", cfg.Transport)
	}
}

// encodeEvent returns (body, contentType, error) for the chosen format.
func encodeEvent(e Event, format string) ([]byte, string, error) {
	switch format {
	case "cef":
		return []byte(e.FormatCEF()), "text/plain; charset=utf-8", nil
	case "ocsf":
		b, err := e.FormatOCSF()
		return b, "application/json", err
	default: // "json" and anything unrecognised
		b, err := e.FormatJSON()
		return b, "application/json", err
	}
}

// ── HTTPS transport ───────────────────────────────────────────────────────────

// httpsClientMu guards the cached http.Client and its key.
var (
	httpsClientMu  sync.Mutex
	httpsClientKey string // CA+Cert+Key paths, tab-separated
	httpsClient    *http.Client
)

// getHTTPSClient returns a cached *http.Client for the given TLS config.
// The client is rebuilt only when the certificate file paths change.
func getHTTPSClient(c TLSCfg) (*http.Client, error) {
	key := c.CA + "\t" + c.Cert + "\t" + c.Key
	httpsClientMu.Lock()
	defer httpsClientMu.Unlock()
	if httpsClient != nil && key == httpsClientKey {
		return httpsClient, nil
	}
	tlsCfg, err := buildTLSConfig(c)
	if err != nil {
		return nil, err
	}
	httpsClient = &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
		Timeout:   5 * time.Second,
	}
	httpsClientKey = key // pragma: allowlist secret
	return httpsClient, nil
}

// sendHTTPS POSTs body to cfg.HTTPS.URL.
// TLS client certificates are required (mTLS); the CA field must point to the
// server CA so the certificate can be verified.
// A token, if set, is sent as:
//   - "Authorization: Splunk <token>"  when the URL contains /services/collector
//   - "Authorization: Bearer <token>"  otherwise
func sendHTTPS(cfg Config, e Event, body []byte, contentType string) error {
	// Validate URL to prevent SSRF via config manipulation.
	u, parseErr := url.Parse(cfg.HTTPS.URL)
	if parseErr != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("HTTPS URL must be a valid https:// address, got %q", cfg.HTTPS.URL)
	}

	client, err := getHTTPSClient(cfg.HTTPS.TLS)
	if err != nil {
		return fmt.Errorf("build TLS: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, cfg.HTTPS.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", contentType)
	if cfg.HTTPS.Token != "" {
		prefix := "Bearer"
		if strings.Contains(cfg.HTTPS.URL, "/services/collector") {
			prefix = "Splunk"
		}
		req.Header.Set("Authorization", prefix+" "+cfg.HTTPS.Token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d from %s", resp.StatusCode, cfg.HTTPS.URL)
	}
	return nil
}

// ── Syslog transport ──────────────────────────────────────────────────────────

// syslogPRI computes an RFC 5424 PRI value.
// Facility: LOG_AUTHPRIV (10).  Severity: NOTICE (5) on success, WARNING (4) on failure.
func syslogPRI(exitCode int32, incomplete bool) int {
	const facilityAuthPriv = 10
	sev := 5 // LOG_NOTICE
	if exitCode != 0 || incomplete {
		sev = 4 // LOG_WARNING
	}
	return facilityAuthPriv*8 + sev
}

// sendSyslog formats and delivers a RFC 5424 message over UDP, plain TCP, or
// TCP with mTLS.  TCP messages use newline framing (RFC 6587 §3.4.2).
func sendSyslog(cfg Config, e Event, body []byte) error {
	pri := syslogPRI(e.ExitCode, e.Incomplete)
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "-"
	}

	// RFC 5424: <PRI>VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID SP STRUCTURED-DATA SP MSG
	msg := fmt.Sprintf("<%d>1 %s %s sudo-logger - sudo-session - %s\n",
		pri,
		time.Now().UTC().Format(time.RFC3339),
		hostname,
		string(body),
	)

	const dialTimeout = 3 * time.Second
	const writeTimeout = 3 * time.Second

	switch cfg.Syslog.Protocol {
	case "udp":
		conn, err := net.DialTimeout("udp", cfg.Syslog.Addr, dialTimeout)
		if err != nil {
			return err
		}
		defer conn.Close()
		conn.SetWriteDeadline(time.Now().Add(writeTimeout)) //nolint:errcheck
		_, err = conn.Write([]byte(msg))
		return err

	case "tcp":
		conn, err := net.DialTimeout("tcp", cfg.Syslog.Addr, dialTimeout)
		if err != nil {
			return err
		}
		defer conn.Close()
		conn.SetWriteDeadline(time.Now().Add(writeTimeout)) //nolint:errcheck
		_, err = conn.Write([]byte(msg))
		return err

	case "tcp-tls":
		tlsCfg, err := buildTLSConfig(cfg.Syslog.TLS)
		if err != nil {
			return fmt.Errorf("build TLS: %w", err)
		}
		host, _, _ := net.SplitHostPort(cfg.Syslog.Addr)
		if host != "" {
			tlsCfg.ServerName = host
		}
		conn, err := tls.DialWithDialer(
			&net.Dialer{Timeout: dialTimeout},
			"tcp", cfg.Syslog.Addr, tlsCfg,
		)
		if err != nil {
			return err
		}
		defer conn.Close()
		conn.SetWriteDeadline(time.Now().Add(writeTimeout)) //nolint:errcheck
		_, err = conn.Write([]byte(msg))
		return err

	default:
		return fmt.Errorf("unknown syslog protocol %q (use udp, tcp, or tcp-tls)", cfg.Syslog.Protocol)
	}
}

// ── TLS helper ────────────────────────────────────────────────────────────────

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// buildTLSConfig constructs a *tls.Config from the given TLSCfg paths.
//   - All empty → default config (system root CAs, no client cert).
//   - CA only   → custom root CA, no client cert (one-way TLS).
//   - CA+Cert+Key → custom root CA + client certificate (mTLS).
func buildTLSConfig(c TLSCfg) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS13}

	if c.CA != "" {
		caPath := filepath.Clean(c.CA)
		if !filepath.IsAbs(caPath) {
			return nil, fmt.Errorf("CA path must be absolute: %q", c.CA)
		}
		pem, err := os.ReadFile(caPath)
		if err != nil {
			return nil, fmt.Errorf("read CA %s: %w", caPath, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("parse CA cert from %s", caPath)
		}
		cfg.RootCAs = pool
	}

	if c.Cert != "" || c.Key != "" {
		if c.Cert == "" || c.Key == "" {
			return nil, fmt.Errorf("both cert and key must be specified together")
		}
		certPath := filepath.Clean(c.Cert)
		keyPath := filepath.Clean(c.Key)
		if !filepath.IsAbs(certPath) || !filepath.IsAbs(keyPath) {
			return nil, fmt.Errorf("cert and key paths must be absolute")
		}
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, fmt.Errorf("load client cert/key: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}

	return cfg, nil
}
