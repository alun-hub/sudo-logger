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
	"strings"
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
			log.Printf("siem: HTTPS: %v", err)
		}
	case "syslog":
		if err := sendSyslog(cfg, e, body); err != nil {
			log.Printf("siem: syslog: %v", err)
		}
	default:
		log.Printf("siem: unknown transport %q — use https or syslog", cfg.Transport)
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

// sendHTTPS POSTs body to cfg.HTTPS.URL.
// TLS client certificates are required (mTLS); the CA field must point to the
// server CA so the certificate can be verified.
// A token, if set, is sent as:
//   - "Authorization: Splunk <token>"  when the URL contains /services/collector
//   - "Authorization: Bearer <token>"  otherwise
func sendHTTPS(cfg Config, e Event, body []byte, contentType string) error {
	tlsCfg, err := buildTLSConfig(cfg.HTTPS.TLS)
	if err != nil {
		return fmt.Errorf("build TLS: %w", err)
	}

	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
		Timeout:   5 * time.Second,
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

// buildTLSConfig constructs a *tls.Config from the given TLSCfg paths.
//   - All empty → default config (system root CAs, no client cert).
//   - CA only   → custom root CA, no client cert (one-way TLS).
//   - CA+Cert+Key → custom root CA + client certificate (mTLS).
func buildTLSConfig(c TLSCfg) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}

	if c.CA != "" {
		pem, err := os.ReadFile(c.CA)
		if err != nil {
			return nil, fmt.Errorf("read CA %s: %w", c.CA, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("parse CA cert from %s", c.CA)
		}
		cfg.RootCAs = pool
	}

	if c.Cert != "" || c.Key != "" {
		if c.Cert == "" || c.Key == "" {
			return nil, fmt.Errorf("both cert and key must be specified together")
		}
		cert, err := tls.LoadX509KeyPair(c.Cert, c.Key)
		if err != nil {
			return nil, fmt.Errorf("load client cert/key: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}

	return cfg, nil
}
