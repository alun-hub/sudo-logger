package iolog

import (
	"bytes"
	"fmt"
	"regexp"

	"sudo-logger/internal/protocol"
)

type redactPattern struct {
	re    *regexp.Regexp
	group int // 1-based index of the group to mask
}

type Redactor struct {
	patterns      []redactPattern
	custom        []*regexp.Regexp
	// maskingActive and pemBufs are mutated on every Redact call and are NOT
	// safe for concurrent use; callers must ensure single-goroutine access
	// (the plugin path does this by calling Redact only from the connection's
	// single reader goroutine) or hold an external mutex (the eBPF path does
	// this via s.mu).
	maskingActive bool
	promptRegex   *regexp.Regexp
	triggerRegex  *regexp.Regexp // Fast-path: checks if ANY pattern might match
	// pemBufs accumulates cross-chunk PEM blocks per stream until -----END
	// arrives.
	pemBufs map[uint8][]byte
}

// RedactionRule describes a system-default masking pattern.
type RedactionRule struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Regex       string `json:"regex"`
	Group       int    `json:"group"`
}

// SystemRedactionRules is the list of built-in patterns.
var SystemRedactionRules = []RedactionRule{
	{
		Name:        "AWS Access Key",
		Description: "Identifies AWS Access Key IDs (AKIA...).",
		Regex:       `\b(AKIA[0-9A-Z]{16})\b`,
		Group:       1,
	},
	{
		Name:        "GitHub Personal Access Token",
		Description: "Matches GitHub PATs starting with ghp_.",
		Regex:       `\b(ghp_[a-zA-Z0-9]{36,})\b`,
		Group:       1,
	},
	{
		Name:        "Authorization Bearer Token",
		Description: "Matches Bearer tokens in HTTP headers or CLI flags.",
		Regex:       `(?i)(Authorization:\s*Bearer\s+|Bearer\s+)([a-zA-Z0-9\-\._~+/]+=*)`,
		Group:       2,
	},
	{
		Name:        "Slack Webhook",
		Description: "Matches Slack incoming webhook URLs.",
		Regex:       `\b(https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/)([a-zA-Z0-9]{12,})\b`,
		Group:       2,
	},
	{
		Name:        "Google API Key",
		Description: "Matches Google Cloud Platform API keys.",
		Regex:       `\b(AIza[0-9A-Za-z\-_]{35})\b`,
		Group:       1,
	},
	{
		Name:        "Stripe Live Secret",
		Description: "Matches Stripe live secret keys.",
		Regex:       `\b(sk_live_[0-9a-zA-Z]{24,})\b`,
		Group:       1,
	},
	{
		Name:        "Private Key Block",
		Description: "Masks entire PEM-encoded private key blocks.",
		Regex:       `(?s)(-----BEGIN [A-Z ]+-----)(.+?)(-----END [A-Z ]+-----)`,
		Group:       2,
	},
	{
		Name:        "URL Credentials",
		Description: "Matches credentials in connection strings (e.g. postgres://user:pass@host).", // pragma: allowlist secret
		Regex:       `(?i)([a-z0-9+]+://[^:\s]+:)(.+)(@[^@\s/]+)`, // pragma: allowlist secret
		Group:       2,
	},
	{
		Name:        "High Entropy Token (Assignment)",
		Description: "Matches any assignment where the value is a 24+ char hex/base64 string, regardless of variable name.",
		Regex:       `\b([A-Z0-9_]+)\s*[:=]\s*(['"]?)([a-f0-9]{24,}|[a-zA-Z0-9\-_+/=]{24,})\b`,
		Group:       3,
	},
	{
		Name:        "Generic Variable Assignment",
		Description: "Matches variables containing KEY, SECRET, TOKEN, AUTH, PASS, PWD, or ACCESS.",
		Regex:       `(?i)(export\s+)?([A-Z0-9_]*(KEY|SECRET|TOKEN|AUTH|PASS|PWD|PASSWORD|ACCESS)[A-Z0-9_]*)\s*[:=]\s*(['"]?)([^\s'"]+)(['"]?)`,
		Group:       5,
	},
}

func NewRedactor(patterns []string) (*Redactor, error) {
	r := &Redactor{
		promptRegex: regexp.MustCompile(`(?i)\b(password|passphrase|secret|token|key|cvv|pin|pass)[:=]\s*$`),
	}

	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("invalid mask_pattern %q: %w", p, err)
		}
		r.custom = append(r.custom, re)
	}

	// Add system default patterns
	for _, rule := range SystemRedactionRules {
		r.addPattern(rule.Regex, rule.Group)
	}

	// Define keywords for the fast-path trigger check.
	// This ensures we don't run expensive regex on every chunk.
	// Note: No word boundaries (\b) here to catch keywords inside larger strings (e.g. db_password).
	// We also include common token prefixes and URL indicators.
	triggerPatterns := `(?i)KEY|SECRET|TOKEN|AUTH|PASS|PWD|ACCESS|Bearer|Authorization|ghp_|sk_live_|AIza|-----BEGIN|AKIA|hooks|http|[:=]\s*[a-zA-Z0-9\-_]{24}`
	r.triggerRegex = regexp.MustCompile(triggerPatterns)

	return r, nil
}

// MustNewRedactor is like NewRedactor but panics if the patterns are invalid.
// Use only when patterns are already validated.
func MustNewRedactor(patterns []string) *Redactor {
	r, err := NewRedactor(patterns)
	if err != nil {
		panic(err)
	}
	return r
}


func (r *Redactor) addPattern(p string, group int) {
	re, err := regexp.Compile(p)
	if err == nil {
		r.patterns = append(r.patterns, redactPattern{re, group})
	}
}

func (r *Redactor) RedactString(s string) string {
	if s == "" {
		return ""
	}
	data, _ := r.Redact([]byte(s), 0xFF) // 0xFF never triggers PEM buffering
	return string(data)
}

var (
	pemBeginMarker = []byte("-----BEGIN ")
	pemEndMarker   = []byte("-----END ")
	// pemMaxBuf is the upper bound on buffered PEM data. If exceeded we flush
	// immediately so a pathological session cannot exhaust agent memory.
	pemMaxBuf = 64 * 1024
)

// Redact returns (data, buffering). When buffering is true the chunk has been
// absorbed into an internal per-stream PEM accumulation buffer; the caller
// must not forward it. The combined, redacted block is returned on the chunk
// that completes the -----END line (buffering=false). Call FlushPEM at
// session end to drain any incomplete buffer.
func (r *Redactor) Redact(data []byte, stream uint8) ([]byte, bool) {
	if len(data) == 0 {
		return data, false
	}

	// ── 1. Interactive prompt masking (Stateful) ───────────────────────────
	// This MUST be checked first and doesn't care about the fast path.
	if r.maskingActive {
		res := make([]byte, len(data))
		copy(res, data)
		for i := range res {
			if res[i] == '\r' || res[i] == '\n' {
				r.maskingActive = false
				break
			}
			res[i] = '*'
		}
		return res, false
	}

	// ── 2. Prompt detection in Output ──────────────────────────────────────
	if stream == protocol.StreamTtyOut || stream == protocol.StreamStdout {
		// Only activate masking if the prompt chunk has no trailing newline.
		// Real password prompts (sudo, ssh, su) wait inline without a newline;
		// `echo "password: "` always appends \n and must not trigger masking.
		if r.promptRegex.Match(data) && !bytes.ContainsAny(data, "\r\n") {
			r.maskingActive = true
		}
	}

	// ── 2.5 PEM block buffering ────────────────────────────────────────────
	// PTY output splits -----BEGIN / body / -----END across separate chunks,
	// which prevents the multi-line regex from matching. Accumulate per stream
	// until the END marker arrives, then redact the combined block at once.
	if r.pemBufs == nil {
		r.pemBufs = make(map[uint8][]byte)
	}
	if buf, active := r.pemBufs[stream]; active {
		buf = append(buf, data...)
		if bytes.Contains(buf, pemEndMarker) || len(buf) >= pemMaxBuf {
			delete(r.pemBufs, stream)
			return r.applyPatterns(buf), false
		}
		r.pemBufs[stream] = buf
		return nil, true
	}
	if bytes.Contains(data, pemBeginMarker) && !bytes.Contains(data, pemEndMarker) {
		r.pemBufs[stream] = append([]byte(nil), data...)
		return nil, true
	}

	// ── 3. Fast Path Check ────────────────────────────────────────────────
	// If the chunk doesn't contain any trigger patterns AND we aren't in
	// active masking mode, we can skip all expensive regex replacements.
	if !r.triggerRegex.Match(data) {
		return data, false
	}

	// ── 4. Surgical Redaction (Slow Path) ──────────────────────────────────
	return r.applyPatterns(data), false
}

// FlushPEM drains any incomplete PEM buffer for stream and returns
// best-effort redacted data. Returns nil if nothing was buffered.
// Must be called at session end to avoid silently dropping partial key output.
func (r *Redactor) FlushPEM(stream uint8) []byte {
	if r.pemBufs == nil {
		return nil
	}
	buf := r.pemBufs[stream]
	delete(r.pemBufs, stream)
	if len(buf) == 0 {
		return nil
	}
	// If the block is complete the normal patterns can handle it.
	if bytes.Contains(buf, pemEndMarker) {
		return r.applyPatterns(buf)
	}
	// Incomplete block (session ended before -----END arrived): keep the
	// -----BEGIN ... ----- header line for context and mask the body.
	if nl := bytes.IndexByte(buf, '\n'); nl >= 0 {
		out := make([]byte, nl+1, len(buf))
		copy(out, buf[:nl+1])
		out = append(out, bytes.Repeat([]byte("*"), len(buf)-nl-1)...)
		return out
	}
	return bytes.Repeat([]byte("*"), len(buf))
}

// applyPatterns runs the full regex substitution suite against data. Each
// pattern re-copies the whole buffer via ReplaceAllFunc, so cost is
// O(len(patterns) * len(data)); this is fine for TTY chunk sizes (a few KB,
// gated by the triggerRegex fast path above) but would need a single-pass
// combined matcher if chunk sizes ever grow substantially.
func (r *Redactor) applyPatterns(data []byte) []byte {
	res := make([]byte, len(data))
	copy(res, data)

	for _, p := range r.patterns {
		res = p.re.ReplaceAllFunc(res, func(match []byte) []byte {
			sub := p.re.FindSubmatchIndex(match)
			if sub == nil {
				return match
			}

			startIdx := sub[p.group*2]
			endIdx := sub[p.group*2+1]

			if startIdx < 0 || endIdx < 0 {
				return match
			}

			secretLen := endIdx - startIdx // pragma: allowlist secret
			var masked []byte

			if bytes.HasPrefix(match, []byte("-----BEGIN")) && p.group == 2 {
				masked = bytes.Repeat([]byte("\r\n****************"), 3)
				masked = append(masked, "\r\n"...)
			} else if p.group == 1 && secretLen > 16 {
				masked = make([]byte, secretLen)
				copy(masked, match[startIdx:startIdx+4])
				for i := 4; i < secretLen; i++ {
					masked[i] = '*'
				}
			} else {
				masked = bytes.Repeat([]byte("*"), secretLen)
			}

			out := make([]byte, 0, len(match))
			out = append(out, match[:startIdx]...)
			out = append(out, masked...)
			out = append(out, match[endIdx:]...)
			return out
		})
	}

	for _, re := range r.custom {
		res = re.ReplaceAllFunc(res, func(match []byte) []byte {
			return bytes.Repeat([]byte("*"), len(match))
		})
	}

	return res
}
