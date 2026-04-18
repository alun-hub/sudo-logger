package iolog

import (
	"regexp"
	"bytes"
	"sudo-logger/internal/protocol"
)

type redactPattern struct {
	re    *regexp.Regexp
	group int // 1-based index of the group to mask
}

type Redactor struct {
	patterns      []redactPattern
	custom        []*regexp.Regexp
	maskingActive bool
	promptRegex   *regexp.Regexp
}

func NewRedactor(patterns []string) *Redactor {
	r := &Redactor{
		promptRegex: regexp.MustCompile(`(?i)\b(password|passphrase|secret|token|key|cvv|pin|pass)[:=]\s*$`),
	}

	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err == nil {
			r.custom = append(r.custom, re)
		}
	}

	// 1. Assignments: key=value, key: value, key*value, "key": "value"
	// Group 1: Key + Separator
	// Group 2: The value/secret
	keys := `db_password|api_key|api_token|secret|token|auth|key|pass|AccountKey|client_secret|X-Api-Key|X-Auth-Token|AWS_SECRET_ACCESS_KEY|STRIPE_LIVE_SECRET|GCP_JSON_KEY|AWS_ACCESS_KEY_ID|backup_vault_token|github_pat|session_token`
	r.addPattern(`(?i)\b(`+keys+`)(["']?\s*[=:\*]\s*["']?)([^\s"';,]+)`, 3)

	// 2. Bearer Tokens & Docker Auth
	r.addPattern(`(?i)(Authorization:\s*Bearer\s+)([a-zA-Z0-9\-\._~+/]+=*)`, 2)
	r.addPattern(`(?i)\b(Bearer\s+)([a-zA-Z0-9\-\._~+/]{12,})`, 2)
	r.addPattern(`(?i)("auth"\s*:\s*")([a-zA-Z0-9+/=]{12,})(")`, 2)

	// 3. URL Auth (Handle passwords with @ correctly)
	// Group 1: scheme://user:
	// Group 2: password (greedy to catch @ in password)
	// Group 3: @host (requires @ followed by non-@ characters until the end or /)
	r.addPattern(`(?i)([a-z0-9+]+://[^:\s]+:)(.+)(@[^@\s/]+)`, 2)
	r.addPattern(`(?i)(-u\s+[^:\s]+:)([^\s]+)`, 2)

	// 4. Standalone Tokens
	r.addPattern(`\b(AKIA[0-9A-Z]{16})\b`, 1)
	r.addPattern(`\b((ghp|gho|ghs|ghr|ght)_[a-zA-Z0-9]{30,})\b`, 1)
	r.addPattern(`\b(sk_live_[0-9a-zA-Z]{20,})\b`, 1)
	r.addPattern(`\b(hvs\.[a-zA-Z0-9]{20,})\b`, 1)
	r.addPattern(`\b(AIza[0-9A-Za-z\-_]{30,})\b`, 1)
	// JWT: Includes dots
	r.addPattern(`\b(eyJhbGciOi[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+)\b`, 1)

	// 5. Large Blocks
	r.addPattern(`(?s)(-----BEGIN [A-Z ]+-----)(.+?)(-----END [A-Z ]+-----)`, 2)
	r.addPattern(`(https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/)([a-zA-Z0-9]{12,})`, 2)

	// 6. Financial
	r.addPattern(`\b([A-Z]{2}[0-9]{2}(?:\s?[0-9A-Z]{4}){3,})\b`, 1)
	r.addPattern(`(?i)\b(BIC|SWIFT|HANDELS)[:=]\s*\b([A-Z0-9]{8,11})\b`, 2)

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
	return string(r.Redact([]byte(s), 0xFF))
}

func (r *Redactor) Redact(data []byte, stream uint8) []byte {
	if len(data) == 0 {
		return data
	}

	res := make([]byte, len(data))
	copy(res, data)

	if r.maskingActive {
		for i := range res {
			if res[i] == '\r' || res[i] == '\n' {
				r.maskingActive = false
				break
			}
			res[i] = '*'
		}
	}

	if stream == protocol.StreamTtyOut || stream == protocol.StreamStdout {
		if r.promptRegex.Match(res) {
			r.maskingActive = true
		}
	}

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
				masked = bytes.Repeat([]byte("\n****************"), 3)
				masked = append(masked, '\n')
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
