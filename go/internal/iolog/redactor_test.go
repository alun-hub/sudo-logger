package iolog

import (
	"strings"
	"testing"

	"sudo-logger/internal/protocol"
)

func TestRedactorPromptMaskingLegitimate(t *testing.T) {
	r := NewRedactor(nil)

	// A real password prompt arrives on ttyout WITHOUT a trailing newline.
	// The redactor should activate masking.
	r.Redact([]byte("Password: "), protocol.StreamTtyOut)
	if !r.maskingActive {
		t.Fatal("expected maskingActive after legitimate prompt, got false")
	}

	// The user's typed password should be masked.
	out := r.Redact([]byte("s3cr3t"), protocol.StreamTtyIn)
	if string(out) != "******" {
		t.Fatalf("expected input masked, got %q", out)
	}

	// Enter key (\r) terminates masking.
	r.Redact([]byte("\r"), protocol.StreamTtyIn)
	if r.maskingActive {
		t.Fatal("expected maskingActive=false after \\r, got true")
	}
}

func TestRedactorEchoBypassPrevented(t *testing.T) {
	r := NewRedactor(nil)

	// An attacker runs: echo "password: "
	// The echo output contains a trailing \n — masking must NOT activate.
	r.Redact([]byte("password: \n"), protocol.StreamTtyOut)
	if r.maskingActive {
		t.Fatal("maskingActive must not activate when prompt chunk contains \\n (echo bypass)")
	}

	// The next command typed by the attacker must appear unmasked.
	cmd := "rm -rf /important"
	out := r.Redact([]byte(cmd), protocol.StreamTtyIn)
	if string(out) != cmd {
		t.Fatalf("command should not be masked after echo bypass attempt, got %q", out)
	}
}

func TestRedactorEchoBypassWithCR(t *testing.T) {
	r := NewRedactor(nil)

	// Same bypass attempt using \r instead of \n.
	r.Redact([]byte("password: \r"), protocol.StreamTtyOut)
	if r.maskingActive {
		t.Fatal("maskingActive must not activate when prompt chunk contains \\r")
	}
}

func TestRedactorNoFalsePositiveOnNonPromptOutput(t *testing.T) {
	r := NewRedactor(nil)

	// Normal output that doesn't match prompt regex must not affect masking.
	r.Redact([]byte("Hello, world!\n"), protocol.StreamTtyOut)
	if r.maskingActive {
		t.Fatal("maskingActive should not activate on non-prompt output")
	}
}

func TestRedactorSurgicalRedaction(t *testing.T) {
	r := NewRedactor(nil)

	// Surgical redaction of inline secrets must still work.
	cases := []struct {
		input    string
		mustMask string
	}{
		{"db_password=s3cr3t123", "s3cr3t123"},           // pragma: allowlist secret
		{"api_key=ABCDEFGHIJKLMNOP", "ABCDEFGHIJKLMNOP"}, // pragma: allowlist secret
	}
	for _, tc := range cases {
		out := string(r.Redact([]byte(tc.input), protocol.StreamTtyOut))
		if strings.Contains(out, tc.mustMask) {
			t.Errorf("input %q: secret %q was not redacted; got %q", tc.input, tc.mustMask, out)
		}
	}
}
