package iolog

import (
	"bytes"
	"strings"
	"testing"

	"sudo-logger/internal/protocol"
)

func TestRedactorPromptMaskingLegitimate(t *testing.T) {
	r := MustNewRedactor(nil)

	// A real password prompt arrives on ttyout WITHOUT a trailing newline.
	// The redactor should activate masking.
	r.Redact([]byte("Password: "), protocol.StreamTtyOut)
	if !r.maskingActive {
		t.Fatal("expected maskingActive after legitimate prompt, got false")
	}

	// The user's typed password should be masked.
	out, _ := r.Redact([]byte("s3cr3t"), protocol.StreamTtyIn)
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
	r := MustNewRedactor(nil)

	// An attacker runs: echo "password: "
	// The echo output contains a trailing \n — masking must NOT activate.
	r.Redact([]byte("password: \n"), protocol.StreamTtyOut)
	if r.maskingActive {
		t.Fatal("maskingActive must not activate when prompt chunk contains \\n (echo bypass)")
	}

	// The next command typed by the attacker must appear unmasked.
	cmd := "rm -rf /important"
	out, _ := r.Redact([]byte(cmd), protocol.StreamTtyIn)
	if string(out) != cmd {
		t.Fatalf("command should not be masked after echo bypass attempt, got %q", out)
	}
}

func TestRedactorEchoBypassWithCR(t *testing.T) {
	r := MustNewRedactor(nil)

	// Same bypass attempt using \r instead of \n.
	r.Redact([]byte("password: \r"), protocol.StreamTtyOut)
	if r.maskingActive {
		t.Fatal("maskingActive must not activate when prompt chunk contains \\r")
	}
}

func TestRedactorNoFalsePositiveOnNonPromptOutput(t *testing.T) {
	r := MustNewRedactor(nil)

	// Normal output that doesn't match prompt regex must not affect masking.
	r.Redact([]byte("Hello, world!\n"), protocol.StreamTtyOut)
	if r.maskingActive {
		t.Fatal("maskingActive should not activate on non-prompt output")
	}
}

func TestRedactorPEMSingleChunk(t *testing.T) {
	r := MustNewRedactor(nil)

	key := "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAA=\n-----END OPENSSH PRIVATE KEY-----\n" // pragma: allowlist secret
	data, buffering := r.Redact([]byte(key), protocol.StreamTtyOut)
	if buffering {
		t.Fatal("single-chunk PEM should not be buffered")
	}
	if bytes.Contains(data, []byte("b3BlbnNzaC1rZXktdjEAAAA=")) {
		t.Errorf("key body was not redacted in single-chunk case; got %q", data)
	}
}

func TestRedactorPEMCrossChunk(t *testing.T) {
	r := MustNewRedactor(nil)

	chunks := [][]byte{
		[]byte("-----BEGIN OPENSSH PRIVATE KEY-----\r\n"), // pragma: allowlist secret
		[]byte("b3BlbnNzaC1rZXktdjEAAAA=\r\n"),
		[]byte("-----END OPENSSH PRIVATE KEY-----\r\n"),
	}

	// First two chunks should be absorbed.
	for i, chunk := range chunks[:2] {
		data, buffering := r.Redact(chunk, protocol.StreamTtyOut)
		if !buffering {
			t.Fatalf("chunk %d: expected buffering=true", i)
		}
		if data != nil {
			t.Fatalf("chunk %d: expected nil data while buffering, got %q", i, data)
		}
	}

	// Third chunk (END marker) should flush and redact.
	data, buffering := r.Redact(chunks[2], protocol.StreamTtyOut)
	if buffering {
		t.Fatal("final chunk should not be buffering")
	}
	if bytes.Contains(data, []byte("b3BlbnNzaC1rZXktdjEAAAA=")) {
		t.Errorf("key body was not redacted in cross-chunk case; got %q", data)
	}
}

func TestRedactorPEMFlushIncomplete(t *testing.T) {
	r := MustNewRedactor(nil)

	// Session ends before -----END arrives; FlushPEM should redact what we have.
	r.Redact([]byte("-----BEGIN RSA PRIVATE KEY-----\r\n"), protocol.StreamTtyOut) // pragma: allowlist secret
	r.Redact([]byte("MIIEowIBAAKCAQEA...\r\n"), protocol.StreamTtyOut)

	flushed := r.FlushPEM(protocol.StreamTtyOut)
	if flushed == nil {
		t.Fatal("expected non-nil flush for incomplete PEM block")
	}
	if bytes.Contains(flushed, []byte("MIIEowIBAAKCAQEA")) {
		t.Errorf("key body was not redacted on flush; got %q", flushed)
	}
}

func TestRedactorSurgicalRedaction(t *testing.T) {
	r := MustNewRedactor(nil)

	// Surgical redaction of inline secrets must still work.
	cases := []struct {
		input    string
		mustMask string
	}{
		{"db_password=s3cr3t123", "s3cr3t123"},           // pragma: allowlist secret
		{"export GITHUB_PERSONAL_ACCESS_TOKEN=foo", "foo"},
		{"GEMINI_API_KEY=bar", "bar"},                    // pragma: allowlist secret
		{"export HOSTUP_API_KEY=\"baz\"", "baz"},
		{"KALLE=L-WO6jacYd5wucJu2u9PKEnB5SFt30yX", "L-WO6jacYd5wucJu2u9PKEnB5SFt30yX"}, // pragma: allowlist secret
		{"UNIFI=0123456789abcdef0123456789abcdef", "0123456789abcdef0123456789abcdef"}, // pragma: allowlist secret
		{"Authorization: Bearer my-secret-token", "my-secret-token"},
		{"https://hooks.slack.com/services/T12345678/B12345678/token12345678", "token12345678"},
	}
	for _, tc := range cases {
		data, _ := r.Redact([]byte(tc.input), protocol.StreamTtyOut)
		out := string(data)
		if strings.Contains(out, tc.mustMask) {
			t.Errorf("input %q: secret %q was not redacted; got %q", tc.input, tc.mustMask, out)
		}
	}
}

// TestRedactString_PEMMarkerDoesNotSwallowInput covers a string that merely
// mentions a PEM header. Routed through Redact's streaming path such a string
// was absorbed into the per-stream PEM buffer and came back empty, taking every
// later call on the same Redactor with it.
func TestRedactString_PEMMarkerDoesNotSwallowInput(t *testing.T) {
	r := MustNewRedactor(nil)

	cmd := `sh -c 'echo -----BEGIN CERTIFICATE----- > /tmp/x'`
	if got := r.RedactString(cmd); got != cmd {
		t.Errorf("command mentioning a PEM header was altered:\n got %q\nwant %q", got, cmd)
	}

	// The Redactor must not have been left in a state that eats later input.
	const next = "deploying the new billing service"
	if got := r.RedactString(next); got != next {
		t.Errorf("later call contaminated by earlier one:\n got %q\nwant %q", got, next)
	}
}

// TestRedactString_StillMasksSecrets guards the other direction: bypassing the
// streaming path must not bypass redaction itself.
func TestRedactString_StillMasksSecrets(t *testing.T) {
	r := MustNewRedactor(nil)

	for _, tc := range []struct{ name, in, mustNotContain string }{
		{"aws key", "aws configure set key AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE"}, // pragma: allowlist secret
		{"github pat", "git clone https://ghp_abcdefghijklmnopqrstuvwxyz0123456789@x", "ghp_abcdefghijklmnopqrstuvwxyz0123456789"}, // pragma: allowlist secret
		{"assignment", "export DB_PASSWORD=hunter2hunter2hunter2", "hunter2hunter2hunter2"}, // pragma: allowlist secret
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := r.RedactString(tc.in)
			if strings.Contains(got, tc.mustNotContain) {
				t.Errorf("secret survived redaction: %q", got)
			}
			if got == "" {
				t.Error("whole string was dropped instead of masked")
			}
		})
	}
}

// TestRedactString_DoesNotDisturbStreamState makes sure the string path cannot
// interfere with an in-flight stream on the same Redactor: the agent uses one
// Redactor for both a session's command line and its I/O chunks.
func TestRedactString_DoesNotDisturbStreamState(t *testing.T) {
	r := MustNewRedactor(nil)

	// Open a PEM block on a real stream; it must stay buffered.
	if _, buffering := r.Redact([]byte("-----BEGIN PRIVATE KEY-----\nabc\n"), protocol.StreamTtyOut); !buffering {
		t.Fatal("expected the stream to start buffering the PEM block")
	}
	// A string redaction in between must neither consume nor flush that buffer.
	if got := r.RedactString("systemctl restart nginx"); got != "systemctl restart nginx" {
		t.Errorf("RedactString returned %q", got)
	}
	if flushed := r.FlushPEM(protocol.StreamTtyOut); flushed == nil {
		t.Error("stream PEM buffer was lost while redacting a string")
	}
}
