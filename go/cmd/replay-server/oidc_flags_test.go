package main

// The -oidc-* flags are deprecated and read by nothing: OIDC is configured
// through the admin UI and stored with the rest of the auth settings. They stay
// declared so deployments already passing them keep starting, which means the
// only thing standing between an operator and a silent no-op is this warning.

import (
	"bytes"
	"log"
	"strings"
	"testing"
)

func captureLog(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	old := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(old) })
	fn()
	return buf.String()
}

func setOIDCFlag(t *testing.T, target *string, value string) {
	t.Helper()
	old := *target
	*target = value
	t.Cleanup(func() { *target = old })
}

func TestWarnOnDeadOIDCFlags_SilentWhenUnset(t *testing.T) {
	if out := captureLog(t, warnOnDeadOIDCFlags); out != "" {
		t.Errorf("warned even though no OIDC flag was set: %s", out)
	}
}

func TestWarnOnDeadOIDCFlags_NamesEveryFlagThatWasSet(t *testing.T) {
	setOIDCFlag(t, flagOIDCIssuer, "https://accounts.example.com")
	setOIDCFlag(t, flagOIDCClientID, "client-abc")

	out := captureLog(t, warnOnDeadOIDCFlags)
	for _, want := range []string{"-oidc-client-id", "-oidc-issuer", "ignored"} {
		if !strings.Contains(out, want) {
			t.Errorf("warning does not mention %q: %s", want, out)
		}
	}
	if strings.Contains(out, "-oidc-client-secret") {
		t.Errorf("warning names a flag that was not set: %s", out)
	}
}

// The secret's value must never reach the log, only its flag name.
func TestWarnOnDeadOIDCFlags_DoesNotLogValues(t *testing.T) {
	const secret = "super-secret-value" // pragma: allowlist secret
	setOIDCFlag(t, flagOIDCSecret, secret)

	if out := captureLog(t, warnOnDeadOIDCFlags); strings.Contains(out, secret) {
		t.Errorf("flag value leaked into the log: %s", out)
	}
}
