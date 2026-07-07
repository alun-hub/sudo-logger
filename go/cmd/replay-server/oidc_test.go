package main

// Tests for isSafeReturnPath (go/cmd/replay-server/oidc.go), the open-redirect
// guard for the OIDC step-up "return to where you were" flow.

import "testing"

func TestIsSafeReturnPath(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/config/sandbox", true},
		{"/policy/sudoers", true},
		{"/", true},
		{"", false},
		{"config/sandbox", false},             // missing leading slash
		{"//evil.com", false},                 // protocol-relative
		{"///evil.com", false},                // protocol-relative, extra slash
		{"/\\evil.com", false},                // backslash trick
		{"https://evil.com", false},           // absolute URL
		{"http://evil.com/x", false},          // absolute URL
		{"/redirect?x=http://evil.com", true}, // query string is fine, still same-origin path
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			if got := isSafeReturnPath(c.path); got != c.want {
				t.Errorf("isSafeReturnPath(%q) = %v, want %v", c.path, got, c.want)
			}
		})
	}
}
