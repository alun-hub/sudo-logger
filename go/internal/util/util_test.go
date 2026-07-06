package util

import (
	"strings"
	"testing"
)

func TestSanitizeForLog(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"/api/sessions", "/api/sessions"},
		{"/api/sessions\nX-Injected: evil", "/api/sessions_X-Injected: evil"},
		{"tab\there", "tab_here"},
		{"del\x7fchar", "del_char"},
	}
	for _, tt := range tests {
		if got := SanitizeForLog(tt.in); got != tt.want {
			t.Errorf("SanitizeForLog(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestValidAgentHost(t *testing.T) {
	tests := []struct {
		host string
		want bool
	}{
		{"web-01", true},
		{"web-01.example.com", true},
		{"", false},
		{".hidden", false},
		{"has/slash", false},
		{"has\\backslash", false},
		{"../etc/passwd", false},
		{"foo..bar", false},
		{strings.Repeat("a", 256), false},
	}
	for _, tt := range tests {
		if got := ValidAgentHost(tt.host); got != tt.want {
			t.Errorf("ValidAgentHost(%q) = %v, want %v", tt.host, got, tt.want)
		}
	}
}
