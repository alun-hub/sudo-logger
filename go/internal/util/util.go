// Package util holds small helpers shared between the server and
// replay-server binaries that would otherwise drift apart as separate
// copies (they live in different `package main`s and can't share code any
// other way).
package util

import "strings"

// SanitizeForLog replaces control characters (including DEL) with '_' so a
// value that ends up in a log line (usernames, hostnames, request paths,
// etc.) can't inject fake log lines or terminal escape sequences via
// embedded newlines/control bytes.
func SanitizeForLog(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return '_'
		}
		return r
	}, s)
}

// ValidAgentHost reports whether host is safe to use as an agent hostname
// identifier: non-empty, at most 255 bytes, no leading dot, and free of
// path-traversal characters. Used wherever a host string from an untrusted
// wire message (heartbeat, sudoers snapshot/error) or admin API request is
// turned into part of a config-store key or file path.
func ValidAgentHost(host string) bool {
	if host == "" || len(host) > 255 || host[0] == '.' {
		return false
	}
	if strings.ContainsAny(host, "/\\") || strings.Contains(host, "..") {
		return false
	}
	return true
}
