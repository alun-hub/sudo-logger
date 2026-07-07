package main

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func writeHTPasswdFile(t *testing.T, entries map[string]string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.htpasswd") // pragma: allowlist secret
	content := ""
	for user, password := range entries { // pragma: allowlist secret
		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
		if err != nil {
			t.Fatalf("bcrypt.GenerateFromPassword: %v", err)
		}
		content += user + ":" + string(hash) + "\n"
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write htpasswd file: %v", err)
	}
	return path
}

func resetHTPasswdUsers(t *testing.T) {
	t.Helper()
	htpasswdMu.Lock()
	htpasswdUsers = nil // pragma: allowlist secret
	htpasswdMu.Unlock()
	t.Cleanup(func() {
		htpasswdMu.Lock()
		htpasswdUsers = nil // pragma: allowlist secret
		htpasswdMu.Unlock()
	})
}

func TestLoadHTPasswd_ValidFile(t *testing.T) {
	resetHTPasswdUsers(t)
	path := writeHTPasswdFile(t, map[string]string{"alice": "correct-horse"})
	if err := loadHTPasswd(path); err != nil {
		t.Fatalf("loadHTPasswd: %v", err)
	}
	if !authenticateHTPasswd("alice", "correct-horse") {
		t.Error("expected authenticateHTPasswd to succeed with correct credentials")
	}
	if authenticateHTPasswd("alice", "wrong-password") {
		t.Error("expected authenticateHTPasswd to fail with wrong password")
	}
	if authenticateHTPasswd("nobody", "whatever") {
		t.Error("expected authenticateHTPasswd to fail for unknown user")
	}
}

func TestLoadHTPasswd_MissingFile(t *testing.T) {
	resetHTPasswdUsers(t)
	if err := loadHTPasswd("/nonexistent/path/does-not-exist.htpasswd"); err == nil {
		t.Error("expected error for missing htpasswd file")
	}
}

func TestLoadHTPasswd_SkipsMalformedAndNonBcryptLines(t *testing.T) {
	resetHTPasswdUsers(t)
	path := filepath.Join(t.TempDir(), "test.htpasswd")
	// "bob" uses MD5 (not supported); "no-colon" is malformed; blank/comment
	// lines must be ignored; "alice" is a valid bcrypt entry.
	aliceHash, err := bcrypt.GenerateFromPassword([]byte("s3cret"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt.GenerateFromPassword: %v", err)
	}
	content := "# comment\n\nbob:$apr1$abcd$efghijklmnop\nno-colon-here\nalice:" + string(aliceHash) + "\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write htpasswd file: %v", err)
	}
	if err := loadHTPasswd(path); err != nil {
		t.Fatalf("loadHTPasswd: %v", err)
	}
	if authenticateHTPasswd("bob", "anything") {
		t.Error("expected non-bcrypt entry to be rejected")
	}
	if !authenticateHTPasswd("alice", "s3cret") {
		t.Error("expected valid bcrypt entry to still authenticate")
	}
}

func TestLoadHTPasswd_ReloadReplacesUserSet(t *testing.T) {
	resetHTPasswdUsers(t)
	path := writeHTPasswdFile(t, map[string]string{"alice": "correct-horse"})
	if err := loadHTPasswd(path); err != nil {
		t.Fatalf("loadHTPasswd: %v", err)
	}
	if !authenticateHTPasswd("alice", "correct-horse") {
		t.Fatal("expected alice to authenticate before reload")
	}

	path2 := writeHTPasswdFile(t, map[string]string{"bob": "another-pass"})
	if err := loadHTPasswd(path2); err != nil {
		t.Fatalf("loadHTPasswd (reload): %v", err)
	}
	if authenticateHTPasswd("alice", "correct-horse") {
		t.Error("expected alice to no longer authenticate after reload replaced the user set")
	}
	if !authenticateHTPasswd("bob", "another-pass") {
		t.Error("expected bob to authenticate after reload")
	}
}
