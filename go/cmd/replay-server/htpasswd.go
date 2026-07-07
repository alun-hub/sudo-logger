// htpasswd.go — legacy HTTP Basic Auth via an htpasswd file (bcrypt hashes
// only, i.e. the format produced by `htpasswd -B`/`htpasswd -nBb`).
package main

import (
	"bufio"
	"log"
	"os"
	"strings"
	"sync"

	"golang.org/x/crypto/bcrypt"
)

var (
	htpasswdMu    sync.RWMutex
	htpasswdUsers map[string]string // username -> bcrypt hash
)

// loadHTPasswd reads and parses path, replacing the in-memory user map
// atomically on success. Called once at startup and again on SIGHUP. Lines
// that aren't a valid "user:hash" pair, or that use a non-bcrypt hash scheme,
// are skipped with a warning rather than failing the whole file — matching
// the flag's documented "bcrypt hashes only" contract.
func loadHTPasswd(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	users := make(map[string]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		i := strings.IndexByte(line, ':')
		if i < 0 {
			log.Printf("htpasswd: skipping malformed line (no ':'): %q", line)
			continue
		}
		user, hash := line[:i], line[i+1:]
		if !strings.HasPrefix(hash, "$2y$") && !strings.HasPrefix(hash, "$2a$") && !strings.HasPrefix(hash, "$2b$") {
			log.Printf("htpasswd: skipping user %q — only bcrypt hashes ($2a$/$2b$/$2y$) are supported", user)
			continue
		}
		users[user] = hash
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	htpasswdMu.Lock()
	htpasswdUsers = users // pragma: allowlist secret
	htpasswdMu.Unlock()
	log.Printf("htpasswd: loaded %d user(s) from %s", len(users), path)
	return nil
}

// isHTPasswdUser reports whether username has an entry in the loaded
// htpasswd file. Used for role resolution only — credential verification
// happens separately in authenticateHTPasswd, and always runs before this
// is consulted (basicAuthMiddleware gates the request first).
func isHTPasswdUser(username string) bool {
	htpasswdMu.RLock()
	defer htpasswdMu.RUnlock()
	_, ok := htpasswdUsers[username]
	return ok
}

// authenticateHTPasswd checks username/password against the loaded htpasswd
// file. Always runs bcrypt even for an unknown username, matching
// authenticate()'s protection against timing-based username enumeration.
func authenticateHTPasswd(username, password string) bool {
	htpasswdMu.RLock()
	hash, ok := htpasswdUsers[username]
	htpasswdMu.RUnlock()
	if !ok {
		bcrypt.CompareHashAndPassword(dummyHash, []byte(password)) //nolint:errcheck
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}
