package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"

	"sudo-logger/internal/protocol"
)

const sudoersManagedPath = "/etc/sudoers.d/sudo-logger-managed"

// collectSudoers reads /etc/sudoers and all files under /etc/sudoers.d/,
// concatenates them with section headers, and returns a SudoersSnapshot.
func collectSudoers(host string) (*protocol.SudoersSnapshot, error) {
	var sb strings.Builder
	var files []protocol.SudoersFile

	addFile := func(path string) {
		data, err := os.ReadFile(path)
		if err != nil {
			debugLog("sudoers: read %s: %v", path, err)
			return
		}
		h := sha256.Sum256(data)
		hashStr := hex.EncodeToString(h[:])
		fmt.Fprintf(&sb, "# --- %s ---\n%s\n", path, data)
		files = append(files, protocol.SudoersFile{
			Path:    path,
			Content: string(data),
			SHA256:  hashStr,
		})
	}

	addFile("/etc/sudoers")

	entries, err := os.ReadDir("/etc/sudoers.d")
	if err != nil && !os.IsNotExist(err) {
		debugLog("sudoers: readdir /etc/sudoers.d: %v", err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		// Skip editor backups and dpkg temp files (same as visudo).
		if strings.HasSuffix(name, "~") || strings.Contains(name, ".") {
			continue
		}
		addFile(filepath.Join("/etc/sudoers.d", name))
	}

	content := sb.String()
	h := sha256.Sum256([]byte(content))
	return &protocol.SudoersSnapshot{
		Host:    host,
		Content: content,
		SHA256:  hex.EncodeToString(h[:]),
		Files:   files,
	}, nil
}

// sendSudoersSnapshot marshals snap and sends it to the log server with up to
// 5 attempts using exponential backoff (same pattern as sendDivergenceAlert).
func sendSudoersSnapshot(snap *protocol.SudoersSnapshot) {
	payload, err := json.Marshal(snap)
	if err != nil {
		log.Printf("sudoers: marshal snapshot: %v", err)
		return
	}

	const maxAttempts = 5
	delay := 5 * time.Second
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if err := trySendSudoersSnapshot(payload); err == nil {
			debugLog("sudoers: snapshot sent for host=%s sha256=%s", snap.Host, snap.SHA256[:8])
			return
		} else {
			log.Printf("sudoers: send snapshot attempt %d/%d: %v", attempt, maxAttempts, err)
		}
		if attempt < maxAttempts {
			time.Sleep(delay)
			delay *= 2
			if delay > 60*time.Second {
				delay = 60 * time.Second
			}
		}
	}
	log.Printf("sudoers: all %d send attempts failed — snapshot lost", maxAttempts)
}

func trySendSudoersSnapshot(payload []byte) error {
	conn, err := tls.Dial("tcp", cfg.Server, tlsClientFor(tlsCfg, cfg.Server))
	if err != nil {
		return fmt.Errorf("dial %s: %w", cfg.Server, err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	w := bufio.NewWriter(conn)
	if err := protocol.WriteMessage(w, protocol.MsgSudoersSnapshot, payload); err != nil {
		return fmt.Errorf("send: %w", err)
	}
	return w.Flush()
}

// startSudoersWatcher sends an initial snapshot and then watches /etc/sudoers
// and /etc/sudoers.d/ for changes, sending a new snapshot whenever the content
// changes. Exits when ctx is cancelled.
func startSudoersWatcher(ctx context.Context, host string) {
	snap, err := collectSudoers(host)
	if err != nil {
		log.Printf("sudoers: initial collect: %v", err)
	} else {
		go sendSudoersSnapshot(snap)
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Printf("sudoers: inotify unavailable: %v — snapshot-only mode (no live updates)", err)
		<-ctx.Done()
		return
	}
	defer watcher.Close()

	for _, p := range []string{"/etc/sudoers", "/etc/sudoers.d"} {
		if err := watcher.Add(p); err != nil {
			debugLog("sudoers: watch %s: %v", p, err)
		}
	}

	var lastHash string
	if snap != nil {
		lastHash = snap.SHA256
	}

	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			debugLog("sudoers: fs event %s on %s", event.Op, event.Name)
			newSnap, err := collectSudoers(host)
			if err != nil {
				log.Printf("sudoers: collect after event: %v", err)
				continue
			}
			if newSnap.SHA256 == lastHash {
				continue // content unchanged
			}
			lastHash = newSnap.SHA256
			go sendSudoersSnapshot(newSnap)
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			log.Printf("sudoers: watcher error: %v", err)
		}
	}
}

// startSudoersPoller launches a background goroutine that fetches the desired
// sudoers config from the log server every 60 seconds and applies it to
// sudoersManagedPath if the content differs (server-wins).
func startSudoersPoller(host string) {
	go func() {
		var lastApplied string
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()

		// Poll immediately on startup, then every 60 s.
		for {
			content, err := fetchConfigFromServer(cfg.Server, "sudoers/"+host)
			if err != nil {
				debugLog("sudoers poller: fetch host config: %v", err)
			}
			if content == "" {
				// No host-specific config — fall back to global default.
				content, err = fetchConfigFromServer(cfg.Server, "sudoers/_default")
				if err != nil {
					debugLog("sudoers poller: fetch default config: %v", err)
				}
			}
			if content != "" && content != lastApplied {
				if err := applySudoers(content); err != nil {
					log.Printf("sudoers poller: apply: %v", err)
					sendSudoersError(host, err.Error(), content)
				} else {
					lastApplied = content
					log.Printf("sudoers: applied managed config to %s", sudoersManagedPath)
				}
			}

			<-ticker.C
		}
	}()
}

func sendSudoersError(host, errMsg, content string) {
	h := sha256.Sum256([]byte(content))
	errPayload, _ := json.Marshal(protocol.SudoersError{
		Host:   host,
		Error:  errMsg,
		SHA256: hex.EncodeToString(h[:]),
		Ts:     time.Now().Unix(),
	})
	// Just a one-shot attempt; if it fails we'll try again next poll if it still fails.
	go func() {
		_ = trySendMessage(protocol.MsgSudoersError, errPayload)
	}()
}

func trySendMessage(msgType uint8, payload []byte) error {
	tcpAddr, err := net.ResolveTCPAddr("tcp", cfg.Server)
	if err != nil {
		return err
	}
	rawTCP, err := net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		return err
	}
	defer rawTCP.Close()

	conn := tls.Client(rawTCP, tlsClientFor(tlsCfg, cfg.Server))
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	defer conn.Close()

	if err := conn.Handshake(); err != nil {
		return err
	}
	w := bufio.NewWriter(conn)
	return protocol.WriteMessage(w, msgType, payload)
}

// applySudoers validates content with visudo -c, then atomically writes it to
// sudoersManagedPath. Returns an error without touching the target if validation
// fails, ensuring no broken sudoers file is ever deployed.
func applySudoers(content string) error {
	tmpPath := fmt.Sprintf("%s.tmp.%d", sudoersManagedPath, os.Getpid())

	if err := os.MkdirAll(filepath.Dir(sudoersManagedPath), 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(sudoersManagedPath), err)
	}
	if err := os.WriteFile(tmpPath, []byte(content), 0o440); err != nil {
		return fmt.Errorf("write tmp: %w", err)
	}

	// Validate with visudo before committing.
	out, err := exec.Command("visudo", "-c", "-f", tmpPath).CombinedOutput()
	if err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("visudo -c failed: %v — %s", err, strings.TrimSpace(string(out)))
	}

	// Atomic rename — same directory guarantees same filesystem.
	if err := os.Rename(tmpPath, sudoersManagedPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("rename to %s: %w", sudoersManagedPath, err)
	}
	return nil
}
