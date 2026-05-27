package main

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"time"

	"sudo-logger/internal/protocol"
)

// startSandboxPoller launches a background goroutine that fetches "sandbox.yaml"
// from the log server every 60 seconds and reloads the sandbox if the content
// has changed. This allows admins to manage the sandbox config centrally via
// the replay-server UI without restarting the agent.
//
// If the server has no sandbox.yaml stored, the response is empty and the
// poller is a no-op. Errors are logged but never fatal.
func startSandboxPoller() {
	go func() {
		var lastHash [32]byte
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		// Poll immediately on startup, then every 60 s.
		for {
			content, err := fetchConfigFromServer(cfg.Server, "sandbox.yaml")
			if err != nil {
				debugLog("sandbox poller: %v", err)
			} else if content != "" {
				h := sha256.Sum256([]byte(content))
				if h != lastHash {
					if err := reloadSandboxFromContent(content); err != nil {
						log.Printf("sandbox poller: reload: %v", err)
					} else {
						lastHash = h
					}
				}
			}
			<-ticker.C
		}
	}()
}

// fetchConfigFromServer opens a fresh mTLS connection to server, sends
// MsgFetchConfig with the given key, reads the MsgConfigData response, and
// closes the connection. Returns ("", nil) when the server has no entry for key.
func fetchConfigFromServer(server, key string) (string, error) {
	tcpAddr, err := net.ResolveTCPAddr("tcp", server)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", server, err)
	}
	rawTCP, err := net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		return "", fmt.Errorf("dial %s: %w", server, err)
	}
	defer rawTCP.Close()

	conn := tls.Client(rawTCP, tlsClientFor(tlsCfg, server))
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	defer conn.Close()

	if err := conn.Handshake(); err != nil {
		return "", fmt.Errorf("TLS handshake: %w", err)
	}

	w := bufio.NewWriter(conn)
	if err := protocol.WriteMessage(w, protocol.MsgFetchConfig, []byte(key)); err != nil {
		return "", fmt.Errorf("send MsgFetchConfig: %w", err)
	}

	r := bufio.NewReader(conn)
	msgType, plen, err := protocol.ReadHeader(r)
	if err != nil {
		return "", fmt.Errorf("read response header: %w", err)
	}
	if msgType != protocol.MsgConfigData {
		return "", fmt.Errorf("unexpected response type 0x%02x", msgType)
	}
	payload, err := protocol.ReadPayload(r, plen)
	if err != nil {
		return "", fmt.Errorf("read response payload: %w", err)
	}
	return string(payload), nil
}
