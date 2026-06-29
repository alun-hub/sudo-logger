package main

import (
	"context"
	"log"
	"strings"
)

// handleAgentHeartbeat processes a MsgHeartbeatAgent message.
func (srv *server) handleAgentHeartbeat(remote string, payload []byte) {
	host := string(payload)
	if host == "" || len(host) > 255 || host[0] == '.' ||
		strings.ContainsAny(host, "/\\") || strings.Contains(host, "..") {
		log.Printf("SECURITY: MsgHeartbeatAgent invalid host %q from %s — dropping", host, remote)
		return
	}
	if err := srv.sessionStore.SaveHeartbeat(context.Background(), host); err != nil {
		log.Printf("save heartbeat host=%s: %v", host, err)
	}
}
