package main

import (
	"context"
	"log"

	"sudo-logger/internal/util"
)

// handleAgentHeartbeat processes a MsgHeartbeatAgent message.
func (srv *server) handleAgentHeartbeat(remote string, payload []byte) {
	host := string(payload)
	if !util.ValidAgentHost(host) {
		log.Printf("SECURITY: MsgHeartbeatAgent invalid host %q from %s — dropping", host, remote)
		return
	}
	if err := srv.sessionStore.SaveHeartbeat(context.Background(), host); err != nil {
		log.Printf("save heartbeat host=%s: %v", host, err)
	}
}
