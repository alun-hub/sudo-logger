package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/godbus/dbus/v5"
)

// dbusSubsystem monitors the D-Bus system bus for polkit CheckAuthorization
// calls.  It uses BecomeMonitor to receive copies of matching messages without
// interfering with bus traffic, then emits a dbus-polkit session event for
// each completed authorization request (authorized, denied, or challenge).
//
// Requires D-Bus >= 1.9 (Fedora 23+, RHEL 8+).  Falls back gracefully if
// the daemon is unavailable or does not support BecomeMonitor.
type dbusSubsystem struct {
	conn   *dbus.Conn
	cancel context.CancelFunc
}

// pendingPolkitCall tracks an in-flight CheckAuthorization request.
// The D-Bus serial links the call to its reply.
type pendingPolkitCall struct {
	actionID string
	subject  string // human-readable: "pid:1234", "session:c2", …
	ts       time.Time
}

func (d *dbusSubsystem) start(ctx context.Context) error {
	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		return fmt.Errorf("connect system bus: %w", err)
	}

	// BecomeMonitor puts the connection into read-only monitor mode.
	// After this call the daemon routes copies of matching messages to us;
	// sending messages is no longer possible.
	rules := []string{
		"type='method_call',interface='org.freedesktop.PolicyKit1.Authority',member='CheckAuthorization'",
		"type='method_return'",
		"type='error'",
	}
	if err := conn.BusObject().Call(
		"org.freedesktop.DBus.Monitoring.BecomeMonitor",
		0, rules, uint32(0),
	).Store(); err != nil {
		conn.Close()
		return fmt.Errorf("BecomeMonitor: %w", err)
	}

	d.conn = conn
	ctx2, cancel := context.WithCancel(ctx)
	d.cancel = cancel
	go d.loop(ctx2)
	return nil
}

func (d *dbusSubsystem) stop() {
	if d.cancel != nil {
		d.cancel()
	}
	if d.conn != nil {
		d.conn.Close()
	}
}

func (d *dbusSubsystem) loop(ctx context.Context) {
	ch := make(chan *dbus.Message, 64)
	d.conn.Eavesdrop(ch)

	// pending maps a D-Bus message serial to the in-flight CheckAuthorization call.
	pending := map[uint32]*pendingPolkitCall{}

	// Periodic sweep to evict calls that never received a reply (e.g. cancelled).
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cutoff := time.Now().Add(-30 * time.Second)
			for k, v := range pending {
				if v.ts.Before(cutoff) {
					delete(pending, k)
				}
			}
		case msg, ok := <-ch:
			if !ok {
				return
			}
			switch msg.Type {
			case dbus.TypeMethodCall:
				d.handleCall(msg, pending)
			case dbus.TypeMethodReply, dbus.TypeError:
				d.handleReply(msg, pending)
			}
		}
	}
}

func (d *dbusSubsystem) handleCall(msg *dbus.Message, pending map[uint32]*pendingPolkitCall) {
	iface, _ := msg.Headers[dbus.FieldInterface].Value().(string)
	member, _ := msg.Headers[dbus.FieldMember].Value().(string)
	if iface != "org.freedesktop.PolicyKit1.Authority" || member != "CheckAuthorization" {
		return
	}
	if len(msg.Body) < 2 {
		return
	}
	actionID, _ := msg.Body[1].(string)
	if actionID == "" {
		return
	}
	pending[msg.Serial()] = &pendingPolkitCall{
		actionID: actionID,
		subject:  extractPolkitSubject(msg.Body[0]),
		ts:       time.Now(),
	}
}

func (d *dbusSubsystem) handleReply(msg *dbus.Message, pending map[uint32]*pendingPolkitCall) {
	replySerial, ok := msg.Headers[dbus.FieldReplySerial].Value().(uint32)
	if !ok {
		return
	}
	call, ok := pending[replySerial]
	if !ok {
		return
	}
	delete(pending, replySerial)

	var exitCode int32
	if msg.Type == dbus.TypeError {
		exitCode = 1
	} else {
		exitCode = parsePolkitResult(msg.Body)
	}
	d.emitEvent(call, exitCode)
}

func (d *dbusSubsystem) emitEvent(call *pendingPolkitCall, exitCode int32) {
	hostname, _ := os.Hostname()
	sess := &ebpfSession{
		id:      generateDBusSessionID(hostname, call.actionID, call.ts),
		user:    call.subject,
		host:    hostname,
		command: call.actionID,
		source:  "dbus-polkit",
		hasIO:   false,
	}
	if err := sess.connect(cfg.Server, tlsCfg, verifyKey); err != nil {
		log.Printf("dbus: polkit event lost: %v", err)
		return
	}
	log.Printf("dbus: polkit action=%q subject=%q exitCode=%d", call.actionID, call.subject, exitCode)
	sess.close(exitCode)
}

// extractPolkitSubject extracts a human-readable string from a polkit (sa{sv})
// subject struct.  Returns "unknown" on parse failure.
func extractPolkitSubject(v interface{}) string {
	parts, ok := v.([]interface{})
	if !ok || len(parts) == 0 {
		return "unknown"
	}
	kind, _ := parts[0].(string)
	var details map[string]dbus.Variant
	if len(parts) > 1 {
		details, _ = parts[1].(map[string]dbus.Variant)
	}
	switch kind {
	case "unix-process":
		if pid, ok := details["pid"]; ok {
			return fmt.Sprintf("pid:%v", pid.Value())
		}
	case "unix-session":
		if sid, ok := details["session-id"]; ok {
			return fmt.Sprintf("session:%v", sid.Value())
		}
	case "system-bus-name":
		if name, ok := details["name"]; ok {
			return fmt.Sprintf("bus:%v", name.Value())
		}
	}
	if kind != "" {
		return kind
	}
	return "unknown"
}

// parsePolkitResult parses an AuthorizationResult (bba{ss}) from a D-Bus reply.
// Returns: 0=authorized, 1=denied, 2=challenge.
func parsePolkitResult(body []interface{}) int32 {
	if len(body) == 0 {
		return 1
	}
	result, ok := body[0].([]interface{})
	if !ok || len(result) < 2 {
		return 1
	}
	isAuthorized, _ := result[0].(bool)
	isChallenge, _ := result[1].(bool)
	switch {
	case isAuthorized:
		return 0
	case isChallenge:
		return 2
	default:
		return 1
	}
}

func generateDBusSessionID(hostname, actionID string, ts time.Time) string {
	tsStr := strconv.FormatInt(ts.UnixNano(), 10)
	safe := func(s string) string {
		var b strings.Builder
		for _, c := range s {
			if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
				(c >= '0' && c <= '9') || c == '-' || c == '_' {
				b.WriteRune(c)
			} else {
				b.WriteRune('_')
			}
		}
		return b.String()
	}
	id := fmt.Sprintf("dbus.%s.%s.%s", safe(hostname), safe(actionID), tsStr)
	if len(id) > 200 {
		id = id[:200]
	}
	return id
}
