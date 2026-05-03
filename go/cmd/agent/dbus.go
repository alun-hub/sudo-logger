package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
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
	mu     sync.Mutex
	retryQ []*pendingEvent
}

const (
	maxPendingAge = 10 * time.Minute
	maxPendingQ   = 200
	retryInterval = 30 * time.Second
)

// pendingEvent holds a failed dbus-polkit emission for later retry.
type pendingEvent struct {
	call     *pendingPolkitCall
	exitCode int32
	queued   time.Time
}

// pendingPolkitCall tracks an in-flight CheckAuthorization request.
// The D-Bus serial links the call to its reply.
type pendingPolkitCall struct {
	actionID      string
	subject       string // human-readable: "pid:1234", "session:c2", …
	user          string // filesystem-safe username for the session user field
	callerProcess string // process name (unix-process) or inferred service name (system-bus-name)
	ts            time.Time
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
	go d.retryLoop(ctx2)
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
		actionID:      actionID,
		subject:       extractPolkitSubject(msg.Body[0]),
		user:          extractPolkitUser(msg.Body[0]),
		callerProcess: extractCallerProcess(msg.Body[0], actionID),
		ts:            time.Now(),
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
	// Skip auto-authorized actions (exitCode=0): no user interaction required,
	// no password/PIN presented — background noise from KDE, NetworkManager etc.
	// Only record challenge (2 = requires auth) and denied (1 = access refused).
	if exitCode == 0 {
		return
	}
	d.emitEvent(call, exitCode)
}

func (d *dbusSubsystem) sendEvent(call *pendingPolkitCall, exitCode int32) error {
	hostname, _ := os.Hostname()
	sess := &ebpfSession{
		id:            generateDBusSessionID(hostname, call.actionID, call.ts),
		user:          call.user,
		host:          hostname,
		command:       call.actionID,
		source:        "dbus-polkit",
		hasIO:         false,
		callerProcess: call.callerProcess,
		ts:            call.ts,
	}
	if err := sess.connect(cfg.Server, tlsCfg, verifyKey); err != nil {
		return err
	}
	log.Printf("dbus: polkit action=%q caller=%q user=%q exitCode=%d", call.actionID, call.callerProcess, call.user, exitCode)
	sess.close(exitCode)
	return nil
}

func (d *dbusSubsystem) emitEvent(call *pendingPolkitCall, exitCode int32) {
	if err := d.sendEvent(call, exitCode); err != nil {
		d.mu.Lock()
		if len(d.retryQ) < maxPendingQ {
			d.retryQ = append(d.retryQ, &pendingEvent{call: call, exitCode: exitCode, queued: time.Now()})
			log.Printf("dbus: polkit event queued for retry (%d in queue): %v", len(d.retryQ), err)
		} else {
			log.Printf("dbus: polkit event dropped (retry queue full): action=%q user=%q", call.actionID, call.user)
		}
		d.mu.Unlock()
	}
}

func (d *dbusSubsystem) retryLoop(ctx context.Context) {
	ticker := time.NewTicker(retryInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.drainRetryQueue()
		}
	}
}

func (d *dbusSubsystem) drainRetryQueue() {
	d.mu.Lock()
	if len(d.retryQ) == 0 {
		d.mu.Unlock()
		return
	}
	queue := d.retryQ
	d.retryQ = nil
	d.mu.Unlock()

	cutoff := time.Now().Add(-maxPendingAge)
	var remaining []*pendingEvent
	serverDown := false

	for i, e := range queue {
		if e.queued.Before(cutoff) {
			log.Printf("dbus: dropping expired polkit event: action=%q user=%q age=%v",
				e.call.actionID, e.call.user, time.Since(e.queued).Round(time.Second))
			continue
		}
		if serverDown {
			remaining = append(remaining, queue[i:]...)
			break
		}
		if err := d.sendEvent(e.call, e.exitCode); err != nil {
			log.Printf("dbus: retry failed (%d events remain queued): %v", len(queue)-i, err)
			serverDown = true
			remaining = append(remaining, queue[i:]...)
			break
		}
	}

	if len(remaining) > 0 {
		d.mu.Lock()
		// Prepend unsent events before any newly queued ones.
		d.retryQ = append(remaining, d.retryQ...)
		if len(d.retryQ) > maxPendingQ {
			dropped := len(d.retryQ) - maxPendingQ
			log.Printf("dbus: retry queue overflow, dropping %d oldest events", dropped)
			d.retryQ = d.retryQ[dropped:]
		}
		d.mu.Unlock()
	}
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

// extractPolkitUser returns a filesystem-safe username for the polkit subject,
// suitable for the session user field (must pass server's sanitizeName check).
// For unix-process subjects it looks up the invoking UID from /proc; for all
// other subject kinds it falls back to "polkit".
func extractPolkitUser(v interface{}) string {
	parts, ok := v.([]interface{})
	if !ok || len(parts) == 0 {
		return "polkit"
	}
	kind, _ := parts[0].(string)
	if kind == "unix-process" && len(parts) > 1 {
		details, _ := parts[1].(map[string]dbus.Variant)
		if pidV, ok := details["pid"]; ok {
			pidStr := fmt.Sprintf("%v", pidV.Value())
			pid64, err := strconv.ParseUint(pidStr, 10, 32)
			if err == nil {
				uid := uidForPID(uint32(pid64))
				if uid != ^uint32(0) {
					if name, lerr := lookupUsername(uid); lerr == nil {
						return name
					}
				}
			}
		}
	}
	return "polkit"
}

// uidForPID reads the real UID of process pid from /proc/<pid>/status.
// Returns ^uint32(0) on any error.
func uidForPID(pid uint32) uint32 {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return ^uint32(0)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "Uid:") {
			var uid uint32
			fmt.Sscanf(strings.TrimPrefix(line, "Uid:"), "%d", &uid)
			return uid
		}
	}
	return ^uint32(0)
}

// extractCallerProcess returns the calling process name for unix-process subjects
// (read from /proc/<pid>/comm) or infers the service name from the action ID prefix
// for system-bus-name subjects and fallbacks.
func extractCallerProcess(v interface{}, actionID string) string {
	parts, ok := v.([]interface{})
	if ok && len(parts) > 0 {
		kind, _ := parts[0].(string)
		if kind == "unix-process" && len(parts) > 1 {
			details, _ := parts[1].(map[string]dbus.Variant)
			if pidV, ok := details["pid"]; ok {
				pidStr := fmt.Sprintf("%v", pidV.Value())
				if pid64, err := strconv.ParseUint(pidStr, 10, 32); err == nil {
					if comm, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid64)); err == nil {
						if name := strings.TrimSpace(string(comm)); name != "" {
							return name
						}
					}
				}
			}
		}
	}
	return inferServiceFromAction(actionID)
}

// inferServiceFromAction maps well-known polkit action ID prefixes to their
// originating system service name.
func inferServiceFromAction(actionID string) string {
	prefixes := [...]struct{ prefix, service string }{
		{"org.fedoraproject.FirewallD1", "firewalld"},
		{"org.freedesktop.NetworkManager", "NetworkManager"},
		{"org.freedesktop.systemd1", "systemd"},
		{"org.freedesktop.packagekit", "PackageKit"},
		{"org.freedesktop.UDisks2", "udisksd"},
		{"org.freedesktop.login1", "systemd-logind"},
		{"org.freedesktop.fwupd", "fwupd"},
		{"org.freedesktop.timedate1", "systemd-timedated"},
		{"org.freedesktop.hostname1", "systemd-hostnamed"},
		{"org.freedesktop.policykit.exec", "pkexec"},
		{"org.debian.apt", "apt"},
		{"com.ubuntu.pkexec", "pkexec"},
	}
	for _, p := range prefixes {
		if strings.HasPrefix(actionID, p.prefix) {
			return p.service
		}
	}
	return ""
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
