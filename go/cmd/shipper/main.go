// sudo-shipper: local daemon that bridges the sudo C plugin (Unix socket)
// to the remote log server (TLS).
//
// One goroutine per sudo session. Maintains the last received ACK timestamp
// and responds to ACK_QUERY messages from the plugin instantly, without
// waiting for a network round-trip.
//
// Run as a systemd service (see sudo-shipper.service).
package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"sudo-logger/internal/iolog"
	"sudo-logger/internal/protocol"
)

// freezeMsgTTY is the same banner the plugin would write but sent directly
// to the TTY device by the shipper so it appears even when sudo is SIGTSTP'd.
const freezeMsgTTY = "\r\n\033[41;97;1m[ SUDO-LOGGER: log server unreachable — input frozen ]\033[0m\r\n" +
	"\033[33mWaiting for log server to come back...\033[0m\r\n"

// validTTYPath restricts tty_path to known safe device paths.
var validTTYPath = regexp.MustCompile(`^/dev/(pts/\d{1,6}|tty[a-zA-Z0-9]{0,10})$`)

// resolveTTYPath resolves /dev/tty to the concrete PTY path.
// /dev/tty is process-relative; a daemon with no controlling terminal gets
// ENXIO when opening it.  We find the real device by reading the symlinks
// of the sudo process's stdio fds in /proc.
func resolveTTYPath(ttyPath string, sudoPID int) string {
	if ttyPath != "/dev/tty" {
		return ttyPath
	}
	for _, fd := range []int{0, 1, 2} {
		link, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", sudoPID, fd))
		if err != nil {
			continue
		}
		if validTTYPath.MatchString(link) {
			return link
		}
	}
	return ttyPath
}

// writeTTYFreezeMsg writes the freeze banner directly to the session's
// controlling terminal.  Called in a goroutine at markDead() time so the
// message appears immediately even when sudo is stopped by job control.
func writeTTYFreezeMsg(ttyPath string) {
	if ttyPath == "" || !validTTYPath.MatchString(ttyPath) {
		return
	}
	f, err := os.OpenFile(ttyPath, os.O_WRONLY, 0)
	if err != nil {
		log.Printf("freeze banner: open %s: %v", ttyPath, err)
		return
	}
	defer f.Close()
	_, _ = f.WriteString(freezeMsgTTY)
}

// writeTTYIdleWarnMsg warns the user that the session will close soon due to
// inactivity.  Any keypress resets the idle timer and cancels the countdown.
func writeTTYIdleWarnMsg(ttyPath string, remaining time.Duration) {
	if ttyPath == "" || !validTTYPath.MatchString(ttyPath) {
		log.Printf("idle warn: skipping tty write (path %q not valid)", ttyPath)
		return
	}
	f, err := os.OpenFile(ttyPath, os.O_WRONLY, 0)
	if err != nil {
		log.Printf("idle warn: open %s: %v", ttyPath, err)
		return
	}
	defer f.Close()
	msg := fmt.Sprintf(
		"\r\n\033[33;1m[ SUDO-LOGGER: session will close in %v due to inactivity — press any key to continue ]\033[0m\r\n",
		remaining.Round(time.Second))
	_, _ = f.WriteString(msg)
}

// writeTTYIdleMsg writes an idle-timeout banner to the session's controlling
// terminal so the user sees why the session is being terminated.
func writeTTYIdleMsg(ttyPath string, timeout time.Duration) {
	if ttyPath == "" || !validTTYPath.MatchString(ttyPath) {
		return
	}
	f, err := os.OpenFile(ttyPath, os.O_WRONLY, 0)
	if err != nil {
		log.Printf("idle banner: open %s: %v", ttyPath, err)
		return
	}
	defer f.Close()
	msg := fmt.Sprintf("\r\n\033[33;1m[ SUDO-LOGGER: session terminated after %v of inactivity ]\033[0m\r\n",
		timeout.Round(time.Second))
	_, _ = f.WriteString(msg)
}

var (
	flagConfig = flag.String("config", "/etc/sudo-logger/shipper.conf", "Path to configuration file")
)

var cfg shipperConfig

// debugLog is a no-op by default; replaced with log.Printf when -debug is set.
var debugLog = func(format string, args ...any) {}

var (
	verifyKey ed25519.PublicKey
	tlsCfg    *tls.Config
)

// activeCgs tracks all live session cgroups so they can be cleaned up on
// shutdown.  Without this, a SIGTERM during e.g. "sudo rpm -Uvh …" (which
// restarts the shipper via a systemd trigger) would leave the session cgroup
// frozen, causing rpm's scriptlet to hang.
var (
	activeCgsMu sync.Mutex
	activeCgs   []*cgroupSession
)

func registerCg(cg *cgroupSession) {
	if cg == nil {
		return
	}
	activeCgsMu.Lock()
	activeCgs = append(activeCgs, cg)
	activeCgsMu.Unlock()
}

func unregisterCg(cg *cgroupSession) {
	if cg == nil {
		return
	}
	activeCgsMu.Lock()
	for i, c := range activeCgs {
		if c == cg {
			activeCgs = append(activeCgs[:i], activeCgs[i+1:]...)
			break
		}
	}
	activeCgsMu.Unlock()
}

// cleanupAllCgs unfreezes and removes every active session cgroup.
// Called on SIGTERM/SIGINT so that processes in frozen cgroups can continue.
func cleanupAllCgs() {
	activeCgsMu.Lock()
	cgs := make([]*cgroupSession, len(activeCgs))
	copy(cgs, activeCgs)
	activeCgs = nil
	activeCgsMu.Unlock()
	for _, cg := range cgs {
		cg.stopTracking()
		cg.remove()
	}
}

func main() {
	flag.Parse()

	var err error
	cfg, err = loadConfig(*flagConfig)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	if cfg.Debug {
		debugLog = log.Printf
	}

	verifyKey, err = loadEd25519PubKey(cfg.VerifyKey)
	if err != nil {
		log.Fatalf("load verify key: %v", err)
	}

	tlsCfg, err = buildTLSConfig()
	if err != nil {
		log.Fatalf("build TLS config: %v", err)
	}

	// Remove stale socket from previous run
	if err := os.Remove(cfg.Socket); err != nil && !os.IsNotExist(err) {
		log.Printf("remove stale socket: %v", err)
	}

	if err := os.MkdirAll("/run/sudo-logger", 0750); err != nil {
		log.Fatalf("mkdir /run/sudo-logger: %v", err)
	}

	ln, err := net.Listen("unix", cfg.Socket)
	if err != nil {
		log.Fatalf("listen unix %s: %v", cfg.Socket, err)
	}
	defer ln.Close()

	// Only root (sudo process) may connect
	if err := os.Chmod(cfg.Socket, 0600); err != nil {
		log.Fatalf("chmod socket: %v", err)
	}

	// Unfreeze all session cgroups on graceful shutdown so processes in
	// frozen cgroups (e.g. rpm scriptlets) are not left stuck.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sigCh
		log.Printf("sudo-shipper shutting down — cleaning up session cgroups")
		cleanupAllCgs()
		os.Exit(0)
	}()

	log.Printf("sudo-shipper listening on %s, forwarding to %s", cfg.Socket, cfg.Server)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		if !isSudoConn(conn) {
			log.Printf("rejected non-root connection on plugin socket")
			conn.Close()
			continue
		}
		go handlePluginConn(conn)
	}
}

// handlePluginConn manages one sudo session end-to-end.
func handlePluginConn(pluginConn net.Conn) {
	defer pluginConn.Close()

	// done is closed when the session ends (normal or error).
	// All per-session watchdog goroutines select on done so they stop
	// immediately and never fire after the session has finished.
	done := make(chan struct{})
	var closeOnce sync.Once
	closeDone := func() { closeOnce.Do(func() { close(done) }) }
	defer closeDone()

	type outMsg struct {
		msgType uint8
		payload []byte
	}
	prioQueue := make(chan outMsg, 100)  // heartbeats, input
	bulkQueue := make(chan outMsg, 1000) // tty output

	pr := bufio.NewReader(pluginConn)
	pw := bufio.NewWriter(pluginConn)

	// ── Step 1: read SESSION_START before connecting to the server ────────
	//
	// We need the sudo PID to create the session cgroup BEFORE sudo forks
	// the child.  Fork inherits cgroup membership, so the child and all its
	// descendants — including GUI programs that later detach and re-parent
	// to init/systemd — remain in the cgroup and can be frozen atomically.
	//
	// 30-second deadline prevents a rogue root connection from leaking this
	// goroutine indefinitely if the client connects but never sends data.
	pluginConn.SetReadDeadline(time.Now().Add(30 * time.Second))
	msgType, plen, err := protocol.ReadHeader(pr)
	pluginConn.SetReadDeadline(time.Time{})
	if err != nil {
		log.Printf("read first message: %v", err)
		return
	}
	if msgType != protocol.MsgSessionStart {
		log.Printf("expected SESSION_START, got 0x%02x — dropping", msgType)
		return
	}
	startPayload, err := protocol.ReadPayload(pr, plen)
	if err != nil {
		log.Printf("read SESSION_START payload: %v", err)
		return
	}
	start, err := protocol.ParseSessionStart(startPayload)
	if err != nil {
		log.Printf("parse SESSION_START: %v", err)
		return
	}

	// ── Step 2: create session cgroup, move sudo into it ──────────────────
	//
	// The defer checks for lingering processes on every exit path (normal
	// SESSION_END, TLS error, read error, etc.).  If the cgroup still has
	// processes, or if any processes escaped the cgroup but are still running
	// (e.g. GUI programs moved by GNOME/systemd to an app-*.scope cgroup),
	// we hand off to a linger goroutine instead of removing immediately.
	cg := newCgroupSession(start.SessionID, start.Pid)
	registerCg(cg)
	defer func() {
		unregisterCg(cg)
		if cg.hasPids() || cg.hasEscapedRunning() {
			go lingerCgroup(cg, cfg.Server, tlsCfg)
		} else {
			cg.stopTracking()
			cg.remove()
		}
	}()

	// ── Step 3: per-session ACK tracking ──────────────────────────────────
	const ackLagLimit = int64(5 * time.Second)

	// guiFrames receives JPEG frames from the Wayland proxy for GUI sessions.
	// Populated in the MsgServerReady case below; consumed after forward() is declared.
	var guiFrames <-chan []byte
	var killProxy func()
	redactor := iolog.NewRedactor(cfg.MaskPatterns)
	defer func() {
		if killProxy != nil {
			killProxy()
		}
	}()

	var (
		sessionAckMu    sync.Mutex
		sessionAckSeq   uint64
		serverConnAlive bool
		// ackDebtStartNs measures how long chunks have been waiting for an
		// ACK.  Reset on every incoming ACK.  Independent of idle time so
		// idle sessions never trigger a false freeze.
		ackDebtStartNs int64
	)

	// frozenSince tracks when the session first became frozen (server
	// unreachable).  Zero means not currently frozen.  Protected by
	// sessionAckMu so it stays in sync with serverConnAlive transitions.
	var frozenSince time.Time

	updateAck := func(ts int64, seq uint64) {
		sessionAckMu.Lock()
		sessionAckSeq = seq
		ackDebtStartNs = 0
		sessionAckMu.Unlock()
		// Do NOT unfreeze or reset serverConnAlive/frozenSince here.
		// A delayed ACK (TCP retransmit of a packet sent before the server
		// went down) must not flip the session back to alive; that would
		// cause a spurious cgroup unfreeze, reset was_frozen in the plugin
		// monitor, and produce a duplicate freeze banner.  markAlive()
		// (called by the heartbeat goroutine after 2 consecutive windows)
		// is the sole authority for declaring the session alive again.
	}

	readAck := func() (int64, uint64) {
		sessionAckMu.Lock()
		defer sessionAckMu.Unlock()
		if !serverConnAlive {
			return 0, sessionAckSeq
		}
		if ackDebtStartNs > 0 && time.Now().UnixNano()-ackDebtStartNs > ackLagLimit {
			return 0, sessionAckSeq
		}
		return time.Now().UnixNano(), sessionAckSeq
	}

	// ── Step 4: connect to remote log server ──────────────────────────────
	tcpAddr, err := net.ResolveTCPAddr("tcp", cfg.Server)
	if err != nil {
		log.Printf("resolve server addr: %v", err)
		protocol.WriteMessage(pw, protocol.MsgSessionError, []byte(err.Error()))
		return
	}
	rawTCP, err := net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		log.Printf("dial server: %v", err)
		protocol.WriteMessage(pw, protocol.MsgSessionError, []byte(err.Error()))
		return
	}
	// Aggressive TCP keepalives: detect network loss in ~4 seconds.
	rawTCP.SetKeepAlive(true)
	rawTCP.SetKeepAlivePeriod(1 * time.Second)
	if sc, scErr := rawTCP.SyscallConn(); scErr == nil {
		sc.Control(func(fd uintptr) {
			syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_KEEPINTVL, 1)
			syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_KEEPCNT, 1)
		})
	}
	tlsClientCfg := tlsCfg.Clone()
	if tlsClientCfg.ServerName == "" {
		tlsClientCfg.ServerName = tcpAddr.IP.String()
		if host, _, splitErr := net.SplitHostPort(cfg.Server); splitErr == nil {
			tlsClientCfg.ServerName = host
		}
	}
	serverConn := tls.Client(rawTCP, tlsClientCfg)
	if err := serverConn.Handshake(); err != nil {
		log.Printf("tls handshake: %v", err)
		rawTCP.Close()
		protocol.WriteMessage(pw, protocol.MsgSessionError, []byte(err.Error()))
		return
	}

	// Resolve /dev/tty to the concrete PTY path; the shipper is a daemon
	// with no controlling terminal and cannot open the process-relative alias.
	ttyPath := resolveTTYPath(start.TtyPath, start.Pid)

	markDead := func() {
		sessionAckMu.Lock()
		firstFreeze := serverConnAlive && frozenSince.IsZero()
		if serverConnAlive {
			frozenSince = time.Now() // record when freeze began
		}
		serverConnAlive = false
		ackDebtStartNs = 0
		sessionAckMu.Unlock()
		cg.freeze() // nil-safe; freezes all session processes via cgroup
		// On first freeze, notify the server immediately so it can mark the
		// session as a network outage rather than a shipper kill, while the
		// server is likely still reachable (~800 ms after network loss).
		if firstFreeze {
			// Write freeze banner directly to the TTY so it appears immediately
			// even when sudo is stopped by job control (SIGTSTP propagation).
			go writeTTYFreezeMsg(ttyPath)
			go reportSessionFreezing(cfg.Server, tlsCfg, start.SessionID)
		}
	}

	markAlive := func() {
		sessionAckMu.Lock()
		wasAlive := serverConnAlive
		serverConnAlive = true
		ackDebtStartNs = 0 // heartbeat proves server is alive; reset ACK debt
		sessionAckMu.Unlock()
		if !wasAlive {
			cg.unfreeze()
		}
	}

	// resetFrozenStatus clears the freeze timestamp so that the next network
	// loss (e.g. an hour later) is treated as a fresh outage with a banner.
	// Called only after the connection has been stable for >10 seconds.
	resetFrozenStatus := func() {
		sessionAckMu.Lock()
		frozenSince = time.Time{}
		sessionAckMu.Unlock()
	}

	// pluginWriteMu serialises writes to pw (plugin connection) so that the
	// watchdog goroutine can send MsgFreezeTimeout without racing the main
	// loop's ACK_RESPONSE writes.
	var pluginWriteMu sync.Mutex

	// ── Freeze-timeout watchdog ───────────────────────────────────────────
	// If the session remains frozen (server unreachable) for longer than
	// -freeze-timeout, unfreeze the cgroup and close the plugin connection so
	// the plugin kills sudo cleanly instead of hanging forever.
	// Disabled when -freeze-timeout=0.
	if cfg.FreezeTimeout > 0 {
		go func() {
			ticker := time.NewTicker(10 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-done:
					return
				case <-ticker.C:
				}

				sessionAckMu.Lock()
				since := frozenSince
				sessionAckMu.Unlock()

				if since.IsZero() {
					continue // not frozen
				}
				if time.Since(since) < cfg.FreezeTimeout {
					continue // frozen but within allowed window
				}

				log.Printf("[%s] server unreachable for >%v — terminating frozen session",
					start.SessionID, cfg.FreezeTimeout)
				cg.unfreeze() // let signals reach bash before sudo is killed
				// Notify the plugin with a specific message so it can show a
				// human-readable banner instead of the generic "shipper lost".
				pluginWriteMu.Lock()
				_ = protocol.WriteMessage(pw, protocol.MsgFreezeTimeout, nil)
				pluginWriteMu.Unlock()
				// Give the plugin one monitor-thread cycle (150 ms) to read the
				// message before the socket is closed.
				time.Sleep(200 * time.Millisecond)
				pluginConn.Close()
				// Tell the server why this session ended so the replay UI can
				// distinguish a freeze-timeout from a shipper kill.
				go reportSessionAbandon(cfg.Server, tlsCfg, start.SessionID)
				return
			}
		}()
	}

	// ── Idle-timeout watchdog ─────────────────────────────────────────────
	// Terminates the session with SIGHUP if no user input (stdin/ttyin) has
	// arrived for longer than idle_timeout.  Disabled when idle_timeout=0.
	// lastInputNs holds the UnixNano timestamp of the most recent input chunk;
	// initialised to now so a freshly started session never immediately fires.
	var lastInputNs atomic.Int64
	lastInputNs.Store(time.Now().UnixNano())
	if cfg.IdleTimeout > 0 {
		// Warn this long before closing; capped at half the timeout so short
		// timeouts still get a visible warning.
		warnBefore := 60 * time.Second
		if warnBefore > cfg.IdleTimeout/2 {
			warnBefore = cfg.IdleTimeout / 2
		}
		go func() {
			ticker := time.NewTicker(10 * time.Second)
			defer ticker.Stop()
			warned := false
			for {
				select {
				case <-done:
					return
				case <-ticker.C:
				}

				since := time.Since(time.Unix(0, lastInputNs.Load()))

				if since >= cfg.IdleTimeout {
					log.Printf("[%s] no input for %v — terminating idle session (pid %d)",
						start.SessionID, since.Round(time.Second), start.Pid)
					go writeTTYIdleMsg(ttyPath, cfg.IdleTimeout)
					time.Sleep(200 * time.Millisecond)
					syscall.Kill(start.Pid, syscall.SIGHUP)
					time.Sleep(1 * time.Second)
					pluginConn.Close()
					return
				}

				if !warned && since >= cfg.IdleTimeout-warnBefore {
					remaining := cfg.IdleTimeout - since
					log.Printf("[%s] idle for %v — warning user (%v remaining, tty=%s)",
						start.SessionID, since.Round(time.Second), remaining.Round(time.Second), ttyPath)
					writeTTYIdleWarnMsg(ttyPath, remaining)
					warned = true
				} else if warned && since < cfg.IdleTimeout-warnBefore {
					// User pressed a key — reset warning so it fires again if
					// the session goes idle once more.
					warned = false
				}
			}
		}()
	}

	// serverWriteMu serialises writes to serverBuf from the main loop and
	// the heartbeat goroutine so that frames are not interleaved.
	var serverWriteMu sync.Mutex

	// lastServerMsg tracks when we last received any message from the server.
	// Updated on MsgAck and MsgHeartbeatAck.  Used by the heartbeat goroutine
	// to detect a silent server-side or network failure.
	var lastServerMsgMu sync.Mutex
	lastServerMsg := time.Now()
	touchServerMsg := func() {
		lastServerMsgMu.Lock()
		lastServerMsg = time.Now()
		lastServerMsgMu.Unlock()
	}

	sessionAckMu.Lock()
	serverConnAlive = true
	sessionAckMu.Unlock()

	// ── Step 5: forward SESSION_START to server, then unblock sudo ────────
	//
	// SESSION_READY is sent only after the server confirms the session is
	// accepted (MsgServerReady) so that block-policy denials reach the plugin
	// before sudo forks the child process.
	serverBuf := bufio.NewWriterSize(serverConn, 32*1024)

	// Redact the command metadata before sending to server.
	start.Command = redactor.RedactString(start.Command)
	start.ResolvedCommand = redactor.RedactString(start.ResolvedCommand)
	startPayload, _ = json.Marshal(start)

	log.Printf("[%s] start user=%s host=%s pid=%d cmd=%s cgroup=%v wayland=%q xdg=%q tty=%s",
		start.SessionID, start.User, start.Host, start.Pid,
		truncate(start.Command, 60), cg != nil,
		start.WaylandDisplay, start.XdgRuntimeDir, ttyPath)
	if err := protocol.WriteMessage(serverBuf, protocol.MsgSessionStart, startPayload); err != nil {
		log.Printf("[%s] forward SESSION_START: %v", start.SessionID, err)
		markDead()
		protocol.WriteMessage(pw, protocol.MsgSessionError, []byte(err.Error()))
		return
	}

	// ── Step 5b: wait for server handshake (policy check) ────────────────
	//
	// The server sends MsgServerReady (session allowed) or MsgSessionDenied
	// (user blocked by security policy).  A 10-second deadline is generous
	// for an in-memory check without leaving the user stuck at the prompt.
	serverConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	sr0 := bufio.NewReader(serverConn)
	hsType, hsPlen, hsErr := protocol.ReadHeader(sr0)
	serverConn.SetReadDeadline(time.Time{})

	if hsErr != nil {
		log.Printf("[%s] server handshake: %v", start.SessionID, hsErr)
		markDead()
		protocol.WriteMessage(pw, protocol.MsgSessionError, []byte(hsErr.Error()))
		return
	}
	switch hsType {
	case protocol.MsgSessionDenied:
		denyPayload, _ := protocol.ReadPayload(sr0, hsPlen)
		log.Printf("[%s] session denied by server policy for user=%s host=%s",
			start.SessionID, start.User, start.Host)
		protocol.WriteMessage(pw, protocol.MsgSessionDenied, denyPayload)
		serverConn.Close()
		return
	case protocol.MsgServerReady:
		_, _ = protocol.ReadPayload(sr0, hsPlen)

		// Start Wayland proxy whenever WAYLAND_DISPLAY is set — even when a
		// tty is present (e.g. "sudo gvim" from a terminal has both a pty
		// and a Wayland display).  The proxy captures only surfaces that the
		// sudo'd command actually creates; terminal-only commands produce no
		// frames and the session falls through to normal terminal replay.
		if start.WaylandDisplay != "" && cfg.Wayland {
			uid, gid := uint32(start.UserUID), uint32(start.UserGID)
			proxySocket, frames, proxyKill, proxyErr := startWaylandProxy(
				start.SessionID, start.WaylandDisplay, start.XdgRuntimeDir, uid, gid)
			if proxyErr != nil {
				log.Printf("[%s] wayland-proxy: %v — GUI session without screen capture",
					start.SessionID, proxyErr)
				protocol.WriteMessage(pw, protocol.MsgSessionReady, sessionReadyBody("", cfg.Disclaimer))
			} else {
				guiFrames = frames
				killProxy = proxyKill
				protocol.WriteMessage(pw, protocol.MsgSessionReady, sessionReadyBody(proxySocket, cfg.Disclaimer))
				log.Printf("[%s] wayland-proxy started, socket=%s", start.SessionID, proxySocket)
			}
		} else {
			protocol.WriteMessage(pw, protocol.MsgSessionReady, sessionReadyBody("", cfg.Disclaimer))
		}
	default:
		log.Printf("[%s] unexpected server handshake type 0x%02x", start.SessionID, hsType)
		markDead()
		protocol.WriteMessage(pw, protocol.MsgSessionError,
			[]byte(fmt.Sprintf("unexpected server handshake 0x%02x", hsType)))
		return
	}

	// ── Step 5c: start sender goroutine ─────────────────────────────────
	//
	// De-couples terminal reading from network writing.  Always drains the
	// priority queue (heartbeats, input) before sending bulk output chunks.
	go func() {
		for {
			var msg outMsg
			select {
			case <-done:
				return
			case msg = <-prioQueue:
				// Priority: heartbeat or input.
			default:
				// Bulk: wait for either.
				select {
				case <-done:
					return
				case msg = <-prioQueue:
				case msg = <-bulkQueue:
				}
			}

			serverWriteMu.Lock()
			serverConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			werr := protocol.WriteMessageNoFlush(serverBuf, msg.msgType, msg.payload)
			if werr == nil && (len(prioQueue) == 0 && len(bulkQueue) == 0) {
				// Flush when queues are drained.
				serverBuf.Flush()
			}
			serverConn.SetWriteDeadline(time.Time{})
			serverWriteMu.Unlock()

			if werr != nil {
				log.Printf("[%s] forward to server: %v", start.SessionID, werr)
				markDead()
				return
			}
		}
	}()

	// ── Step 6: read messages from server (ACKs + heartbeat replies) ──────
	//
	// sr0 is reused here (not a new bufio.Reader) to avoid silently dropping
	// any bytes that bufio may have buffered during the handshake read above.
	go func() {
		defer func() {
			serverConn.Close()
			markDead()
		}()
		sr := sr0
		for {
			msgType, plen, err := protocol.ReadHeader(sr)
			if err != nil {
				return
			}
			payload, err := protocol.ReadPayload(sr, plen)
			if err != nil {
				return
			}
			switch msgType {
			case protocol.MsgAck:
				ack, err := protocol.ParseAck(payload)
				if err != nil {
					log.Printf("parse ack: %v", err)
					continue
				}
				if !verifyAckSig(ack, start.SessionID) {
					log.Printf("ack signature invalid seq=%d — ignoring", ack.Seq)
					continue
				}
				touchServerMsg()
				updateAck(time.Now().UnixNano(), ack.Seq)
			case protocol.MsgHeartbeatAck:
				touchServerMsg()
				// markAlive is handled by the heartbeat goroutine after 2
				// consecutive successes to avoid flapping on delayed packets.
			}
		}
	}()

	// ── Step 6b: heartbeat goroutine ──────────────────────────────────────
	// Sends MsgHeartbeat every 400 ms.
	//   • No reply in 800 ms → markDead() (freeze), but keep pinging.
	//   • 2 consecutive windows with a response → markAlive() (unfreeze).
	//   • Write fails → TCP truly dead, exit goroutine.
	//
	// Recovery requires 2 consecutive successes (not just one) so that a
	// single delayed HeartbeatAck in flight when the server went down cannot
	// briefly flip state back to alive, which would cause a spurious second
	// freeze banner and a brief cgroup unfreeze visible to the user via fg.
	const hbInterval = 400 * time.Millisecond
	go func() {
		ticker := time.NewTicker(hbInterval)
		defer ticker.Stop()
		consecutiveOK := 0
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
			}

			prioQueue <- outMsg{msgType: protocol.MsgHeartbeat}

			lastServerMsgMu.Lock()
			age := time.Since(lastServerMsg)
			lastServerMsgMu.Unlock()
			if age > 2*hbInterval {
				// No response from server — freeze, but keep pinging.
				consecutiveOK = 0
				markDead()
			} else {
				consecutiveOK++
				if consecutiveOK >= 2 {
					// Two consecutive windows with a server response — server
					// is genuinely back.  markAlive is idempotent when already alive.
					markAlive()
				}
				if consecutiveOK >= 25 {
					// Connection has been stable for >10 seconds (25 * 400ms).
					// Safe to reset frozenSince so that future outages get a banner.
					resetFrozenStatus()
				}
			}
		}
	}()

	forward := func(msgType uint8, payload []byte) {
		sessionAckMu.Lock()
		alive := serverConnAlive
		sessionAckMu.Unlock()
		if !alive {
			return
		}

		msg := outMsg{msgType: msgType, payload: payload}
		isPrio := msgType == protocol.MsgSessionEnd || msgType == protocol.MsgSessionAbandon || msgType == protocol.MsgSessionFreezing

		if !isPrio && msgType == protocol.MsgChunk && len(payload) > 16 {
			stream := payload[16]
			if stream == protocol.StreamStdin || stream == protocol.StreamTtyIn {
				isPrio = true
			}
		}

		if isPrio {
			select {
			case prioQueue <- msg:
			case <-done:
			}
		} else {
			select {
			case bulkQueue <- msg:
			case <-done:
				// If session is ending, we don't care about bulk logs anymore.
			}
		}

		if msgType == protocol.MsgChunk {
			sessionAckMu.Lock()
			if ackDebtStartNs == 0 {
				ackDebtStartNs = time.Now().UnixNano()
			}
			sessionAckMu.Unlock()
		}
	}

	// ── Step 6c: forward Wayland proxy frames to server ──────────────────
	if guiFrames != nil {
		go func() {
			var screenSeq uint64
			for frame := range guiFrames {
				screenSeq++
				chunk := encodeScreenChunk(screenSeq, time.Now().UnixNano(), frame)
				forward(protocol.MsgChunk, chunk)
			}
		}()
	}

	// ── Step 7: main loop — SESSION_START already handled above ───────────
	var savedSessionEnd []byte
loop:
	for {
		msgType, plen, err := protocol.ReadHeader(pr)
		if err != nil {
			break loop
		}
		payload, err := protocol.ReadPayload(pr, plen)
		if err != nil {
			break loop
		}

		switch msgType {
		case protocol.MsgAckQuery:
			ts, seq := readAck()
			resp := protocol.EncodeAckResponse(ts, seq)
			pluginWriteMu.Lock()
			err := protocol.WriteMessage(pw, protocol.MsgAckResponse, resp)
			pluginWriteMu.Unlock()
			if err != nil {
				log.Printf("write ack response: %v", err)
				break loop
			}

		case protocol.MsgChunk:
			chunk, err := protocol.ParseChunk(payload)
			if err == nil && (chunk.Stream <= protocol.StreamTtyOut) {
				chunk.Data = redactor.Redact(chunk.Data, chunk.Stream)
				payload = protocol.EncodeChunk(chunk.Seq, chunk.Timestamp, chunk.Stream, chunk.Data)
			}
			if err == nil && (chunk.Stream == protocol.StreamStdin || chunk.Stream == protocol.StreamTtyIn) {
				lastInputNs.Store(time.Now().UnixNano())
			}
			forward(protocol.MsgChunk, payload)

		case protocol.MsgSessionEnd:
			savedSessionEnd = payload
			break loop

		default:
			log.Printf("unknown message type 0x%02x len=%d — ignoring", msgType, plen)
		}
	}

	// ── Step 8: linger if GUI processes remain ────────────────────────────
	//
	// If the sudo process (the plugin client) has exited but the cgroup still
	// has running processes, we enter linger mode. We keep the server
	// connection open and continue to forward Wayland proxy frames until the
	// cgroup is empty.
	if cg.hasPids() || cg.hasEscapedRunning() {
		log.Printf("[%s] sudo exited but GUI processes remain; entering linger mode", start.SessionID)
		const pollInterval = 1 * time.Second
		for cg.hasPids() || cg.hasEscapedRunning() {
			time.Sleep(pollInterval)
			// Heartbeat goroutine is still running and will call markDead()
			// (freezing the cgroup) if the server becomes unreachable.
		}
		log.Printf("[%s] all GUI processes exited; finishing session", start.SessionID)
	}

	// ── Step 9: final cleanup ─────────────────────────────────────────────
	if savedSessionEnd != nil {
		forward(protocol.MsgSessionEnd, savedSessionEnd)
	}

	// Stop all watchdog goroutines (including the heartbeat goroutine) before
	// touching serverConnAlive.  Without this, markAlive() in the heartbeat
	// goroutine can race with the serverConnAlive=false write below: if it wins
	// the lock it sets serverConnAlive=true again, and the subsequent write
	// failure on Close() causes markDead() to fire with firstFreeze=true,
	// producing a spurious freeze banner after normal session exit.
	closeDone()
	sessionAckMu.Lock()
	serverConnAlive = false
	sessionAckMu.Unlock()
	serverConn.Close()
}

// lingerCgroup keeps a session cgroup alive after the sudo process exits so
// that detached GUI programs (gvim, okular, …) remain frozen when the log
// server is unreachable.  It also tracks any PIDs that escaped the cgroup
// (moved by GNOME/systemd) and freezes those via SIGSTOP/SIGCONT.
// Exits when both the cgroup and all escaped PIDs are empty.
func lingerCgroup(cg *cgroupSession, server string, tlsCfg *tls.Config) {
	defer cg.stopTracking()
	defer cg.remove()
	log.Printf("cgroup %s: lingering (GUI processes remain)", cg.path)

	const pollInterval = 2 * time.Second
	const dialTimeout = 2 * time.Second

	serverReachable := func() bool {
		// A plain TCP connection is sufficient to verify network reachability.
		// A full TLS handshake would waste a round-trip and leave the server with
		// a connection that never sends SESSION_START.
		conn, err := net.DialTimeout("tcp", server, dialTimeout)
		if err != nil {
			return false
		}
		conn.Close()
		return true
	}

	for {
		time.Sleep(pollInterval)
		if !cg.hasPids() && !cg.hasEscapedRunning() {
			debugLog("cgroup %s: linger done — no more processes", cg.path)
			return
		}
		if serverReachable() {
			cg.unfreeze()
		} else {
			cg.freeze()
		}
	}
}

// ansiColors maps disclaimer_color names to ANSI SGR codes (open + reset).
var ansiColors = map[string][2]string{
	"red":         {"\033[91m", "\033[0m"},
	"green":       {"\033[92m", "\033[0m"},
	"blue":        {"\033[94m", "\033[0m"},
	"orange":      {"\033[33m", "\033[0m"},
	"bold_red":    {"\033[1;91m", "\033[0m"},
	"bold_green":  {"\033[1;92m", "\033[0m"},
	"bold_blue":   {"\033[1;94m", "\033[0m"},
	"bold_orange": {"\033[1;33m", "\033[0m"},
}

// applyColor wraps text with ANSI codes for the given color name and converts
// newlines to CRLF for correct terminal display.
func applyColor(text, color string) string {
	// Newlines must be CRLF for raw tty writes.
	text = strings.ReplaceAll(text, "\n", "\r\n")
	if codes, ok := ansiColors[color]; ok {
		return codes[0] + text + codes[1]
	}
	return text
}

// sessionReadyBody encodes a SESSION_READY JSON payload. Returns nil when both
// fields are empty so the plugin receives a zero-length body (backward compat).
func sessionReadyBody(proxyDisplay, disclaimer string) []byte {
	if proxyDisplay == "" && disclaimer == "" {
		return nil
	}
	if disclaimer != "" {
		disclaimer = applyColor(disclaimer, cfg.DisclaimerColor)
	}
	body, _ := json.Marshal(protocol.SessionReadyBody{ProxyDisplay: proxyDisplay, Disclaimer: disclaimer})
	return body
}

// reportSessionAbandon opens a fresh TLS connection to the server and sends a
// SESSION_ABANDON message so the server can mark the session as terminated by
// freeze-timeout rather than by an unexpected shipper death.
// Best-effort: logs and returns on any error.
func reportSessionAbandon(server string, cfg *tls.Config, sessionID string) {
	reportSessionMsg(server, cfg, sessionID, protocol.MsgSessionAbandon, 30*time.Second)
}

// reportSessionFreezing opens a fresh TLS connection to the server and sends a
// SESSION_FREEZING message so the server knows this session was frozen due to
// network loss — not a shipper kill.  Called on the first markDead() call while
// the server is likely still reachable (~800 ms after network loss).
// Best-effort: logs and returns on any error.
func reportSessionFreezing(server string, cfg *tls.Config, sessionID string) {
	reportSessionMsg(server, cfg, sessionID, protocol.MsgSessionFreezing, 10*time.Second)
}

// reportSessionMsg dials a fresh TLS connection to server and sends a single
// framed message of msgType with sessionID as the payload.
// Used by reportSessionAbandon and reportSessionFreezing.
func reportSessionMsg(server string, cfg *tls.Config, sessionID string, msgType uint8, dialTimeout time.Duration) {
	label := fmt.Sprintf("0x%02x", msgType)

	tcpAddr, err := net.ResolveTCPAddr("tcp", server)
	if err != nil {
		log.Printf("[%s] %s: resolve %s: %v", sessionID, label, server, err)
		return
	}
	rawTCP, err := net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		log.Printf("[%s] %s: dial: %v", sessionID, label, err)
		return
	}
	defer rawTCP.Close()

	tlsCfgClone := cfg.Clone()
	if tlsCfgClone.ServerName == "" {
		if host, _, splitErr := net.SplitHostPort(server); splitErr == nil {
			tlsCfgClone.ServerName = host
		} else {
			tlsCfgClone.ServerName = tcpAddr.IP.String()
		}
	}
	tlsConn := tls.Client(rawTCP, tlsCfgClone)
	tlsConn.SetDeadline(time.Now().Add(dialTimeout))
	defer tlsConn.Close()
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("[%s] %s: TLS handshake: %v", sessionID, label, err)
		return
	}
	w := bufio.NewWriter(tlsConn)
	if err := protocol.WriteMessage(w, msgType, []byte(sessionID)); err != nil {
		log.Printf("[%s] %s: write: %v", sessionID, label, err)
		return
	}
	log.Printf("[%s] %s sent to server", sessionID, label)
}

// verifyAckSig checks the ed25519 signature attached to an ACK from the server.
// The signed message is AckSignMessage(sessionID, seq, ts_ns) which binds the
// ACK to a specific session — an ACK captured from session A cannot be
// replayed to unfreeze session B.
func verifyAckSig(ack *Ack, sessionID string) bool {
	msg := protocol.AckSignMessage(sessionID, ack.Seq, ack.Timestamp)
	return ed25519.Verify(verifyKey, msg, ack.Sig[:])
}

// isSudoConn checks via SO_PEERCRED that the connecting process is running
// as root (defence-in-depth on top of the 0600 socket permissions).
func isSudoConn(conn net.Conn) bool {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return false
	}
	rawConn, err := uc.SyscallConn()
	if err != nil {
		return false
	}
	var uid = ^uint32(0) // invalid sentinel
	_ = rawConn.Control(func(fd uintptr) {
		ucred, soErr := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if soErr == nil {
			uid = ucred.Uid
		}
	})
	return uid == 0
}

// loadEd25519PubKey reads a PEM-encoded PKIX ed25519 public key.
func loadEd25519PubKey(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", path)
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	ed, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key in %s is not ed25519", path)
	}
	return ed, nil
}

func buildTLSConfig() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(cfg.Cert, cfg.Key)
	if err != nil {
		return nil, fmt.Errorf("load client cert: %w", err)
	}

	caPEM, err := os.ReadFile(cfg.CA)
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("parse CA cert")
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// encodeScreenChunk builds a CHUNK payload with STREAM_SCREEN.
// Layout: [8 seq][8 ts_ns][1 stream=0x05][4 datalen][data]
func encodeScreenChunk(seq uint64, tsNS int64, data []byte) []byte {
	buf := make([]byte, 21+len(data))
	binary.BigEndian.PutUint64(buf[0:], seq)
	binary.BigEndian.PutUint64(buf[8:], uint64(tsNS))
	buf[16] = protocol.StreamScreen
	binary.BigEndian.PutUint32(buf[17:], uint32(len(data)))
	copy(buf[21:], data)
	return buf
}

// validSessionID restricts session IDs to safe characters.
var validSessionID = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,255}$`)

// startWaylandProxy starts the wayland-proxy subprocess for a GUI session.
func startWaylandProxy(sessionID, waylandDisplay, xdgRuntimeDir string, uid, gid uint32) (
	proxySocket string, frames <-chan []byte, kill func(), err error,
) {
	// Resolve the real compositor socket path.
	realSocket := waylandDisplay
	if !filepath.IsAbs(realSocket) {
		if xdgRuntimeDir == "" {
			return "", nil, nil, fmt.Errorf("wayland-proxy: WAYLAND_DISPLAY is relative but XDG_RUNTIME_DIR is empty")
		}
		realSocket = filepath.Join(xdgRuntimeDir, waylandDisplay)
	}

	// VULN-001 & VULN-004 Fix: Validate untrusted inputs from the plugin.
	if !validSessionID.MatchString(sessionID) {
		return "", nil, nil, fmt.Errorf("wayland-proxy: invalid session ID")
	}
	if strings.Contains(waylandDisplay, "..") {
		return "", nil, nil, fmt.Errorf("wayland-proxy: invalid WAYLAND_DISPLAY")
	}
	if !filepath.IsAbs(xdgRuntimeDir) || strings.Contains(xdgRuntimeDir, "..") {
		return "", nil, nil, fmt.Errorf("wayland-proxy: invalid XDG_RUNTIME_DIR")
	}

	// Verify that the target directory is owned by the user (or root).
	// This prevents the user from pointing to a directory they don't own
	// to cause the shipper (root) to create files there.
	info, err := os.Stat(xdgRuntimeDir)
	if err != nil {
		return "", nil, nil, fmt.Errorf("wayland-proxy: cannot stat XDG_RUNTIME_DIR: %w", err)
	}
	if !info.IsDir() {
		return "", nil, nil, fmt.Errorf("wayland-proxy: XDG_RUNTIME_DIR is not a directory")
	}
	stat := info.Sys().(*syscall.Stat_t)
	if stat.Uid != uid && stat.Uid != 0 {
		return "", nil, nil, fmt.Errorf("wayland-proxy: XDG_RUNTIME_DIR is not owned by the user (uid=%d)", uid)
	}

	// Create the proxy socket in /run/user/<uid>/ so that the sudo'd command
	// (running as unconfined_t) can connect to it. A socket in /run/sudo-logger/
	// has SELinux type sudo_shipper_var_run_t; unconfined_t is silently denied
	// connectto on that type and the GUI app falls back to X11. /run/user/<uid>/
	// has type user_tmp_t which unconfined_t can freely connect to.
	// The shipper can write here because ReadWritePaths=/run/user is set in the
	// service unit (ProtectHome=read-only overrides /run/user but ReadWritePaths
	// restores write access).
	proxySocket = filepath.Join(xdgRuntimeDir, "sudo-wayland-"+sessionID+".sock")

	// Create the listening socket as root before spawning the proxy.
	os.Remove(proxySocket)
	ln, err := net.Listen("unix", proxySocket)
	if err != nil {
		return "", nil, nil, fmt.Errorf("wayland-proxy: listen %s: %w", proxySocket, err)
	}

	// Securely set permissions on the socket file. By using Chmod on the
	// file descriptor (File().Chmod), we avoid following symlinks that
	// an attacker might have placed at proxySocket in the meantime.
	if f, err := ln.(*net.UnixListener).File(); err == nil {
		if err := f.Chmod(0666); err != nil {
			f.Close()
			ln.Close()
			return "", nil, nil, fmt.Errorf("wayland-proxy: chmod socket: %w", err)
		}
		f.Close()
	}

	// Prevent Close() from removing the socket file — gvim needs the path.
	// The shipper removes the socket when the session ends.
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	// File() dups the fd; close the net.Listener (our original) immediately.
	lnFile, err := ln.(*net.UnixListener).File()
	ln.Close()
	if err != nil {
		os.Remove(proxySocket)
		return "", nil, nil, fmt.Errorf("wayland-proxy: socket fd: %w", err)
	}

	// Pass the listener fd as fd 3 (ExtraFiles[0]).
	cmd := exec.Command(cfg.ProxyBin,
		"--real", realSocket,
		"--fd", "3",
		"--period", fmt.Sprintf("%d", cfg.ProxyPeriod),
	)
	cmd.Stderr = os.Stderr
	cmd.ExtraFiles = []*os.File{lnFile}
	// Run proxy as the invoking user so it can connect to the compositor socket.
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: uid, Gid: gid},
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		lnFile.Close()
		os.Remove(proxySocket)
		return "", nil, nil, fmt.Errorf("wayland-proxy: stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		lnFile.Close()
		os.Remove(proxySocket)
		return "", nil, nil, fmt.Errorf("wayland-proxy: start: %w", err)
	}
	lnFile.Close() // child inherited it via ExtraFiles; close our dup

	killProxy := func() {
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
	}

	ch := make(chan []byte, 32)
	go func() {
		defer close(ch)
		defer os.Remove(proxySocket)
		defer cmd.Wait()
		var sizeBuf [4]byte
		for {
			if _, err := io.ReadFull(stdout, sizeBuf[:]); err != nil {
				return
			}
			size := binary.BigEndian.Uint32(sizeBuf[:])
			if size == 0 || size > 10*1024*1024 { // sanity: max 10 MB per frame
				return
			}
			frame := make([]byte, size)
			if _, err := io.ReadFull(stdout, frame); err != nil {
				return
			}
			select {
			case ch <- frame:
			default:
				// Drop frame if shipper is behind — prefer liveness over completeness.
			}
		}
	}()

	return proxySocket, ch, killProxy, nil
}

// Ack is re-declared here for the verifyAckHMAC helper so we don't
// need a circular import. The actual type lives in protocol.
type Ack = protocol.Ack
