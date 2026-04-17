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
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"syscall"
	"time"

	"sudo-logger/internal/protocol"
)

// freezeMsgTTY is the same banner the plugin would write but sent directly
// to the TTY device by the shipper so it appears even when sudo is SIGTSTP'd.
const freezeMsgTTY = "\r\n\033[41;97;1m[ SUDO-LOGGER: log server unreachable — input frozen ]\033[0m\r\n" +
	"\033[33mWaiting for log server to come back...\033[0m\r\n"

// validTTYPath restricts tty_path to known safe device paths.
var validTTYPath = regexp.MustCompile(`^/dev/(pts/\d{1,6}|tty[a-zA-Z0-9]{0,10})$`)

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

var (
	flagServer  = flag.String("server", "logserver:9876", "Remote log server address")
	flagSocket  = flag.String("socket", "/run/sudo-logger/plugin.sock", "Unix socket path")
	flagCert    = flag.String("cert", "/etc/sudo-logger/client.crt", "Client TLS certificate")
	flagKey     = flag.String("key", "/etc/sudo-logger/client.key", "Client TLS key")
	flagCA      = flag.String("ca", "/etc/sudo-logger/ca.crt", "CA certificate")
	flagVerifyKey     = flag.String("verifykey", "/etc/sudo-logger/ack-verify.key", "ed25519 public key for ACK verification (PEM)")
	flagFreezeTimeout = flag.Duration("freeze-timeout", 3*time.Minute, "Terminate a frozen session after this duration of server unreachability (0 = never)")
	flagDebug         = flag.Bool("debug", false, "Enable verbose debug logging")
	flagProxyBin      = flag.String("proxy-bin", "/usr/libexec/sudo-logger/wayland-proxy", "Path to the wayland-proxy binary")
)

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
	if *flagDebug {
		debugLog = log.Printf
	}

	var err error
	verifyKey, err = loadEd25519PubKey(*flagVerifyKey)
	if err != nil {
		log.Fatalf("load verify key: %v", err)
	}

	tlsCfg, err = buildTLSConfig()
	if err != nil {
		log.Fatalf("build TLS config: %v", err)
	}

	// Remove stale socket from previous run
	if err := os.Remove(*flagSocket); err != nil && !os.IsNotExist(err) {
		log.Printf("remove stale socket: %v", err)
	}

	if err := os.MkdirAll("/run/sudo-logger", 0750); err != nil {
		log.Fatalf("mkdir /run/sudo-logger: %v", err)
	}

	ln, err := net.Listen("unix", *flagSocket)
	if err != nil {
		log.Fatalf("listen unix %s: %v", *flagSocket, err)
	}
	defer ln.Close()

	// Only root (sudo process) may connect
	if err := os.Chmod(*flagSocket, 0600); err != nil {
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

	log.Printf("sudo-shipper listening on %s, forwarding to %s", *flagSocket, *flagServer)

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

	pr := bufio.NewReader(pluginConn)
	pw := bufio.NewWriter(pluginConn)

	// ── Step 1: read SESSION_START before connecting to the server ────────
	//
	// We need the sudo PID to create the session cgroup BEFORE sudo forks
	// the child.  Fork inherits cgroup membership, so the child and all its
	// descendants — including GUI programs that later detach and re-parent
	// to init/systemd — remain in the cgroup and can be frozen atomically.
	msgType, plen, err := protocol.ReadHeader(pr)
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
			go lingerCgroup(cg, *flagServer, tlsCfg)
		} else {
			cg.stopTracking()
			cg.remove()
		}
	}()

	// ── Step 3: per-session ACK tracking ──────────────────────────────────
	const ackLagLimit = int64(2 * time.Second)

	// guiFrames receives JPEG frames from the Wayland proxy for GUI sessions.
	// Populated in the MsgServerReady case below; consumed after forward() is declared.
	var guiFrames <-chan []byte

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
		serverConnAlive = true // connection recovered
		sessionAckSeq = seq
		ackDebtStartNs = 0
		frozenSince = time.Time{} // reset — server is reachable again
		sessionAckMu.Unlock()
		cg.unfreeze() // nil-safe; no-op when not frozen
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
	tcpAddr, err := net.ResolveTCPAddr("tcp", *flagServer)
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
		if host, _, splitErr := net.SplitHostPort(*flagServer); splitErr == nil {
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
			go writeTTYFreezeMsg(start.TtyPath)
			go reportSessionFreezing(*flagServer, tlsCfg, start.SessionID)
		}
	}

	markAlive := func() {
		sessionAckMu.Lock()
		wasAlive := serverConnAlive
		serverConnAlive = true
		ackDebtStartNs = 0 // heartbeat proves server is alive; reset ACK debt
		frozenSince = time.Time{}
		sessionAckMu.Unlock()
		if !wasAlive {
			cg.unfreeze()
		}
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
	if *flagFreezeTimeout > 0 {
		go func() {
			ticker := time.NewTicker(10 * time.Second)
			defer ticker.Stop()
			for range ticker.C {
				sessionAckMu.Lock()
				since := frozenSince
				sessionAckMu.Unlock()

				if since.IsZero() {
					continue // not frozen
				}
				if time.Since(since) < *flagFreezeTimeout {
					continue // frozen but within allowed window
				}

				log.Printf("[%s] server unreachable for >%v — terminating frozen session",
					start.SessionID, *flagFreezeTimeout)
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
				go reportSessionAbandon(*flagServer, tlsCfg, start.SessionID)
				return
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
	serverBuf := bufio.NewWriter(serverConn)
	log.Printf("[%s] start user=%s host=%s pid=%d cmd=%s cgroup=%v wayland=%q xdg=%q",
		start.SessionID, start.User, start.Host, start.Pid,
		truncate(start.Command, 60), cg != nil,
		start.WaylandDisplay, start.XdgRuntimeDir)
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
		if start.WaylandDisplay != "" {
			uid, gid := resolveUserIDs(start.User)
			proxySocket, frames, proxyErr := startWaylandProxy(
				start.SessionID, start.WaylandDisplay, start.XdgRuntimeDir, uid, gid)
			if proxyErr != nil {
				log.Printf("[%s] wayland-proxy: %v — GUI session without screen capture",
					start.SessionID, proxyErr)
				protocol.WriteMessage(pw, protocol.MsgSessionReady, nil)
			} else {
				guiFrames = frames
				body, _ := json.Marshal(protocol.SessionReadyBody{ProxyDisplay: proxySocket})
				protocol.WriteMessage(pw, protocol.MsgSessionReady, body)
				log.Printf("[%s] wayland-proxy started, socket=%s", start.SessionID, proxySocket)
			}
		} else {
			protocol.WriteMessage(pw, protocol.MsgSessionReady, nil)
		}
	default:
		log.Printf("[%s] unexpected server handshake type 0x%02x", start.SessionID, hsType)
		markDead()
		protocol.WriteMessage(pw, protocol.MsgSessionError,
			[]byte(fmt.Sprintf("unexpected server handshake 0x%02x", hsType)))
		return
	}

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
				markAlive()
			}
		}
	}()

	// ── Step 6b: heartbeat goroutine ──────────────────────────────────────
	// Sends MsgHeartbeat every 400 ms.
	//   • No reply in 800 ms → markDead() (freeze), but keep pinging.
	//   • Reply arrives after dead period → markAlive() (unfreeze).
	//   • Write fails → TCP truly dead, exit goroutine.
	const hbInterval = 400 * time.Millisecond
	go func() {
		ticker := time.NewTicker(hbInterval)
		defer ticker.Stop()
		for range ticker.C {
			serverWriteMu.Lock()
			serverConn.SetWriteDeadline(time.Now().Add(hbInterval))
			werr := protocol.WriteMessage(serverBuf, protocol.MsgHeartbeat, nil)
			serverConn.SetWriteDeadline(time.Time{})
			serverWriteMu.Unlock()

			if werr != nil {
				// TCP connection is gone — no recovery possible.
				markDead()
				return
			}

			lastServerMsgMu.Lock()
			age := time.Since(lastServerMsg)
			lastServerMsgMu.Unlock()
			if age > 2*hbInterval {
				// No response from server — freeze, but keep pinging.
				// Recovery happens in the ACK reader via markAlive().
				markDead()
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
		serverWriteMu.Lock()
		serverConn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		werr := protocol.WriteMessage(serverBuf, msgType, payload)
		serverConn.SetWriteDeadline(time.Time{})
		serverWriteMu.Unlock()
		if werr != nil {
			log.Printf("forward to server: %v", werr)
			markDead()
			return
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
	for {
		msgType, plen, err := protocol.ReadHeader(pr)
		if err != nil {
			return
		}
		payload, err := protocol.ReadPayload(pr, plen)
		if err != nil {
			return
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
				return
			}

		case protocol.MsgChunk:
			forward(protocol.MsgChunk, payload)

		case protocol.MsgSessionEnd:
			forward(protocol.MsgSessionEnd, payload)
			// Mark the connection as intentionally closed before closing the
			// socket.  The heartbeat goroutine may still fire once after this
			// and call markDead() — setting serverConnAlive=false here ensures
			// firstFreeze is false so no spurious SESSION_FREEZING is sent.
			sessionAckMu.Lock()
			serverConnAlive = false
			sessionAckMu.Unlock()
			serverConn.Close()
			return

		default:
			log.Printf("unknown message type 0x%02x len=%d — ignoring", msgType, plen)
		}
	}
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
	cert, err := tls.LoadX509KeyPair(*flagCert, *flagKey)
	if err != nil {
		return nil, fmt.Errorf("load client cert: %w", err)
	}

	caPEM, err := os.ReadFile(*flagCA)
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

// resolveUserIDs looks up the UID and GID for username.
// Falls back to (65534, 65534) — nobody — on any error.
func resolveUserIDs(username string) (uid, gid uint32) {
	u, err := user.Lookup(username)
	if err != nil {
		log.Printf("resolveUserIDs(%q): %v — using nobody", username, err)
		return 65534, 65534
	}
	uid64, _ := strconv.ParseUint(u.Uid, 10, 32)
	gid64, _ := strconv.ParseUint(u.Gid, 10, 32)
	return uint32(uid64), uint32(gid64)
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

// startWaylandProxy starts the wayland-proxy subprocess for a GUI session.
// It returns the proxy socket path and a channel that receives JPEG frame
// bytes as they are produced. The channel is closed when the proxy exits.
// The caller must send the proxy socket path back to the plugin via SESSION_READY.
//
// The proxy process is started as the invoking user (uid/gid) so it can
// connect to the Wayland compositor socket in /run/user/<uid>/.
// The proxy socket is placed in the user's XDG_RUNTIME_DIR so the user
// can create it and gvim (running as root) can connect to it.
func startWaylandProxy(sessionID, waylandDisplay, xdgRuntimeDir string, uid, gid uint32) (
	proxySocket string, frames <-chan []byte, err error,
) {
	// Resolve the real compositor socket path.
	realSocket := waylandDisplay
	if !filepath.IsAbs(realSocket) {
		if xdgRuntimeDir == "" {
			return "", nil, fmt.Errorf("wayland-proxy: WAYLAND_DISPLAY is relative but XDG_RUNTIME_DIR is empty")
		}
		realSocket = filepath.Join(xdgRuntimeDir, waylandDisplay)
	}

	// Place the proxy socket in the user's runtime dir so the user-owned
	// proxy process can create it.  Root (gvim) can still connect because
	// root bypasses DAC on socket files.
	if xdgRuntimeDir == "" {
		xdgRuntimeDir = fmt.Sprintf("/run/user/%d", uid)
	}
	proxySocket = filepath.Join(xdgRuntimeDir, "sudo-wayland-"+sessionID+".sock")

	cmd := exec.Command(*flagProxyBin, "--real", realSocket, "--socket", proxySocket)
	cmd.Stderr = os.Stderr
	// Run proxy as the invoking user so it can access the compositor socket.
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: uid, Gid: gid},
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", nil, fmt.Errorf("wayland-proxy: stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return "", nil, fmt.Errorf("wayland-proxy: start: %w", err)
	}

	ch := make(chan []byte, 32)
	go func() {
		defer close(ch)
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

	return proxySocket, ch, nil
}

// Ack is re-declared here for the verifyAckHMAC helper so we don't
// need a circular import. The actual type lives in protocol.
type Ack = protocol.Ack
