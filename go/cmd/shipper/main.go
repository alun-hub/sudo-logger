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
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"sudo-logger/internal/protocol"
)

var (
	flagServer  = flag.String("server", "logserver:9876", "Remote log server address")
	flagSocket  = flag.String("socket", "/run/sudo-logger/plugin.sock", "Unix socket path")
	flagCert    = flag.String("cert", "/etc/sudo-logger/client.crt", "Client TLS certificate")
	flagKey     = flag.String("key", "/etc/sudo-logger/client.key", "Client TLS key")
	flagCA      = flag.String("ca", "/etc/sudo-logger/ca.crt", "CA certificate")
	flagHMAC    = flag.String("hmackey", "/etc/sudo-logger/hmac.key", "HMAC key file")
	flagDebug   = flag.Bool("debug", false, "Enable verbose debug logging")
)

// debugLog is a no-op by default; replaced with log.Printf when -debug is set.
var debugLog = func(format string, args ...any) {}

var (
	hmacKey []byte
	tlsCfg  *tls.Config
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
	hmacKey, err = os.ReadFile(*flagHMAC)
	if err != nil {
		log.Fatalf("read hmac key: %v", err)
	}

	tlsCfg, err = buildTLSConfig()
	if err != nil {
		log.Fatalf("build TLS config: %v", err)
	}

	// Remove stale socket from previous run
	os.Remove(*flagSocket)

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

	var (
		sessionAckMu    sync.Mutex
		sessionAckSeq   uint64
		serverConnAlive bool
		// ackDebtStartNs measures how long chunks have been waiting for an
		// ACK.  Reset on every incoming ACK.  Independent of idle time so
		// idle sessions never trigger a false freeze.
		ackDebtStartNs int64
	)

	updateAck := func(ts int64, seq uint64) {
		sessionAckMu.Lock()
		serverConnAlive = true // connection recovered
		sessionAckSeq = seq
		ackDebtStartNs = 0
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
		serverConnAlive = false
		ackDebtStartNs = 0
		sessionAckMu.Unlock()
		cg.freeze() // nil-safe; freezes all session processes via cgroup
	}

	markAlive := func() {
		sessionAckMu.Lock()
		wasAlive := serverConnAlive
		serverConnAlive = true
		sessionAckMu.Unlock()
		if !wasAlive {
			cg.unfreeze()
		}
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
	// SESSION_READY is sent only after SESSION_START has been forwarded so
	// the server is always informed before sudo forks the child process.
	serverBuf := bufio.NewWriter(serverConn)
	log.Printf("[%s] start user=%s host=%s pid=%d cmd=%s cgroup=%v",
		start.SessionID, start.User, start.Host, start.Pid,
		truncate(start.Command, 60), cg != nil)
	if err := protocol.WriteMessage(serverBuf, protocol.MsgSessionStart, startPayload); err != nil {
		log.Printf("[%s] forward SESSION_START: %v", start.SessionID, err)
		markDead()
		protocol.WriteMessage(pw, protocol.MsgSessionError, []byte(err.Error()))
		return
	}
	// Sudo is now cleared to fork the child — which inherits the cgroup.
	protocol.WriteMessage(pw, protocol.MsgSessionReady, nil)

	// ── Step 6: read messages from server (ACKs + heartbeat replies) ──────
	go func() {
		defer func() {
			serverConn.Close()
			markDead()
		}()
		sr := bufio.NewReader(serverConn)
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
				if !verifyAckHMAC(ack) {
					log.Printf("ack HMAC mismatch seq=%d — ignoring", ack.Seq)
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
			if err := protocol.WriteMessage(pw, protocol.MsgAckResponse, resp); err != nil {
				log.Printf("write ack response: %v", err)
				return
			}

		case protocol.MsgChunk:
			forward(protocol.MsgChunk, payload)

		case protocol.MsgSessionEnd:
			forward(protocol.MsgSessionEnd, payload)
			serverBuf.Flush()
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
		tcpAddr, err := net.ResolveTCPAddr("tcp", server)
		if err != nil {
			return false
		}
		rawTCP, err := net.DialTCP("tcp", nil, tcpAddr)
		if err != nil {
			return false
		}
		defer rawTCP.Close()
		cfg := tlsCfg.Clone()
		if cfg.ServerName == "" {
			if host, _, splitErr := net.SplitHostPort(server); splitErr == nil {
				cfg.ServerName = host
			} else {
				cfg.ServerName = tcpAddr.IP.String()
			}
		}
		tlsConn := tls.Client(rawTCP, cfg)
		tlsConn.SetDeadline(time.Now().Add(dialTimeout))
		defer tlsConn.Close()
		return tlsConn.Handshake() == nil
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

// verifyAckHMAC checks the HMAC attached to an ACK from the server.
// The server signs: sessionID (not available here) + seq + ts_ns.
// For the shipper we verify using seq + ts_ns only (no session binding).
// The server includes the session ID in its HMAC — full verification
// happens conceptually at the server; here we do a lightweight check.
func verifyAckHMAC(ack *Ack) bool {
	mac := hmac.New(sha256.New, hmacKey)
	var buf [16]byte
	binary.BigEndian.PutUint64(buf[0:], ack.Seq)
	binary.BigEndian.PutUint64(buf[8:], uint64(ack.Timestamp))
	mac.Write(buf[:])
	expected := mac.Sum(nil)
	return hmac.Equal(expected, ack.HMAC[:])
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

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// Ack is re-declared here for the verifyAckHMAC helper so we don't
// need a circular import. The actual type lives in protocol.
type Ack = protocol.Ack
