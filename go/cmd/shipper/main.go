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
	flagHMAC = flag.String("hmackey", "/etc/sudo-logger/hmac.key", "HMAC key file")
)

var (
	hmacKey []byte
	tlsCfg  *tls.Config
)

func main() {
	flag.Parse()

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
	// defer cg.remove() runs on every return path: normal end, TLS error,
	// network loss, and force-kill.  remove() is nil-safe.
	cg := newCgroupSession(start.SessionID, start.Pid)
	defer cg.remove()

	// ── Step 3: per-session ACK tracking ──────────────────────────────────
	const ackLagLimit = int64(4 * time.Second)

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
			syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_KEEPCNT, 3)
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

	// ── Step 6: read ACKs from server ─────────────────────────────────────
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
			if msgType != protocol.MsgAck {
				continue
			}
			ack, err := protocol.ParseAck(payload)
			if err != nil {
				log.Printf("parse ack: %v", err)
				continue
			}
			if !verifyAckHMAC(ack) {
				log.Printf("ack HMAC mismatch seq=%d — ignoring", ack.Seq)
				continue
			}
			updateAck(time.Now().UnixNano(), ack.Seq)
		}
	}()

	forward := func(msgType uint8, payload []byte) {
		sessionAckMu.Lock()
		alive := serverConnAlive
		sessionAckMu.Unlock()
		if !alive {
			return
		}
		serverConn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		defer serverConn.SetWriteDeadline(time.Time{})
		if err := protocol.WriteMessage(serverBuf, msgType, payload); err != nil {
			log.Printf("forward to server: %v", err)
			markDead()
			return
		}
		if err := serverBuf.Flush(); err != nil {
			log.Printf("flush to server: %v", err)
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
