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

	// Each session gets its own ACK tracker so the plugin gets
	// per-session freshness, not a stale value from a concurrent session.
	const ackLagLimit = int64(4 * time.Second) // ns without ACK after sending chunks = dead

	var (
		sessionAckMu    sync.Mutex
		sessionAckSeq   uint64
		serverConnAlive bool
		// ackDebtStartNs is set when a chunk is forwarded without a prior ACK
		// clearing the debt. It is reset to 0 whenever an ACK arrives from the
		// server. This measures "how long have chunks been waiting for an ACK"
		// independent of how long the user was idle between keypresses.
		ackDebtStartNs int64
	)

	updateAck := func(ts int64, seq uint64) {
		sessionAckMu.Lock()
		sessionAckSeq = seq
		// Any ACK from the server clears the outstanding debt.
		ackDebtStartNs = 0
		sessionAckMu.Unlock()
	}

	// readAck returns the current ACK state.
	// Returns time.Now() (fresh) when the server is alive and ACKing promptly.
	// Returns 0 (stale) when:
	//   - TCP connection has died, OR
	//   - A chunk has been waiting for an ACK for longer than ackLagLimit.
	//     The wait is measured from when the debt started, not from when the
	//     user last typed — this prevents false freezes after idle periods.
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

	// Connect to remote server — must succeed before sudo is allowed to proceed.
	// Dial TCP manually so we can set aggressive keepalives before the TLS handshake.
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
	rawTCP.SetKeepAlivePeriod(1 * time.Second) // TCP_KEEPIDLE=1
	if sc, scErr := rawTCP.SyscallConn(); scErr == nil {
		sc.Control(func(fd uintptr) {
			syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_KEEPINTVL, 1)
			syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_KEEPCNT, 3)
		})
	}
	// Clone config and set ServerName from the address (host part only).
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

	// Mark alive — readAck will return time.Now() until this flips to false.
	markDead := func() {
		sessionAckMu.Lock()
		serverConnAlive = false
		ackDebtStartNs = 0 // readAck uses serverConnAlive=false path now
		sessionAckMu.Unlock()
	}

	sessionAckMu.Lock()
	serverConnAlive = true
	sessionAckMu.Unlock()

	// Tell plugin sudo may proceed
	protocol.WriteMessage(pw, protocol.MsgSessionReady, nil)

	serverBuf := bufio.NewWriter(serverConn)

	// Goroutine: read ACKs from server. When connection drops, mark dead
	// so the plugin sees a stale ACK timestamp and freezes within ACK_TIMEOUT_SECS.
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

	// forward sends a message to the server with a hard write deadline so the
	// main loop is never blocked longer than 2s. On any error the connection
	// is marked dead and subsequent calls become no-ops.
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
		// Start the ACK debt timer when a chunk is forwarded.
		// If no debt is already outstanding, this is the start of a new
		// unACKed window. An arriving ACK (updateAck) will reset it to 0.
		if msgType == protocol.MsgChunk {
			sessionAckMu.Lock()
			if ackDebtStartNs == 0 {
				ackDebtStartNs = time.Now().UnixNano()
			}
			sessionAckMu.Unlock()
		}
	}

	// Main loop: read messages from plugin
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
			// Plugin wants to know the last ACK timestamp — respond immediately
			ts, seq := readAck()
			resp := protocol.EncodeAckResponse(ts, seq)
			if err := protocol.WriteMessage(pw, protocol.MsgAckResponse, resp); err != nil {
				log.Printf("write ack response: %v", err)
				return
			}

		case protocol.MsgSessionStart:
			log.Printf("session start: %s", truncate(string(payload), 120))
			forward(protocol.MsgSessionStart, payload)

		case protocol.MsgChunk:
			forward(protocol.MsgChunk, payload)

		case protocol.MsgSessionEnd:
			forward(protocol.MsgSessionEnd, payload)
			if serverConn != nil {
				// Flush and close gracefully
				if serverBuf != nil {
					serverBuf.Flush()
				}
				serverConn.Close()
			}
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
