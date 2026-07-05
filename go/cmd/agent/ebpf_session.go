package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"sudo-logger/internal/iolog"
	"sudo-logger/internal/protocol"
)

type ebpfSession struct {
	id            string
	user          string
	host          string
	remote        string
	command       string
	cgroupID      uint64
	source        string // "ebpf-tty" or "ebpf-pkexec"
	parentID      string // parent session ID (pkexec only)
	hasIO         bool   // false = no TTY data expected (background pkexec)
	ts            time.Time // event time; zero means use time.Now() at connect
	connectedAt   time.Time // set by connect(); used by sweeper to evict stale sessions

	mu     sync.Mutex
	conn   net.Conn
	bw     *bufio.Writer
	redactor *iolog.Redactor
	seq    uint64
	done   bool
	cancel context.CancelFunc
}

func (s *ebpfSession) connect(addr string, tlsCfg *tls.Config, verifyKey []byte) error {
	s.connectedAt = time.Now()
	rawTCP, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("dial %s: %w", addr, err)
	}
	tc := rawTCP.(*net.TCPConn)
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(1 * time.Second)

	cfg := tlsCfg.Clone()
	if cfg.ServerName == "" {
		if host, _, err := net.SplitHostPort(addr); err == nil {
			cfg.ServerName = host
		}
	}
	tlsConn := tls.Client(rawTCP, cfg)
	if err := tlsConn.Handshake(); err != nil {
		rawTCP.Close()
		return fmt.Errorf("TLS handshake: %w", err)
	}

	s.conn = tlsConn
	s.bw = bufio.NewWriterSize(tlsConn, 64*1024)

	src := s.source
	if src == "" {
		src = "ebpf-tty"
	}
	start := protocol.SessionStart{
		SessionID:       s.id,
		User:            s.user,
		Host:            s.host,
		Command:         s.command,
		Ts:              func() int64 { if !s.ts.IsZero() { return s.ts.Unix() }; return time.Now().Unix() }(),
		Pid:             os.Getpid(),
		Source:          src,
		ParentSessionID: s.parentID,
		HasIO:           s.hasIO,
	}
	payload, _ := json.Marshal(start)
	if err := protocol.WriteMessage(s.bw, protocol.MsgSessionStart, payload); err != nil {
		tlsConn.Close()
		return fmt.Errorf("send session start: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel

	go s.heartbeat(ctx)
	go s.drainACKs(ctx, verifyKey)

	return nil
}

func (s *ebpfSession) sendChunk(tsNS int64, stream uint8, data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done || s.conn == nil {
		return
	}
	if s.redactor != nil {
		var buffering bool
		data, buffering = s.redactor.Redact(data, stream)
		if buffering {
			return
		}
	}
	s.seq++
	payload := protocol.EncodeChunk(s.seq, tsNS, stream, data)
	if s.conn != nil {
		_ = s.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	}
	if err := protocol.WriteMessage(s.bw, protocol.MsgChunk, payload); err != nil {
		log.Printf("ebpf [%s]: send chunk: %v", s.id, err)
		s.done = true
		if s.cancel != nil {
			s.cancel()
		}
	}
}

func (s *ebpfSession) close(exitCode int32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done || s.conn == nil {
		return
	}
	s.done = true
	if s.cancel != nil {
		s.cancel()
	}
	payload := protocol.EncodeSessionEnd(s.seq, exitCode)
	_ = protocol.WriteMessage(s.bw, protocol.MsgSessionEnd, payload)
	s.conn.Close()
}

func (s *ebpfSession) heartbeat(ctx context.Context) {
	ticker := time.NewTicker(400 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		s.mu.Lock()
		if s.done {
			s.mu.Unlock()
			return
		}
		_ = protocol.WriteMessage(s.bw, protocol.MsgHeartbeat, nil)
		s.mu.Unlock()
	}
}

func (s *ebpfSession) drainACKs(ctx context.Context, verifyKey []byte) {
	s.mu.Lock()
	conn := s.conn
	s.mu.Unlock()
	if conn == nil {
		return
	}
	br := bufio.NewReader(conn)

	for {
		// Check context before blocking on read.
		select {
		case <-ctx.Done():
			return
		default:
		}

		msgType, payloadLen, err := protocol.ReadHeader(br)
		if err != nil {
			return
		}
		payload, err := protocol.ReadPayload(br, payloadLen)
		if err != nil {
			return
		}

		switch msgType {
		case protocol.MsgAck:
			if verifyKey != nil {
				ack, parseErr := protocol.ParseAck(payload)
				if parseErr != nil {
					log.Printf("ebpf [%s]: parse ACK: %v — ignoring", s.id, parseErr)
					continue
				}
				if !verifyAckSig(ack, s.id, verifyKey) {
					log.Printf("ebpf [%s]: ACK signature invalid seq=%d — ignoring", s.id, ack.Seq)
					continue
				}
			}
		case protocol.MsgHeartbeatAck:
		}

	}
}

func generateEBPFSessionID(hostname, username, sessionNum string) string {
	ts := strconv.FormatInt(time.Now().UnixNano(), 10)
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
	id := fmt.Sprintf("ebpf.%s.%s.%s.%s", safe(hostname), safe(username), sessionNum, ts)
	if len(id) > 200 {
		id = id[:200]
	}
	return id
}
