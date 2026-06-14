// plugin.go — Unix-socket plugin handler for sudo-logger-agent.
// Receives connections from the sudo C plugin and forwards them to the log
// server over TLS.  This is the same logic as the former sudo-logger-agent daemon.
package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"sudo-logger/internal/iolog"
	"sudo-logger/internal/protocol"
)

const freezeMsgHeader = "\r\n\033[41;97;1m[ SUDO-LOGGER: log server unreachable — input frozen ]\033[0m\r\n"

var validTTYPath = regexp.MustCompile(`^/dev/(pts/\d{1,6}|tty[a-zA-Z0-9]{0,10})$`)

func resolveTTYPath(ttyPath string, sudoPID int) string {
	if ttyPath != "/dev/tty" {
		if validTTYPath.MatchString(ttyPath) {
			return ttyPath
		}
		// If the provided path is invalid, fall back to /dev/tty resolution via procfs.
		ttyPath = "/dev/tty"
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

func writeTTYFreezeMsg(ttyPath string, freezeTimeout time.Duration) {
	if ttyPath == "" || !validTTYPath.MatchString(ttyPath) {
		return
	}
	f, err := os.OpenFile(ttyPath, os.O_WRONLY, 0)
	if err != nil {
		log.Printf("freeze banner: open %s: %v", ttyPath, err)
		return
	}
	defer f.Close()
	msg := freezeMsgHeader
	if freezeTimeout > 0 {
		msg += fmt.Sprintf("\033[33mWaiting for log server to come back... (session terminates in %s if unreachable)\033[0m\r\n", freezeTimeout)
	} else {
		msg += "\033[33mWaiting for log server to come back...\033[0m\r\n"
	}
	_, _ = f.WriteString(msg)
}

func writeTTYIdleWarnMsg(ttyPath string, remaining time.Duration) {
	if ttyPath == "" || !validTTYPath.MatchString(ttyPath) {
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

// activeCgs tracks all live session cgroups for graceful cleanup on shutdown.
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

// handlePluginConn manages one sudo session end-to-end.
func handlePluginConn(pluginConn net.Conn) {
	defer pluginConn.Close()

	done := make(chan struct{})
	var closeOnce sync.Once
	closeDone := func() { closeOnce.Do(func() { close(done) }) }
	defer closeDone()

	type outMsg struct {
		msgType uint8
		payload []byte
	}
	prioQueue := make(chan outMsg, 100)
	bulkQueue := make(chan outMsg, 10000)

	stopSender := make(chan struct{})
	var senderWg sync.WaitGroup
	senderWg.Add(1)

	pr := bufio.NewReader(pluginConn)
	pw := bufio.NewWriter(pluginConn)

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
	if plen > protocol.MaxSessionStartPayload {
		log.Printf("SESSION_START payload too large (%d bytes, max %d) — dropping", plen, protocol.MaxSessionStartPayload)
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

	// Notify the divergence tracker that the plugin logged this sudo session.
	// witnessed=true means eBPF saw the execve — the session is fully confirmed.
	// witnessed=false means eBPF was not running or missed the execve.
	witnessed := div.confirmPlugin(start.User, start.Host)
	if witnessed {
		start.DivergenceStatus = "confirmed"
	} else {
		start.DivergenceStatus = "unwitnessed"
	}

	cg := newCgroupSession(start.SessionID, start.Pid)
	registerCg(cg)
	// Register the sudo PID in the BPF tracked_sudo_pids map so the execve hook
	// suppresses the child execve sudo fires when running the target command.
	// Also register the session cgroup for PTY I/O capture.
	// Both must happen before SESSION_READY is sent (sudo forks only after that).
	if ebpfSys != nil {
		ebpfSys.trackSudoPID(uint32(start.Pid), start.SessionID)
	}
	sandboxSys.registerPID(uint32(start.Pid))
	if cg != nil && ebpfSys != nil {
		ebpfSys.trackPluginCgroup(cg.path, start.SessionID)
	}
	defer func() {
		sandboxSys.unregisterPID(uint32(start.Pid))
		if ebpfSys != nil {
			ebpfSys.untrackSudoPID(uint32(start.Pid))
		}
		if cg != nil && ebpfSys != nil {
			ebpfSys.untrackPluginCgroup(cg.path)
		}
		unregisterCg(cg)
		if cg.hasPids() || cg.hasEscapedRunning() {
			go lingerCgroup(cg, cfg.Server, tlsCfg)
		} else {
			cg.stopTracking()
			cg.remove()
		}
	}()

	const ackLagLimit = int64(5 * time.Second)
	redactor := iolog.NewRedactor(getEffectiveMaskPatterns())

	const maxDeadBuf = 500 // max chunks buffered while server unreachable

	var (
		sessionAckMu    sync.Mutex
		sessionAckSeq   uint64
		serverConnAlive bool
		ackDebtStartNs  int64
		deadBuf         []outMsg // chunks buffered during server outage
	)
	var frozenSince time.Time

	updateAck := func(ts int64, seq uint64) {
		sessionAckMu.Lock()
		sessionAckSeq = seq
		ackDebtStartNs = 0
		sessionAckMu.Unlock()
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
	rawTCP.SetKeepAlive(true)
	rawTCP.SetKeepAlivePeriod(1 * time.Second)
	if sc, scErr := rawTCP.SyscallConn(); scErr == nil {
		sc.Control(func(fd uintptr) {
			syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_KEEPINTVL, 1)
			syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_KEEPCNT, 1)
		})
	}
	serverConn := tls.Client(rawTCP, tlsClientFor(tlsCfg, cfg.Server))
	if err := serverConn.Handshake(); err != nil {
		log.Printf("tls handshake: %v", err)
		rawTCP.Close()
		protocol.WriteMessage(pw, protocol.MsgSessionError, []byte(err.Error()))
		return
	}

	ttyPath := resolveTTYPath(start.TtyPath, start.Pid)

	markDead := func() {
		sessionAckMu.Lock()
		firstFreeze := serverConnAlive && frozenSince.IsZero()
		if serverConnAlive {
			frozenSince = time.Now()
		}
		serverConnAlive = false
		ackDebtStartNs = 0
		sessionAckMu.Unlock()
		cg.freeze()
		if firstFreeze {
			go writeTTYFreezeMsg(ttyPath, cfg.FreezeTimeout)
			go reportSessionFreezing(cfg.Server, tlsCfg, start.SessionID)
		}
	}

	markAlive := func() {
		sessionAckMu.Lock()
		wasAlive := serverConnAlive
		serverConnAlive = true
		ackDebtStartNs = 0
		buf := deadBuf
		deadBuf = nil
		sessionAckMu.Unlock()
		if !wasAlive {
			cg.unfreeze()
			for i, m := range buf {
				select {
				case bulkQueue <- m:
				case <-done:
					log.Printf("markAlive: session closed mid-drain, dropping %d buffered chunks", len(buf)-i)
					return
				}
			}
		}
	}

	resetFrozenStatus := func() {
		sessionAckMu.Lock()
		frozenSince = time.Time{}
		sessionAckMu.Unlock()
	}

	var pluginWriteMu sync.Mutex

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
					continue
				}
				if time.Since(since) < cfg.FreezeTimeout {
					continue
				}
				log.Printf("[%s] server unreachable for >%v — terminating frozen session",
					start.SessionID, cfg.FreezeTimeout)
				cg.unfreeze()
				pluginWriteMu.Lock()
				_ = protocol.WriteMessage(pw, protocol.MsgFreezeTimeout, nil)
				pluginWriteMu.Unlock()
				time.Sleep(200 * time.Millisecond)
				pluginConn.Close()
				go reportSessionAbandon(cfg.Server, tlsCfg, start.SessionID)
				return
			}
		}()
	}

	var lastInputNs atomic.Int64
	lastInputNs.Store(time.Now().UnixNano())
	if cfg.IdleTimeout > 0 {
		warnBefore := 60 * time.Second
		if warnBefore > cfg.IdleTimeout/2 {
			warnBefore = cfg.IdleTimeout / 2
		}
		tickerInterval := 10 * time.Second
		if cfg.IdleTimeout < tickerInterval {
			tickerInterval = cfg.IdleTimeout / 2
			if tickerInterval < 100*time.Millisecond {
				tickerInterval = 100 * time.Millisecond
			}
		}
		go func() {
			ticker := time.NewTicker(tickerInterval)
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
					writeTTYIdleWarnMsg(ttyPath, remaining)
					warned = true
				} else if warned && since < cfg.IdleTimeout-warnBefore {
					warned = false
				}
			}
		}()
	}

	var serverWriteMu sync.Mutex
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

	serverBuf := bufio.NewWriterSize(serverConn, 8*1024)
	sw := protocol.NewWriter(serverBuf, &serverWriteMu)
	if cg != nil {
		cg.serverW = sw
	}

	start.Command = redactor.RedactString(start.Command)
	start.ResolvedCommand = redactor.RedactString(start.ResolvedCommand)
	start.Source = "plugin"
	start.Groups = resolveUserGroups(start.User)
	startPayload, _ = json.Marshal(start)

	log.Printf("[%s] start user=%s host=%s pid=%d cmd=%s cgroup=%v tty=%s",
		start.SessionID, start.User, start.Host, start.Pid,
		truncate(start.Command, 60), cg != nil, ttyPath)
	if err := protocol.WriteMessage(serverBuf, protocol.MsgSessionStart, startPayload); err != nil {
		log.Printf("[%s] forward SESSION_START: %v", start.SessionID, err)
		markDead()
		protocol.WriteMessage(pw, protocol.MsgSessionError, []byte(err.Error()))
		return
	}

	serverConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	sr := bufio.NewReader(serverConn)

readHandshake:
	hsType, hsPlen, hsErr := protocol.ReadHeader(sr)
	serverConn.SetReadDeadline(time.Time{})

	if hsErr != nil {
		log.Printf("[%s] server handshake: %v", start.SessionID, hsErr)
		markDead()
		protocol.WriteMessage(pw, protocol.MsgSessionError, []byte(hsErr.Error()))
		return
	}
	switch hsType {
	case protocol.MsgSessionDenied:
		denyPayload, _ := protocol.ReadPayload(sr, hsPlen)
		log.Printf("[%s] session denied by server policy for user=%s host=%s",
			start.SessionID, start.User, start.Host)
		protocol.WriteMessage(pw, protocol.MsgSessionDenied, denyPayload)
		serverConn.Close()
		return
	case protocol.MsgSessionChallenge:
		challengePayload, _ := protocol.ReadPayload(sr, hsPlen)
		log.Printf("[%s] session challenge from server", start.SessionID)
		// Forward challenge to plugin
		if err := protocol.WriteMessage(pw, protocol.MsgSessionChallenge, challengePayload); err != nil {
			log.Printf("[%s] forward challenge: %v", start.SessionID, err)
			return
		}
		// Wait for response from plugin
		pluginConn.SetReadDeadline(time.Now().Add(60 * time.Second))
		respType, respPlen, respErr := protocol.ReadHeader(pr)
		pluginConn.SetReadDeadline(time.Time{})
		if respErr != nil {
			log.Printf("[%s] read challenge response from plugin: %v", start.SessionID, respErr)
			return
		}
		if respType != protocol.MsgSessionChallengeResponse {
			log.Printf("[%s] expected challenge response, got 0x%02x", start.SessionID, respType)
			return
		}
		respPayload, _ := protocol.ReadPayload(pr, respPlen)
		// Forward response to server
		if err := protocol.WriteMessage(serverBuf, protocol.MsgSessionChallengeResponse, respPayload); err != nil {
			log.Printf("[%s] forward challenge response: %v", start.SessionID, err)
			return
		}
		// Wait for next server response (Denied or ServerReady)
		serverConn.SetReadDeadline(time.Now().Add(10 * time.Second))
		goto readHandshake

	case protocol.MsgServerReady:
		srPayload, _ := protocol.ReadPayload(sr, hsPlen)
		var serverReady protocol.ServerReadyBody
		_ = json.Unmarshal(srPayload, &serverReady)
		sessionTTL := serverReady.SessionTTL
		cg.SetReady()
		protocol.WriteMessage(pw, protocol.MsgSessionReady, sessionReadyBody(cfg.Disclaimer, sessionTTL))
		if sessionTTL > 0 {
			go func() {
				// Calculate when to show the 60s warning.
				warnAfter := time.Duration(sessionTTL-60) * time.Second
				if sessionTTL <= 60 {
					// If window is very short, warn immediately or skip?
					// Let's warn at 10s if window is <= 60s.
					warnAfter = time.Duration(sessionTTL-10) * time.Second
				}
				if warnAfter < 0 {
					warnAfter = 0
				}

				select {
				case <-done:
					return
				case <-time.After(warnAfter):
					timeLeft := sessionTTL - int64(warnAfter.Seconds())
					log.Printf("[%s] session will expire in %ds — warning user", start.SessionID, timeLeft)
					pluginWriteMu.Lock()
					_ = protocol.WriteMessage(pw, protocol.MsgSessionWarning, []byte(fmt.Sprintf("%d", timeLeft)))
					pluginWriteMu.Unlock()
				}

				select {
				case <-done:
					return
				case <-time.After(time.Duration(sessionTTL)*time.Second - warnAfter):
				}

				log.Printf("[%s] session TTL expired (%ds) — terminating", start.SessionID, sessionTTL)
				cg.unfreeze()
				pluginWriteMu.Lock()
				_ = protocol.WriteMessage(pw, protocol.MsgSessionExpired, nil)
				pluginWriteMu.Unlock()
				time.Sleep(200 * time.Millisecond)
				pluginConn.Close()
			}()
		}
	default:
		log.Printf("[%s] unexpected server handshake type 0x%02x", start.SessionID, hsType)
		markDead()
		protocol.WriteMessage(pw, protocol.MsgSessionError,
			[]byte(fmt.Sprintf("unexpected server handshake 0x%02x", hsType)))
		return
	}

	go func() {
		defer senderWg.Done()
		drainAndExit := func() {
			serverWriteMu.Lock()
			defer serverWriteMu.Unlock()
			serverConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			for len(prioQueue) > 0 {
				m := <-prioQueue
				protocol.WriteMessageNoFlush(serverBuf, m.msgType, m.payload)
			}
			for len(bulkQueue) > 0 {
				m := <-bulkQueue
				protocol.WriteMessageNoFlush(serverBuf, m.msgType, m.payload)
			}
			serverBuf.Flush()
			serverConn.SetWriteDeadline(time.Time{})
		}
		for {
			var msg outMsg
			var ok bool
			select {
			case <-stopSender:
				drainAndExit()
				return
			case <-done:
				return
			case msg, ok = <-prioQueue:
			default:
				select {
				case <-stopSender:
					drainAndExit()
					return
				case <-done:
					return
				case msg, ok = <-prioQueue:
				case msg, ok = <-bulkQueue:
				}
			}
			if !ok {
				return
			}
			serverWriteMu.Lock()
			werr := protocol.WriteMessageNoFlush(serverBuf, msg.msgType, msg.payload)
			isPrio := msg.msgType != protocol.MsgChunk
			if !isPrio && len(msg.payload) > 16 {
				stream := msg.payload[16]
				isPrio = stream == protocol.StreamStdin || stream == protocol.StreamTtyIn
			}
			if werr == nil && (isPrio || (len(prioQueue) == 0 && len(bulkQueue) == 0)) {
				serverConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
				werr = serverBuf.Flush()
				serverConn.SetWriteDeadline(time.Time{})
			}
			serverWriteMu.Unlock()
			if werr != nil {
				log.Printf("[%s] forward to server: %v", start.SessionID, werr)
				markDead()
				return
			}
		}
	}()

	go func() {
		defer func() {
			serverConn.Close()
			markDead()
		}()
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
				if !verifyAckSig(ack, start.SessionID, verifyKey) {
					log.Printf("ack signature invalid seq=%d — ignoring", ack.Seq)
					continue
				}
				touchServerMsg()
				updateAck(time.Now().UnixNano(), ack.Seq)
			case protocol.MsgHeartbeatAck:
				touchServerMsg()
			}
		}
	}()

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
			if age > 15*hbInterval {
				consecutiveOK = 0
				markDead()
			} else {
				consecutiveOK++
				if consecutiveOK >= 2 {
					markAlive()
				}
				if consecutiveOK >= 25 {
					resetFrozenStatus()
				}
			}
		}
	}()

	forward := func(msgType uint8, payload []byte) {
		sessionAckMu.Lock()
		alive := serverConnAlive
		if !alive && msgType == protocol.MsgChunk {
			if len(deadBuf) < maxDeadBuf {
				deadBuf = append(deadBuf, outMsg{msgType: msgType, payload: payload})
			}
			sessionAckMu.Unlock()
			return
		}
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
			if err == nil && chunk.Stream <= protocol.StreamTtyOut {
				chunk.Data = redactor.Redact(chunk.Data, chunk.Stream)
				payload = protocol.EncodeChunk(chunk.Seq, chunk.Timestamp, chunk.Stream, chunk.Data)
			}
			if err == nil && (chunk.Stream == protocol.StreamStdin || chunk.Stream == protocol.StreamTtyIn) {
				lastInputNs.Store(time.Now().UnixNano())
			}
			forward(protocol.MsgChunk, payload)
		case protocol.MsgResize:
			forward(protocol.MsgResize, payload)
		case protocol.MsgSessionEnd:
			savedSessionEnd = payload
			break loop
		default:
			log.Printf("unknown message type 0x%02x len=%d — ignoring", msgType, plen)
		}
	}

	// Give the descendant tracker a moment to catch the first child fork
	// before we decide whether to enter linger mode. This is crucial for
	// commands like 'gvim' where the parent exits immediately after forking.
	time.Sleep(2 * time.Second)

	if cg.hasPids() || cg.hasEscapedRunning() {
		log.Printf("[%s] sudo exited but GUI processes remain; entering linger mode", start.SessionID)
		for cg.hasPids() || cg.hasEscapedRunning() {
			time.Sleep(1 * time.Second)
		}
		log.Printf("[%s] all GUI processes exited; finishing session", start.SessionID)
	}

	if savedSessionEnd != nil {
		forward(protocol.MsgSessionEnd, savedSessionEnd)
	}

	close(stopSender)
	senderWg.Wait()
	closeDone()
	sessionAckMu.Lock()
	serverConnAlive = false
	sessionAckMu.Unlock()
	serverConn.Close()
}

func lingerCgroup(cg *cgroupSession, server string, tlsCfg *tls.Config) {
	defer cg.stopTracking()
	defer cg.remove()
	log.Printf("cgroup %s: lingering (GUI processes remain)", cg.path)
	const pollInterval = 2 * time.Second
	const dialTimeout = 2 * time.Second
	serverReachable := func() bool {
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
			return
		}
		if serverReachable() {
			cg.unfreeze()
		} else {
			cg.freeze()
		}
	}
}

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

func applyColor(text, color string) string {
	text = strings.ReplaceAll(text, "\n", "\r\n")
	if codes, ok := ansiColors[color]; ok {
		return codes[0] + text + codes[1]
	}
	return text
}

func sessionReadyBody(disclaimer string, sessionTTL int64) []byte {
	var freezeSecs int64
	if cfg.FreezeTimeout > 0 {
		freezeSecs = int64(cfg.FreezeTimeout.Seconds())
	}
	if disclaimer == "" && sessionTTL == 0 && freezeSecs == 0 {
		return nil
	}
	body, _ := json.Marshal(protocol.SessionReadyBody{
		Disclaimer:        applyColor(disclaimer, cfg.DisclaimerColor),
		SessionTTL:        sessionTTL,
		FreezeTimeoutSecs: freezeSecs,
	})
	return body
}

func reportSessionAbandon(server string, tlsCfg *tls.Config, sessionID string) {
	reportSessionMsg(server, tlsCfg, sessionID, protocol.MsgSessionAbandon, 30*time.Second)
}

func reportSessionFreezing(server string, tlsCfg *tls.Config, sessionID string) {
	reportSessionMsg(server, tlsCfg, sessionID, protocol.MsgSessionFreezing, 10*time.Second)
}

func reportSessionMsg(server string, tlsCfg *tls.Config, sessionID string, msgType uint8, dialTimeout time.Duration) {
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
	tlsConn := tls.Client(rawTCP, tlsClientFor(tlsCfg, server))
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

func isSudoConn(conn net.Conn) bool {
	if os.Getenv("SUDO_LOGGER_INSECURE_TEST") == "1" {
		return true
	}
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return false
	}
	rawConn, err := uc.SyscallConn()
	if err != nil {
		return false
	}
	var uid = ^uint32(0)
	_ = rawConn.Control(func(fd uintptr) {
		ucred, soErr := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if soErr == nil {
			uid = ucred.Uid
		}
	})
	return uid == 0
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

var validSessionID = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,255}$`)

// sendDivergenceAlert sends a DIVERGENCE_ALERT to the log server with
// exponential backoff retries.  Called as a goroutine by the divergence tracker.
func sendDivergenceAlert(user, host, comm string, ts time.Time) {
	alert := protocol.DivergenceAlert{
		User: user,
		Host: host,
		Comm: comm,
		Ts:   ts.Unix(),
	}
	payload, err := json.Marshal(alert)
	if err != nil {
		log.Printf("divergence alert marshal: %v", err)
		return
	}

	const maxAttempts = 5
	delay := 5 * time.Second
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if err := trySendDivergenceAlert(payload); err == nil {
			return
		} else {
			log.Printf("divergence alert: attempt %d/%d failed: %v", attempt, maxAttempts, err)
		}
		if attempt < maxAttempts {
			time.Sleep(delay)
			delay *= 2
			if delay > 60*time.Second {
				delay = 60 * time.Second
			}
		}
	}
	log.Printf("divergence alert: all %d attempts failed — alert for user=%s host=%s lost", maxAttempts, user, host)
}

func trySendDivergenceAlert(payload []byte) error {
	conn, err := tls.Dial("tcp", cfg.Server, tlsCfg)
	if err != nil {
		return fmt.Errorf("dial %s: %w", cfg.Server, err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	w := bufio.NewWriter(conn)
	if err := protocol.WriteMessage(w, protocol.MsgDivergenceAlert, payload); err != nil {
		return fmt.Errorf("send: %w", err)
	}
	if err := w.Flush(); err != nil {
		return fmt.Errorf("flush: %w", err)
	}
	return nil
}
