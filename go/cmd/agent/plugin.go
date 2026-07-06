// plugin.go — Unix-socket plugin handler for sudo-logger-agent.
// Receives connections from the sudo C plugin and forwards them to the log
// server over TLS.  This is the same logic as the former sudo-logger-agent daemon.
package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
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

type outMsg struct {
	msgType uint8
	payload []byte
}

const sessionAckLagLimit = int64(5 * time.Second)
const maxDeadBuf = 500 // max chunks buffered while server unreachable

// sessionConn holds all per-connection state for one plugin<->agent<->server
// session: the socket handles, the shared ack/liveness bookkeeping guarded by
// sessionAckMu, and the queues/synchronization used by the sender, reader,
// heartbeat, idle-watch, and freeze-watch goroutines. Extracted from what was
// previously ~670 lines of closures inside handlePluginConn (review T1-1) so
// the concurrency model — which mutex guards what, which goroutine owns
// which field — is explicit instead of implicit in closure captures.
type sessionConn struct {
	pluginConn net.Conn
	pr         *bufio.Reader
	pw         *bufio.Writer

	start    *protocol.SessionStart
	cg       *cgroupSession
	redactor *iolog.Redactor
	ttyPath  string

	serverConn *tls.Conn
	serverBuf  *bufio.Writer
	sw         *protocol.Writer

	done       chan struct{}
	closeOnce  sync.Once
	stopSender chan struct{}
	senderWg   sync.WaitGroup

	prioQueue chan outMsg
	bulkQueue chan outMsg

	pluginWriteMu   sync.Mutex
	serverWriteMu   sync.Mutex
	lastServerMsgMu sync.Mutex
	lastServerMsg   time.Time

	// sessionAckMu guards the fields below: liveness bookkeeping shared
	// between the reader goroutine (updateAck), the heartbeat goroutine
	// (markDead/markAlive/resetFrozenStatus), forward() (deadBuf, called
	// from the main read loop), and the freeze-watch goroutine (frozenSince).
	sessionAckMu    sync.Mutex
	sessionAckSeq   uint64
	serverConnAlive bool
	ackDebtStartNs  int64
	deadBuf         []outMsg
	frozenSince     time.Time

	lastInputNs atomic.Int64
}

func (sc *sessionConn) close() {
	sc.closeOnce.Do(func() { close(sc.done) })
}

func (sc *sessionConn) updateAck(seq uint64) {
	sc.sessionAckMu.Lock()
	sc.sessionAckSeq = seq
	sc.ackDebtStartNs = 0
	sc.sessionAckMu.Unlock()
}

func (sc *sessionConn) readAck() (int64, uint64) {
	sc.sessionAckMu.Lock()
	defer sc.sessionAckMu.Unlock()
	if !sc.serverConnAlive {
		return 0, sc.sessionAckSeq
	}
	if sc.ackDebtStartNs > 0 && time.Now().UnixNano()-sc.ackDebtStartNs > sessionAckLagLimit {
		return 0, sc.sessionAckSeq
	}
	return time.Now().UnixNano(), sc.sessionAckSeq
}

func (sc *sessionConn) markDead() {
	sc.sessionAckMu.Lock()
	firstFreeze := sc.serverConnAlive && sc.frozenSince.IsZero()
	if sc.serverConnAlive {
		sc.frozenSince = time.Now()
	}
	sc.serverConnAlive = false
	sc.ackDebtStartNs = 0
	sc.sessionAckMu.Unlock()
	sc.cg.freeze()
	if firstFreeze {
		go writeTTYFreezeMsg(sc.ttyPath, cfg.FreezeTimeout)
		go reportSessionFreezing(cfg.Server, tlsCfg, sc.start.SessionID)
	}
}

func (sc *sessionConn) markAlive() {
	sc.sessionAckMu.Lock()
	wasAlive := sc.serverConnAlive
	// serverConnAlive flips to true before deadBuf is requeued below, so a
	// forward() call that races this unlock can push a live chunk onto
	// bulkQueue ahead of these buffered ones — the server disk-writer
	// appends to the cast file in dequeue order, not by seq, so a chunk
	// reordering here would show up as out-of-order events on replay.
	// This is a narrow window (a handful of goroutine-scheduling
	// instructions) right at reconnect, not sustained reordering.
	// Deliberately not fixed by holding sessionAckMu across the channel
	// sends below: bulkQueue can be full, and blocking here while holding
	// the lock would stall forward()/readAck/markDead for every other
	// chunk on this session, which is worse than the rare reorder.
	sc.serverConnAlive = true
	sc.ackDebtStartNs = 0
	buf := sc.deadBuf
	sc.deadBuf = nil
	sc.sessionAckMu.Unlock()
	if !wasAlive {
		sc.cg.unfreeze()
		for i, m := range buf {
			select {
			case sc.bulkQueue <- m:
			case <-sc.done:
				log.Printf("markAlive: session closed mid-drain, dropping %d buffered chunks", len(buf)-i)
				return
			}
		}
	}
}

func (sc *sessionConn) resetFrozenStatus() {
	sc.sessionAckMu.Lock()
	sc.frozenSince = time.Time{}
	sc.sessionAckMu.Unlock()
}

func (sc *sessionConn) touchServerMsg() {
	sc.lastServerMsgMu.Lock()
	sc.lastServerMsg = time.Now()
	sc.lastServerMsgMu.Unlock()
}

func (sc *sessionConn) forward(msgType uint8, payload []byte) {
	sc.sessionAckMu.Lock()
	alive := sc.serverConnAlive
	if !alive && msgType == protocol.MsgChunk {
		if len(sc.deadBuf) < maxDeadBuf {
			sc.deadBuf = append(sc.deadBuf, outMsg{msgType: msgType, payload: payload})
		}
		sc.sessionAckMu.Unlock()
		return
	}
	sc.sessionAckMu.Unlock()
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
		case sc.prioQueue <- msg:
		case <-sc.done:
		}
	} else {
		select {
		case sc.bulkQueue <- msg:
		case <-sc.done:
		}
	}
	if msgType == protocol.MsgChunk {
		sc.sessionAckMu.Lock()
		if sc.ackDebtStartNs == 0 {
			sc.ackDebtStartNs = time.Now().UnixNano()
		}
		sc.sessionAckMu.Unlock()
	}
}

// runFreezeWatch terminates the session if the server connection has been
// dead (frozen) for longer than cfg.FreezeTimeout. Caller only starts this
// goroutine when FreezeTimeout > 0.
func (sc *sessionConn) runFreezeWatch() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-sc.done:
			return
		case <-ticker.C:
		}
		sc.sessionAckMu.Lock()
		since := sc.frozenSince
		sc.sessionAckMu.Unlock()
		if since.IsZero() {
			continue
		}
		if time.Since(since) < cfg.FreezeTimeout {
			continue
		}
		log.Printf("[%s] server unreachable for >%v — terminating frozen session",
			sc.start.SessionID, cfg.FreezeTimeout)
		sc.cg.unfreeze()
		sc.pluginWriteMu.Lock()
		_ = protocol.WriteMessage(sc.pw, protocol.MsgFreezeTimeout, nil)
		sc.pluginWriteMu.Unlock()
		time.Sleep(200 * time.Millisecond)
		sc.pluginConn.Close()
		go reportSessionAbandon(cfg.Server, tlsCfg, sc.start.SessionID)
		return
	}
}

// runIdleWatch terminates the session if no stdin/tty-in has been seen for
// cfg.IdleTimeout, warning the user shortly before. Caller only starts this
// goroutine when IdleTimeout > 0.
func (sc *sessionConn) runIdleWatch() {
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
	ticker := time.NewTicker(tickerInterval)
	defer ticker.Stop()
	warned := false
	for {
		select {
		case <-sc.done:
			return
		case <-ticker.C:
		}
		since := time.Since(time.Unix(0, sc.lastInputNs.Load()))
		if since >= cfg.IdleTimeout {
			log.Printf("[%s] no input for %v — terminating idle session (pid %d)",
				sc.start.SessionID, since.Round(time.Second), sc.start.Pid)
			go writeTTYIdleMsg(sc.ttyPath, cfg.IdleTimeout)
			time.Sleep(200 * time.Millisecond)
			syscall.Kill(sc.start.Pid, syscall.SIGHUP)
			time.Sleep(1 * time.Second)
			sc.pluginConn.Close()
			return
		}
		if !warned && since >= cfg.IdleTimeout-warnBefore {
			remaining := cfg.IdleTimeout - since
			writeTTYIdleWarnMsg(sc.ttyPath, remaining)
			warned = true
		} else if warned && since < cfg.IdleTimeout-warnBefore {
			warned = false
		}
	}
}

// runTTLWatch warns the user shortly before, then terminates the session
// when, the server-granted JIT approval window (sessionTTL seconds) expires.
// Caller only starts this goroutine when sessionTTL > 0.
func (sc *sessionConn) runTTLWatch(sessionTTL int64) {
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
	case <-sc.done:
		return
	case <-time.After(warnAfter):
		timeLeft := sessionTTL - int64(warnAfter.Seconds())
		log.Printf("[%s] session will expire in %ds — warning user", sc.start.SessionID, timeLeft)
		sc.pluginWriteMu.Lock()
		_ = protocol.WriteMessage(sc.pw, protocol.MsgSessionWarning, []byte(fmt.Sprintf("%d", timeLeft)))
		sc.pluginWriteMu.Unlock()
	}

	select {
	case <-sc.done:
		return
	case <-time.After(time.Duration(sessionTTL)*time.Second - warnAfter):
	}

	log.Printf("[%s] session TTL expired (%ds) — terminating", sc.start.SessionID, sessionTTL)
	sc.cg.unfreeze()
	sc.pluginWriteMu.Lock()
	_ = protocol.WriteMessage(sc.pw, protocol.MsgSessionExpired, nil)
	sc.pluginWriteMu.Unlock()
	time.Sleep(200 * time.Millisecond)
	sc.pluginConn.Close()
}

// runSender drains prioQueue/bulkQueue (priority first) and writes each
// message to the server, flushing after priority messages or when both
// queues are empty. On stopSender it drains whatever remains before
// returning so no already-queued data is lost.
func (sc *sessionConn) runSender() {
	defer sc.senderWg.Done()
	drainAndExit := func() {
		sc.serverWriteMu.Lock()
		defer sc.serverWriteMu.Unlock()
		sc.serverConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		for len(sc.prioQueue) > 0 {
			m := <-sc.prioQueue
			protocol.WriteMessageNoFlush(sc.serverBuf, m.msgType, m.payload)
		}
		for len(sc.bulkQueue) > 0 {
			m := <-sc.bulkQueue
			protocol.WriteMessageNoFlush(sc.serverBuf, m.msgType, m.payload)
		}
		sc.serverBuf.Flush()
		sc.serverConn.SetWriteDeadline(time.Time{})
	}
	for {
		var msg outMsg
		var ok bool
		select {
		case <-sc.stopSender:
			drainAndExit()
			return
		case <-sc.done:
			return
		case msg, ok = <-sc.prioQueue:
		default:
			select {
			case <-sc.stopSender:
				drainAndExit()
				return
			case <-sc.done:
				return
			case msg, ok = <-sc.prioQueue:
			case msg, ok = <-sc.bulkQueue:
			}
		}
		if !ok {
			return
		}
		sc.serverWriteMu.Lock()
		werr := protocol.WriteMessageNoFlush(sc.serverBuf, msg.msgType, msg.payload)
		isPrio := msg.msgType != protocol.MsgChunk
		if !isPrio && len(msg.payload) > 16 {
			stream := msg.payload[16]
			isPrio = stream == protocol.StreamStdin || stream == protocol.StreamTtyIn
		}
		if werr == nil && (isPrio || (len(sc.prioQueue) == 0 && len(sc.bulkQueue) == 0)) {
			sc.serverConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			werr = sc.serverBuf.Flush()
			sc.serverConn.SetWriteDeadline(time.Time{})
		}
		sc.serverWriteMu.Unlock()
		if werr != nil {
			log.Printf("[%s] forward to server: %v", sc.start.SessionID, werr)
			sc.markDead()
			return
		}
	}
}

// runReaderACK reads ACK/HEARTBEAT_ACK messages from the server connection
// (via sr) until it errors or the connection closes, verifying each ACK's
// signature and updating liveness bookkeeping. The deferred close+markDead
// is what unblocks runSender/runHeartbeat when the server connection drops
// out from under them.
func (sc *sessionConn) runReaderACK(sr *bufio.Reader) {
	defer func() {
		sc.serverConn.Close()
		sc.markDead()
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
			if !verifyAckSig(ack, sc.start.SessionID, verifyKey) {
				log.Printf("ack signature invalid seq=%d — ignoring", ack.Seq)
				continue
			}
			sc.touchServerMsg()
			sc.updateAck(ack.Seq)
		case protocol.MsgHeartbeatAck:
			sc.touchServerMsg()
		}
	}
}

// runHeartbeat sends a HEARTBEAT every hbInterval and, based on how long
// it's been since the server last spoke (touchServerMsg), decides whether
// to markDead/markAlive/resetFrozenStatus.
func (sc *sessionConn) runHeartbeat() {
	const hbInterval = 400 * time.Millisecond
	ticker := time.NewTicker(hbInterval)
	defer ticker.Stop()
	consecutiveOK := 0
	for {
		select {
		case <-sc.done:
			return
		case <-ticker.C:
		}
		select {
		case sc.prioQueue <- outMsg{msgType: protocol.MsgHeartbeat}:
		case <-sc.done:
			return
		default:
			// queue is full, drop heartbeat to prevent block
		}
		sc.lastServerMsgMu.Lock()
		age := time.Since(sc.lastServerMsg)
		sc.lastServerMsgMu.Unlock()
		if age > 15*hbInterval {
			consecutiveOK = 0
			sc.markDead()
		} else {
			consecutiveOK++
			if consecutiveOK >= 2 {
				sc.markAlive()
			}
			if consecutiveOK >= 25 {
				sc.resetFrozenStatus()
			}
		}
	}
}

// doHandshake performs the SESSION_START -> {Denied,Challenge,ServerReady}
// exchange with the server, forwarding challenge/response between the
// plugin and the server as needed. Returns an error (already reported to
// the plugin and/or logged) if the caller should stop and return; nil once
// SESSION_READY has been sent to the plugin and it's safe to start the
// sender/reader/heartbeat goroutines.
func (sc *sessionConn) doHandshake(sr *bufio.Reader) error {
	sc.serverConn.SetReadDeadline(time.Now().Add(10 * time.Second))

readHandshake:
	hsType, hsPlen, hsErr := protocol.ReadHeader(sr)
	sc.serverConn.SetReadDeadline(time.Time{})

	if hsErr != nil {
		log.Printf("[%s] server handshake: %v", sc.start.SessionID, hsErr)
		sc.markDead()
		protocol.WriteMessage(sc.pw, protocol.MsgSessionError, []byte(hsErr.Error()))
		return hsErr
	}
	switch hsType {
	case protocol.MsgSessionDenied:
		denyPayload, _ := protocol.ReadPayload(sr, hsPlen)
		log.Printf("[%s] session denied by server policy for user=%s host=%s",
			sc.start.SessionID, sc.start.User, sc.start.Host)
		protocol.WriteMessage(sc.pw, protocol.MsgSessionDenied, denyPayload)
		sc.serverConn.Close()
		return fmt.Errorf("session denied")

	case protocol.MsgSessionChallenge:
		challengePayload, _ := protocol.ReadPayload(sr, hsPlen)
		log.Printf("[%s] session challenge from server", sc.start.SessionID)
		// Forward challenge to plugin
		if err := protocol.WriteMessage(sc.pw, protocol.MsgSessionChallenge, challengePayload); err != nil {
			log.Printf("[%s] forward challenge: %v", sc.start.SessionID, err)
			return err
		}
		// Wait for response from plugin
		sc.pluginConn.SetReadDeadline(time.Now().Add(60 * time.Second))
		respType, respPlen, respErr := protocol.ReadHeader(sc.pr)
		sc.pluginConn.SetReadDeadline(time.Time{})
		if respErr != nil {
			log.Printf("[%s] read challenge response from plugin: %v", sc.start.SessionID, respErr)
			return respErr
		}
		if respType != protocol.MsgSessionChallengeResponse {
			log.Printf("[%s] expected challenge response, got 0x%02x", sc.start.SessionID, respType)
			return fmt.Errorf("unexpected response type 0x%02x", respType)
		}
		respPayload, _ := protocol.ReadPayload(sc.pr, respPlen)
		// Forward response to server
		if err := protocol.WriteMessage(sc.serverBuf, protocol.MsgSessionChallengeResponse, respPayload); err != nil {
			log.Printf("[%s] forward challenge response: %v", sc.start.SessionID, err)
			return err
		}
		// Wait for next server response (Denied or ServerReady)
		sc.serverConn.SetReadDeadline(time.Now().Add(10 * time.Second))
		goto readHandshake

	case protocol.MsgServerReady:
		srPayload, _ := protocol.ReadPayload(sr, hsPlen)
		var serverReady protocol.ServerReadyBody
		_ = json.Unmarshal(srPayload, &serverReady)
		sessionTTL := serverReady.SessionTTL
		sc.cg.SetReady()
		protocol.WriteMessage(sc.pw, protocol.MsgSessionReady, sessionReadyBody(cfg.Disclaimer, sessionTTL))
		if sessionTTL > 0 {
			go sc.runTTLWatch(sessionTTL)
		}
		return nil

	default:
		log.Printf("[%s] unexpected server handshake type 0x%02x", sc.start.SessionID, hsType)
		sc.markDead()
		protocol.WriteMessage(sc.pw, protocol.MsgSessionError,
			[]byte(fmt.Sprintf("unexpected server handshake 0x%02x", hsType)))
		return fmt.Errorf("unexpected handshake type 0x%02x", hsType)
	}
}

// handlePluginConn manages one sudo session end-to-end.
func handlePluginConn(pluginConn net.Conn) {
	sc := &sessionConn{
		pluginConn: pluginConn,
		done:       make(chan struct{}),
		stopSender: make(chan struct{}),
		prioQueue:  make(chan outMsg, 100),
		bulkQueue:  make(chan outMsg, 10000),
	}
	defer pluginConn.Close()
	defer sc.close()

	sc.pr = bufio.NewReader(pluginConn)
	sc.pw = bufio.NewWriter(pluginConn)

	pluginConn.SetReadDeadline(time.Now().Add(30 * time.Second))
	msgType, plen, err := protocol.ReadHeader(sc.pr)
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
	startPayload, err := protocol.ReadPayload(sc.pr, plen)
	if err != nil {
		log.Printf("read SESSION_START payload: %v", err)
		return
	}
	start, err := protocol.ParseSessionStart(startPayload)
	if err != nil {
		log.Printf("parse SESSION_START: %v", err)
		return
	}
	sc.start = start

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
	sc.cg = cg
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
			go lingerCgroup(cg, cfg.Server)
		} else {
			cg.stopTracking()
			cg.remove()
		}
	}()

	sc.redactor = iolog.MustNewRedactor(getEffectiveMaskPatterns())

	tcpAddr, err := net.ResolveTCPAddr("tcp", cfg.Server)
	if err != nil {
		log.Printf("resolve server addr: %v", err)
		protocol.WriteMessage(sc.pw, protocol.MsgSessionError, []byte(err.Error()))
		return
	}
	rawTCP, err := net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		log.Printf("dial server: %v", err)
		protocol.WriteMessage(sc.pw, protocol.MsgSessionError, []byte(err.Error()))
		return
	}
	rawTCP.SetKeepAlive(true)
	rawTCP.SetKeepAlivePeriod(1 * time.Second)
	if scc, sccErr := rawTCP.SyscallConn(); sccErr == nil {
		scc.Control(func(fd uintptr) {
			syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_KEEPINTVL, 1)
			syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_KEEPCNT, 1)
		})
	}
	serverConn := tls.Client(rawTCP, tlsClientFor(tlsCfg, cfg.Server))
	if err := serverConn.Handshake(); err != nil {
		log.Printf("tls handshake: %v", err)
		rawTCP.Close()
		protocol.WriteMessage(sc.pw, protocol.MsgSessionError, []byte(err.Error()))
		return
	}
	sc.serverConn = serverConn

	sc.ttyPath = resolveTTYPath(start.TtyPath, start.Pid)

	if cfg.FreezeTimeout > 0 {
		go sc.runFreezeWatch()
	}

	sc.lastInputNs.Store(time.Now().UnixNano())
	if cfg.IdleTimeout > 0 {
		go sc.runIdleWatch()
	}

	sc.lastServerMsg = time.Now()

	sc.sessionAckMu.Lock()
	sc.serverConnAlive = true
	sc.sessionAckMu.Unlock()

	sc.serverBuf = bufio.NewWriterSize(serverConn, 8*1024)
	sc.sw = protocol.NewWriter(sc.serverBuf, &sc.serverWriteMu)
	if cg != nil {
		cg.serverW = sc.sw
	}
	// The SESSION_START and CHALLENGE_RESPONSE writes below go straight to
	// serverBuf, bypassing sw/serverWriteMu. That's safe only because they
	// happen here, before the sender goroutine (which also writes to
	// serverBuf, via sw) is started further down. If a write is ever added
	// to this handshake section after the sender goroutine starts, it must
	// go through sw instead.

	start.Command = sc.redactor.RedactString(start.Command)
	start.ResolvedCommand = sc.redactor.RedactString(start.ResolvedCommand)
	start.Source = "plugin"
	start.Groups = resolveUserGroups(start.User)
	startPayload, _ = json.Marshal(start)

	log.Printf("[%s] start user=%s host=%s pid=%d cmd=%s cgroup=%v tty=%s",
		start.SessionID, start.User, start.Host, start.Pid,
		truncate(start.Command, 60), cg != nil, sc.ttyPath)
	if err := protocol.WriteMessage(sc.serverBuf, protocol.MsgSessionStart, startPayload); err != nil {
		log.Printf("[%s] forward SESSION_START: %v", start.SessionID, err)
		sc.markDead()
		protocol.WriteMessage(sc.pw, protocol.MsgSessionError, []byte(err.Error()))
		return
	}

	sr := bufio.NewReader(serverConn)
	if err := sc.doHandshake(sr); err != nil {
		return
	}

	sc.senderWg.Add(1)
	go sc.runSender()
	go sc.runReaderACK(sr)
	go sc.runHeartbeat()

	var savedSessionEnd []byte
loop:
	for {
		msgType, plen, err := protocol.ReadHeader(sc.pr)
		if err != nil {
			break loop
		}
		payload, err := protocol.ReadPayload(sc.pr, plen)
		if err != nil {
			break loop
		}
		switch msgType {
		case protocol.MsgAckQuery:
			ts, seq := sc.readAck()
			resp := protocol.EncodeAckResponse(ts, seq)
			sc.pluginWriteMu.Lock()
			err := protocol.WriteMessage(sc.pw, protocol.MsgAckResponse, resp)
			sc.pluginWriteMu.Unlock()
			if err != nil {
				log.Printf("write ack response: %v", err)
				break loop
			}
		case protocol.MsgChunk:
			chunk, err := protocol.ParseChunk(payload)
			if err != nil {
				// Never forward a chunk we couldn't parse: it never went
				// through the redactor, so it could carry an unmasked
				// secret. Drop it rather than risk shipping raw bytes.
				log.Printf("[%s] drop malformed CHUNK (%d bytes): %v", start.SessionID, len(payload), err)
				continue loop
			}
			if chunk.Stream <= protocol.StreamTtyOut {
				data, buffering := sc.redactor.Redact(chunk.Data, chunk.Stream)
				if buffering {
					continue loop
				}
				chunk.Data = data
				payload = protocol.EncodeChunk(chunk.Seq, chunk.Timestamp, chunk.Stream, chunk.Data)
			}
			if chunk.Stream == protocol.StreamStdin || chunk.Stream == protocol.StreamTtyIn {
				sc.lastInputNs.Store(time.Now().UnixNano())
			}
			sc.forward(protocol.MsgChunk, payload)
		case protocol.MsgResize:
			sc.forward(protocol.MsgResize, payload)
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

	// Flush any PEM blocks still open when the session ended (e.g. -----END
	// never arrived due to kill/truncation). Best-effort redaction on partial data.
	for _, stream := range []uint8{protocol.StreamStdout, protocol.StreamTtyOut, protocol.StreamStderr} {
		if flushed := sc.redactor.FlushPEM(stream); flushed != nil {
			p := protocol.EncodeChunk(0, time.Now().UnixNano(), stream, flushed)
			sc.forward(protocol.MsgChunk, p)
		}
	}

	if savedSessionEnd != nil {
		sc.forward(protocol.MsgSessionEnd, savedSessionEnd)
	}

	close(sc.stopSender)
	sc.senderWg.Wait()
	sc.close()
	sc.sessionAckMu.Lock()
	sc.serverConnAlive = false
	sc.sessionAckMu.Unlock()
	serverConn.Close()
}
func lingerCgroup(cg *cgroupSession, server string) {
	defer cg.stopTracking()
	defer cg.remove()
	log.Printf("cgroup %s: lingering (GUI processes remain)", cg.path)
	const pollInterval = 2 * time.Second
	const dialTimeout = 2 * time.Second
	// Bound how long we track a lingering session: a GUI process that never
	// exits would otherwise keep this goroutine (and its periodic dial probe)
	// running for the lifetime of the agent.
	const maxLinger = 24 * time.Hour
	deadline := time.Now().Add(maxLinger)
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
		if time.Now().After(deadline) {
			log.Printf("cgroup %s: linger exceeded %s, stopping tracking", cg.path, maxLinger)
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
	// Give the TLS close_notify a brief window to reach the server before the
	// deferred Close() tears down the connection, instead of racing it.
	tlsConn.SetReadDeadline(time.Now().Add(1 * time.Second))
	_, _ = tlsConn.Read(make([]byte, 1))
	log.Printf("[%s] %s sent to server", sessionID, label)
}

func isSudoConn(conn net.Conn) bool {
	// Bypass gated on running inside `go test` (flag.Lookup("test.v") is only
	// non-nil in a test binary, since only the testing package registers it)
	// as well as the env var, so it cannot be triggered in a production
	// binary even if the env var leaks into the unit file. Same idiom as
	// siem/sender.go's test-only loopback allowance.
	if flag.Lookup("test.v") != nil && os.Getenv("SUDO_LOGGER_INSECURE_TEST") == "1" {
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
