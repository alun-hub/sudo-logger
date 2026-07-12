package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"sudo-logger/internal/protocol"
	"sudo-logger/internal/util"
)

// maxOverflow bounds the number of overflow goroutines processChunk can spawn
// once diskQueue's primary buffer (see handler.go) is full, before falling
// back to blocking backpressure. Combined with diskQueue's capacity, this
// caps worst-case per-connection memory at roughly
// (diskQueue capacity + maxOverflow) * MaxChunkPayload -- real chunk sizes
// are far smaller than that cap in practice, so this still leaves generous
// headroom over normal bursty load.
const maxOverflow = 200

type diskTask struct {
	msgType uint8
	payload []byte
}

type sessionConn struct {
	srv              *server
	conn             *tls.Conn
	remote           string
	r                *bufio.Reader
	w                *bufio.Writer
	netWriteMu       sync.Mutex
	sess             *session
	diskSess         atomic.Pointer[session]
	start            *protocol.SessionStart
	sendMu           sync.Mutex
	sendCond         *sync.Cond
	pendingSeq       uint64
	pendingHeartbeat bool
	senderClosed     bool
	sessionID        string
	diskQueue        chan diskTask
	diskDone         chan struct{}
	diskWg           sync.WaitGroup
	overflowWg       sync.WaitGroup
	overflowCount    atomic.Int32
	diskCloseOnce    sync.Once
}

func (s *sessionConn) closeDisk() {
	s.diskCloseOnce.Do(func() {
		// Signal overflow goroutines to abort before closing diskQueue.
		// Overflow goroutines select on diskQueue or diskDone; closing
		// diskDone unblocks them without triggering a "send on closed
		// channel" panic that would crash the server.
		close(s.diskDone)
		// Wait for all overflow goroutines to exit cleanly before closing diskQueue.
		s.overflowWg.Wait()
		close(s.diskQueue)
		s.diskWg.Wait()
	})
}

func (s *sessionConn) run() {
	defer s.conn.Close()

	s.startDiskWriter()
	s.coalesceACKs()

	defer func() {
		// Signal and wait for disk writer to finish
		s.closeDisk()

		s.sendMu.Lock()
		s.senderClosed = true
		s.sendCond.Signal()
		s.sendMu.Unlock()
	}()

	for {
		msgType, plen, err := protocol.ReadHeader(s.r)
		if err != nil {
			// CRITICAL: Stop the background writer and wait for all data to hit disk
			// BEFORE we decide if the session was successful or not.
			s.closeDisk()

			if s.sess != nil {
				if s.sess.freezeCandidate {
					log.Printf("[%s] %s connection lost after SESSION_FREEZING — marking network outage",
						s.sess.id, s.remote)
					_ = s.sess.writer.MarkNetworkOutage()
				} else {
					log.Printf("SECURITY: [%s] %s dropped connection without session_end — session may be incomplete (agent killed?): %v",
						s.sess.id, s.remote, err)
					_ = s.sess.writer.MarkIncomplete()
				}
				s.srv.sessionsIncomplete.Add(1)
				s.srv.closeSession(s.sess)
			}
			return
		}

		// SESSION_START is JSON metadata — apply a tighter size limit to prevent
		// a malicious (mTLS-authenticated) agent from triggering a 1 MB allocation.
		if msgType == protocol.MsgSessionStart && plen > protocol.MaxSessionStartPayload {
			log.Printf("SECURITY: SESSION_START payload too large from %s: %d bytes (max %d) — dropping connection",
				s.remote, plen, protocol.MaxSessionStartPayload)
			return
		}

		if msgType == protocol.MsgSudoersSnapshot && plen > protocol.MaxSudoersPayload {
			log.Printf("SECURITY: MsgSudoersSnapshot too large from %s: %d bytes (max %d) — dropping",
				s.remote, plen, protocol.MaxSudoersPayload)
			return
		}

		payload, err := protocol.ReadPayload(s.r, plen)
		if err != nil {
			log.Printf("read payload from %s: %v", s.remote, err)
			return
		}

		if err := s.handleMessage(msgType, payload); err != nil {
			return
		}
	}
}

func (s *sessionConn) startDiskWriter() {
	s.diskWg.Add(1)
	go func() {
		defer s.diskWg.Done()
		for {
			task, ok := <-s.diskQueue
			if !ok {
				return
			}

			// Collect a batch of up to 100 available tasks to reduce I/O overhead
			batch := []diskTask{task}
		collect:
			for i := 0; i < 99; i++ {
				select {
				case t, ok := <-s.diskQueue:
					if !ok {
						break collect
					}
					batch = append(batch, t)
				default:
					break collect // No more immediately available
				}
			}

			ds := s.diskSess.Load()
			if ds == nil {
				// No session opened yet; discard tasks
				continue
			}
			sid := ds.id

			var lastSeq uint64
			for _, t := range batch {
				if t.msgType == protocol.MsgResize {
					if ds != nil {
						resize, err := protocol.ParseResize(t.payload)
						if err != nil {
							log.Printf("[%s] disk-writer parse resize: %v", sid, err)
							continue
						}
						if err := ds.writer.WriteResize(resize.Cols, resize.Rows, resize.Timestamp); err != nil {
							log.Printf("[%s] write resize: %v", sid, err)
						}
					}
					continue
				}

				chunk, err := protocol.ParseChunk(t.payload)
				if err != nil {
					log.Printf("[%s] disk-writer parse chunk: %v", sid, err)
					continue
				}

				// Perform actual disk/S3 I/O
				if ds != nil {
					switch chunk.Stream {
					case protocol.StreamTtyOut, protocol.StreamStdout, protocol.StreamStderr:
						if err := ds.writer.WriteOutput(chunk.Data, chunk.Timestamp); err != nil {
							log.Printf("[%s] write output: %v", sid, err)
						}
					case protocol.StreamTtyIn, protocol.StreamStdin:
						if err := ds.writer.WriteInput(chunk.Data, chunk.Timestamp); err != nil {
							log.Printf("[%s] write input: %v", sid, err)
						}
					}
					atomic.StoreUint64(&ds.lastSeq, chunk.Seq)
					lastSeq = chunk.Seq
				}
			}

			if ds != nil {
				_ = ds.writer.Flush()
			}

			// ONLY NOW that the batch is on disk, we signal the ACK coalescer
			if lastSeq > 0 {
				s.sendMu.Lock()
				s.pendingSeq = lastSeq
				s.sendCond.Signal()
				s.sendMu.Unlock()
			}
		}
	}()
}

func (s *sessionConn) coalesceACKs() {
	go func() {
		for {
			s.sendMu.Lock()
			for s.pendingSeq == 0 && !s.pendingHeartbeat && !s.senderClosed {
				s.sendCond.Wait()
			}
			if s.senderClosed {
				s.sendMu.Unlock()
				return
			}
			seq := s.pendingSeq
			s.pendingSeq = 0
			hb := s.pendingHeartbeat
			s.pendingHeartbeat = false
			sid := s.sessionID
			s.sendMu.Unlock()

			if seq > 0 {
				ackPayload := s.srv.buildACK(sid, seq)
				s.netWriteMu.Lock()
				err := protocol.WriteMessage(s.w, protocol.MsgAck, ackPayload)
				s.netWriteMu.Unlock()
				if err != nil {
					log.Printf("[%s] write ack (async): %v", sid, err)
					return
				}
			}
			if hb {
				s.netWriteMu.Lock()
				err := protocol.WriteMessage(s.w, protocol.MsgHeartbeatAck, nil)
				s.netWriteMu.Unlock()
				if err != nil {
					log.Printf("[%s] write hb ack (async): %v", sid, err)
					return
				}
			}
		}
	}()
}

func (s *sessionConn) processSessionStart(payload []byte) error {
	if s.sess != nil {
		log.Printf("SECURITY: duplicate session start attempt from %s — dropping connection", s.remote)
		return fmt.Errorf("duplicate session start")
	}
	var err error
	s.start, err = protocol.ParseSessionStart(payload)
	if err != nil {
		log.Printf("parse session start from %s: %v", s.remote, err)
		return err
	}
	s.start.User = util.SanitizeForLog(s.start.User)
	s.start.Host = util.SanitizeForLog(s.start.Host)

	certs := s.conn.ConnectionState().PeerCertificates
	if len(certs) > 0 && !certMatchesHost(certs[0], s.start.Host) {
		if *flagStrictCertHost {
			log.Printf("SECURITY: %s claimed host=%q but cert CN=%q DNSNames=%v — closing",
				s.remote, s.start.Host, certs[0].Subject.CommonName, certs[0].DNSNames)
			return fmt.Errorf("strict cert host mismatch")
		}
		log.Printf("WARNING: %s claimed host=%q but cert CN=%q DNSNames=%v (use -strict-cert-host to enforce)",
			s.remote, s.start.Host, certs[0].Subject.CommonName, certs[0].DNSNames)
	}

	blocked, msg, err := s.srv.sessionStore.IsBlocked(context.Background(), s.start.User, s.start.Host)
	if err != nil {
		log.Printf("SECURITY: [%s] block policy check failed for user=%s host=%s: %v",
			s.start.SessionID, s.start.User, s.start.Host, err)
		s.netWriteMu.Lock()
		_ = protocol.WriteMessage(s.w, protocol.MsgSessionError, []byte("internal block check error"))
		s.netWriteMu.Unlock()
		return err
	}
	if blocked {
		log.Printf("SECURITY: [%s] user=%s host=%s denied by block policy",
			s.start.SessionID, s.start.User, s.start.Host)
		s.netWriteMu.Lock()
		_ = protocol.WriteMessage(s.w, protocol.MsgSessionDenied, []byte(msg))
		s.netWriteMu.Unlock()
		return fmt.Errorf("denied by block policy")
	}

	var result CheckResult
	whitelisted, err := s.srv.sessionStore.IsWhitelisted(context.Background(), s.start.User, s.start.Host)
	if err != nil {
		log.Printf("SECURITY: [%s] whitelist check failed for user=%s host=%s: %v",
			s.start.SessionID, s.start.User, s.start.Host, err)
		s.netWriteMu.Lock()
		_ = protocol.WriteMessage(s.w, protocol.MsgSessionError, []byte("internal whitelist check error"))
		s.netWriteMu.Unlock()
		return err
	}
	if whitelisted {
		log.Printf("[%s] whitelist: user=%s host=%s — bypassing JIT approval", s.start.SessionID, s.start.User, s.start.Host)
	} else {
		result = s.srv.approvalMgr.Check(s.start.User, s.start.Host, s.start.RunasUser, s.start.Command,
			s.start.Groups, s.start.Justification)
		switch result.Result {
		case ApprovalResultNeedReason:
			if msg := s.srv.approvalMgr.RetryMessage(s.start.User, s.start.Host); msg != "" {
				s.netWriteMu.Lock()
				_ = protocol.WriteMessage(s.w, protocol.MsgSessionDenied, []byte(msg))
				s.netWriteMu.Unlock()
			} else {
				s.netWriteMu.Lock()
				_ = protocol.WriteMessage(s.w, protocol.MsgSessionDenied, []byte(
					"sudo-logger: access requires justification. Run sudo again and provide a reason when prompted."))
				s.netWriteMu.Unlock()
			}
			log.Printf("[%s] approval: user=%s host=%s — no justification provided", s.start.SessionID, s.start.User, s.start.Host)
			return fmt.Errorf("justification required")
		case ApprovalResultChallenge:
			if s.start.TtyPath == "" {
				s.netWriteMu.Lock()
				_ = protocol.WriteMessage(s.w, protocol.MsgSessionDenied, []byte(
					"sudo-logger: access requires justification. Provide reason via sudo-logger-agent or retry interactively."))
				s.netWriteMu.Unlock()
				log.Printf("[%s] approval: user=%s host=%s — non-TTY session requires justification", s.start.SessionID, s.start.User, s.start.Host)
				return fmt.Errorf("non-TTY session requires justification")
			}
			challenge := protocol.SessionChallenge{HasWebhook: result.HasWebhook}
			body, _ := json.Marshal(challenge)
			s.netWriteMu.Lock()
			_ = protocol.WriteMessage(s.w, protocol.MsgSessionChallenge, body)
			s.netWriteMu.Unlock()
			log.Printf("[%s] approval: user=%s host=%s — challenge sent", s.start.SessionID, s.start.User, s.start.Host)
			return nil
		case ApprovalResultPending:
			msg := fmt.Sprintf("sudo-logger: approval request %s submitted.\nYou will be notified when approved. Retry sudo when notified.", result.RequestID)
			s.netWriteMu.Lock()
			_ = protocol.WriteMessage(s.w, protocol.MsgSessionDenied, []byte(msg))
			s.netWriteMu.Unlock()
			log.Printf("[%s] approval: user=%s host=%s — pending request %s created", s.start.SessionID, s.start.User, s.start.Host, result.RequestID)
			return fmt.Errorf("approval pending")
		case ApprovalResultDeny:
			log.Printf("SECURITY: [%s] user=%s host=%s denied by OPA policy",
				s.start.SessionID, s.start.User, s.start.Host)
			s.netWriteMu.Lock()
			_ = protocol.WriteMessage(s.w, protocol.MsgSessionDenied, []byte(
				"sudo-logger: access denied by policy."))
			s.netWriteMu.Unlock()
			return fmt.Errorf("denied by OPA policy")
		case ApprovalResultAllow:
			// Approved or exempt — continue normally.
		}
	}

	return s.openApprovedSession(result)
}

// openApprovedSession opens the session and replies SERVER_READY once
// approval checking has concluded with ApprovalResultAllow (or the session
// is whitelisted). Shared by processSessionStart and
// processChallengeResponse — the two paths converge here once a session is
// cleared to start, regardless of which one did the clearing.
func (s *sessionConn) openApprovedSession(result CheckResult) error {
	var err error
	s.sess, err = s.srv.openSession(s.start)
	if err != nil {
		log.Printf("open session %s: %v", s.start.SessionID, err)
		return err
	}
	s.diskSess.Store(s.sess)
	log.Printf("[%s] start user=%s host=%s runas=%s uid=%d cmd=%q resolved=%q cwd=%s tsid=%s",
		s.sess.id, s.sess.user, s.sess.host, s.sess.runas, s.start.RunasUID,
		util.SanitizeForLog(s.sess.command), util.SanitizeForLog(s.start.ResolvedCommand),
		util.SanitizeForLog(s.sess.cwd), s.sess.writer.TSID())

	readyBody, _ := json.Marshal(protocol.ServerReadyBody{SessionTTL: result.SessionTTL})
	s.netWriteMu.Lock()
	err = protocol.WriteMessage(s.w, protocol.MsgServerReady, readyBody)
	s.netWriteMu.Unlock()
	if err != nil {
		log.Printf("[%s] write SERVER_READY: %v", s.start.SessionID, err)
		s.srv.closeSession(s.sess)
		s.sess = nil
		return err
	}

	s.sendMu.Lock()
	s.sessionID = s.start.SessionID
	s.sendMu.Unlock()

	return nil
}

func (s *sessionConn) processChallengeResponse(payload []byte) error {
	if s.sess != nil {
		log.Printf("SECURITY: duplicate session start attempt from %s — dropping connection", s.remote)
		return fmt.Errorf("duplicate session start")
	}
	if s.start == nil {
		log.Printf("challenge response before session_start from %s", s.remote)
		return fmt.Errorf("challenge response before session_start")
	}
	var resp protocol.SessionChallengeResponse
	if err := json.Unmarshal(payload, &resp); err != nil {
		log.Printf("[%s] parse challenge response: %v", s.start.SessionID, err)
		return err
	}
	s.start.Justification = resp.Justification

	// Re-run the check with the newly provided justification.
	result := s.srv.approvalMgr.Check(s.start.User, s.start.Host, s.start.RunasUser, s.start.Command,
		s.start.Groups, s.start.Justification)
	switch result.Result {
	case ApprovalResultNeedReason, ApprovalResultChallenge:
		// They already had their chance.
		s.netWriteMu.Lock()
		_ = protocol.WriteMessage(s.w, protocol.MsgSessionDenied, []byte("sudo-logger: access requires justification."))
		s.netWriteMu.Unlock()
		return fmt.Errorf("access requires justification")
	case ApprovalResultPending:
		msg := fmt.Sprintf("sudo-logger: approval request %s submitted.\nYou will be notified when approved. Retry sudo when notified.", result.RequestID)
		s.netWriteMu.Lock()
		_ = protocol.WriteMessage(s.w, protocol.MsgSessionDenied, []byte(msg))
		s.netWriteMu.Unlock()
		log.Printf("[%s] approval: user=%s host=%s — pending request %s created (via challenge)", s.start.SessionID, s.start.User, s.start.Host, result.RequestID)
		return fmt.Errorf("approval pending")
	case ApprovalResultDeny:
		log.Printf("SECURITY: [%s] user=%s host=%s denied by OPA policy (post-challenge)",
			s.start.SessionID, s.start.User, s.start.Host)
		s.netWriteMu.Lock()
		_ = protocol.WriteMessage(s.w, protocol.MsgSessionDenied, []byte("sudo-logger: access denied by policy."))
		s.netWriteMu.Unlock()
		return fmt.Errorf("denied by OPA policy")
	case ApprovalResultAllow:
		// Approved or exempt — continue normally.
	}

	return s.openApprovedSession(result)
}

func (s *sessionConn) processChunk(payload []byte) error {
	if s.sess == nil {
		log.Printf("chunk before session_start from %s", s.remote)
		return fmt.Errorf("chunk before session_start")
	}

	// Non-blocking handoff to disk writer if possible.
	task := diskTask{protocol.MsgChunk, payload}
	select {
	case s.diskQueue <- task:
		// Fits in primary queue
	default:
		// Primary queue is full. Check if we can spawn an overflow goroutine.
		if s.overflowCount.Load() < maxOverflow {
			s.overflowCount.Add(1)
			s.overflowWg.Add(1)
			go func(t diskTask) {
				defer s.overflowWg.Done()
				defer s.overflowCount.Add(-1)
				// Use select so that closing diskDone (shutdown) unblocks
				// the goroutine instead of panicking on a closed channel.
				select {
				case s.diskQueue <- t:
				case <-s.diskDone:
				}
			}(task)
		} else {
			// Hard limit reached (VULN-001 protection). Apply backpressure by blocking
			// the main loop. This slows down the client via TCP flow control.
			s.diskQueue <- task
		}
	}
	return nil
}

func (s *sessionConn) processResize(payload []byte) error {
	if s.sess == nil {
		log.Printf("resize before session_start from %s", s.remote)
		return nil
	}
	s.diskQueue <- diskTask{protocol.MsgResize, payload}
	return nil
}

func (s *sessionConn) processHeartbeatAck() {
	s.sendMu.Lock()
	s.pendingHeartbeat = true
	s.sendCond.Signal()
	s.sendMu.Unlock()
}

func (s *sessionConn) processSessionEnd(payload []byte) error {
	s.closeDisk()

	end, err := protocol.ParseSessionEnd(payload)
	if err != nil {
		log.Printf("parse session_end: %v", err)
	}
	if s.sess != nil {
		if end != nil {
			_ = s.sess.writer.WriteExitCode(end.ExitCode)
			log.Printf("[%s] end user=%s exit=%d seq=%d duration=%s",
				s.sess.id, s.sess.user, end.ExitCode, end.FinalSeq,
				time.Since(s.sess.startTime).Round(time.Second))
		}
		s.srv.closeSession(s.sess)
		s.sess = nil
	}
	return fmt.Errorf("session ended cleanly")
}

func (s *sessionConn) handleMessage(mType uint8, payload []byte) error {
	switch mType {
	case protocol.MsgSessionStart:
		return s.processSessionStart(payload)

	case protocol.MsgSessionChallengeResponse:
		return s.processChallengeResponse(payload)

	case protocol.MsgChunk:
		return s.processChunk(payload)

	case protocol.MsgResize:
		return s.processResize(payload)

	case protocol.MsgHeartbeat:
		s.processHeartbeatAck()
		return nil

	case protocol.MsgSessionEnd:
		return s.processSessionEnd(payload)

	case protocol.MsgSessionFreezing:
		sid := string(payload)
		log.Printf("SESSION_FREEZING from %s session_id=%s", s.remote, sid)
		s.srv.mu.Lock()
		activeSess := s.srv.sessions[sid]
		s.srv.mu.Unlock()
		if activeSess != nil {
			activeSess.freezeCandidate = true
		} else {
			if err := s.srv.sessionStore.MarkSessionNetworkOutage(context.Background(), sid); err != nil {
				log.Printf("mark network-outage session_id=%s: %v", sid, err)
			}
		}
		return fmt.Errorf("session freezing")

	case protocol.MsgSessionAbandon:
		if s.sess != nil {
			log.Printf("[%s] SESSION_ABANDON on active connection — ignoring", s.sess.id)
			return nil
		}
		sid := string(payload)
		log.Printf("SESSION_ABANDON from %s session_id=%s", s.remote, sid)
		if err := s.srv.sessionStore.MarkSessionNetworkOutage(context.Background(), sid); err != nil {
			log.Printf("mark network-outage session_id=%s: %v", sid, err)
		}
		return fmt.Errorf("session abandon")

	case protocol.MsgSandboxAlert:
		var alert protocol.SandboxAlert
		if err := json.Unmarshal(payload, &alert); err != nil {
			log.Printf("parse SANDBOX_ALERT from %s: %v", s.remote, err)
			return nil
		}
		log.Printf("SECURITY ALERT: SANDBOX_VIOLATION from %s — process %q (PID %d) blocked (type %d) in session %s",
			s.remote, alert.Comm, alert.Pid, alert.Type, alert.SessionID)

		if alert.SessionID != "" {
			if err := s.srv.sessionStore.RecordSandboxViolation(context.Background(), alert.SessionID, alert); err != nil {
				log.Printf("[%s] record violation: %v", alert.SessionID, err)
			}
		}
		return nil

	case protocol.MsgFetchConfig:
		key := strings.TrimSpace(string(payload))
		var content string
		if !agentFetchableConfigKey(key) {
			log.Printf("SECURITY: MsgFetchConfig for disallowed key %q from %s — denying", key, s.remote)
		} else if c, err := s.srv.sessionStore.GetConfig(context.Background(), key); err != nil {
			log.Printf("fetch config %q from %s: %v", key, s.remote, err)
		} else {
			content = c
		}
		s.netWriteMu.Lock()
		_ = protocol.WriteMessage(s.w, protocol.MsgConfigData, []byte(content))
		s.netWriteMu.Unlock()
		return nil

	case protocol.MsgSudoersSnapshot:
		var snap protocol.SudoersSnapshot
		if err := json.Unmarshal(payload, &snap); err != nil {
			log.Printf("parse MsgSudoersSnapshot from %s: %v", s.remote, err)
			return err
		}
		if !util.ValidAgentHost(snap.Host) {
			log.Printf("SECURITY: MsgSudoersSnapshot invalid host %q from %s — dropping", snap.Host, s.remote)
			return fmt.Errorf("invalid host in sudoers snapshot")
		}
		if err := s.srv.sessionStore.SaveSudoersSnapshot(context.Background(), &snap); err != nil {
			log.Printf("save sudoers snapshot host=%s: %v", snap.Host, err)
		}
		return fmt.Errorf("sudoers snapshot complete")

	case protocol.MsgSudoersError:
		var serr protocol.SudoersError
		if err := json.Unmarshal(payload, &serr); err != nil {
			log.Printf("parse MsgSudoersError from %s: %v", s.remote, err)
			return err
		}
		if !util.ValidAgentHost(serr.Host) {
			log.Printf("SECURITY: MsgSudoersError invalid host %q from %s — dropping", serr.Host, s.remote)
			return fmt.Errorf("invalid host in sudoers error")
		}
		if err := s.srv.sessionStore.SaveSudoersError(context.Background(), serr); err != nil {
			log.Printf("save sudoers error host=%s: %v", serr.Host, err)
		}
		return nil

	case protocol.MsgHeartbeatAgent:
		s.srv.handleAgentHeartbeat(s.remote, payload)
		return fmt.Errorf("agent heartbeat complete")

	default:
		log.Printf("unknown msg 0x%02x len=%d from %s", mType, len(payload), s.remote)
		return nil
	}
}
