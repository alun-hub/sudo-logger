package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"sudo-logger/internal/iolog"
	"sudo-logger/internal/protocol"
)

func (srv *server) handleConn(conn *tls.Conn) {
	defer conn.Close()

	remote := conn.RemoteAddr().String()
	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)
	var netWriteMu sync.Mutex // Protects all writes to 'w'

	var sess *session
	var diskSess atomic.Pointer[session]
	var start *protocol.SessionStart

	// ── Async ACK Coalescer ───────────────────────────────────────────────
	// Prevents TCP flow control deadlocks by decoupling reads from writes.
	// Under high I/O, this naturally coalesces thousands of ACKs into one.
	var (
		sendMu           sync.Mutex
		sendCond         = sync.NewCond(&sendMu)
		pendingSeq       uint64
		pendingHeartbeat bool
		senderClosed     bool
		sessionID        string
	)

	// ── Async Disk Writer ────────────────────────────────────────────────
	// Shock absorber for high I/O bursts. Decouples network from storage.
	type diskTask struct {
		msgType uint8
		payload []byte
	}
	diskQueue := make(chan diskTask, 50000)
	diskDone  := make(chan struct{})
	var diskWg sync.WaitGroup
	diskWg.Add(1)

	var overflowCount atomic.Int32
	const maxOverflow = 1000

	go func() {
		defer diskWg.Done()
		for {
			task, ok := <-diskQueue
			if !ok {
				return
			}

			// Collect a batch of up to 100 available tasks to reduce I/O overhead
			batch := []diskTask{task}
			for i := 0; i < 99; i++ {
				select {
				case t, ok := <-diskQueue:
					if !ok {
						i = 100
						break
					}
					batch = append(batch, t)
				default:
					i = 100 // No more immediately available
				}
			}

			s := diskSess.Load()
			var sid string
			if s != nil {
				sid = s.id
			} else {
				sid = sessionID
			}

			var lastSeq uint64
			for _, t := range batch {
				if t.msgType == protocol.MsgResize {
					if s != nil {
						resize, err := protocol.ParseResize(t.payload)
						if err != nil {
							log.Printf("[%s] disk-writer parse resize: %v", sid, err)
							continue
						}
						if err := s.writer.WriteResize(resize.Cols, resize.Rows, resize.Timestamp); err != nil {
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
				if s != nil {
					switch chunk.Stream {
					case protocol.StreamTtyOut, protocol.StreamStdout, protocol.StreamStderr:
						if err := s.writer.WriteOutput(chunk.Data, chunk.Timestamp); err != nil {
							log.Printf("[%s] write output: %v", sid, err)
						}
					case protocol.StreamTtyIn, protocol.StreamStdin:
						if err := s.writer.WriteInput(chunk.Data, chunk.Timestamp); err != nil {
							log.Printf("[%s] write input: %v", sid, err)
						}
					}
					atomic.StoreUint64(&s.lastSeq, chunk.Seq)
					lastSeq = chunk.Seq
				}
			}

			if s != nil {
				_ = s.writer.Flush()
			}

			// ONLY NOW that the batch is on disk, we signal the ACK coalescer
			if lastSeq > 0 {
				sendMu.Lock()
				pendingSeq = lastSeq
				sendCond.Signal()
				sendMu.Unlock()
			}
		}
	}()

	go func() {
		for {
			sendMu.Lock()
			for pendingSeq == 0 && !pendingHeartbeat && !senderClosed {
				sendCond.Wait()
			}
			if senderClosed {
				sendMu.Unlock()
				return
			}
			seq := pendingSeq
			pendingSeq = 0
			hb := pendingHeartbeat
			pendingHeartbeat = false
			sid := sessionID
			sendMu.Unlock()

			if seq > 0 {
				ackPayload := srv.buildACK(sid, seq)
				netWriteMu.Lock()
				err := protocol.WriteMessage(w, protocol.MsgAck, ackPayload)
				netWriteMu.Unlock()
				if err != nil {
					log.Printf("[%s] write ack (async): %v", sid, err)
					return
				}
			}
			if hb {
				netWriteMu.Lock()
				err := protocol.WriteMessage(w, protocol.MsgHeartbeatAck, nil)
				netWriteMu.Unlock()
				if err != nil {
					log.Printf("[%s] write hb ack (async): %v", sid, err)
					return
				}
			}		}
	}()

	var diskCloseOnce sync.Once
	closeDisk := func() {
		diskCloseOnce.Do(func() {
			// Signal overflow goroutines to abort before closing diskQueue.
			// Overflow goroutines select on diskQueue or diskDone; closing
			// diskDone unblocks them without triggering a "send on closed
			// channel" panic that would crash the server.
			close(diskDone)
			close(diskQueue)
			diskWg.Wait()
		})
	}

	defer func() {
		// Signal and wait for disk writer to finish
		closeDisk()

		sendMu.Lock()
		senderClosed = true
		sendCond.Signal()
		sendMu.Unlock()
	}()
	// ──────────────────────────────────────────────────────────────────────

	for {
		msgType, plen, err := protocol.ReadHeader(r)
		if err != nil {
			// CRITICAL: Stop the background writer and wait for all data to hit disk
			// BEFORE we decide if the session was successful or not.
			closeDisk()

			if sess != nil {
				if sess.freezeCandidate {
					log.Printf("[%s] %s connection lost after SESSION_FREEZING — marking network outage",
						sess.id, remote)
					_ = sess.writer.MarkNetworkOutage()
				} else {
					log.Printf("SECURITY: [%s] %s dropped connection without session_end — session may be incomplete (agent killed?): %v",
						sess.id, remote, err)
					_ = sess.writer.MarkIncomplete()
				}
				srv.sessionsIncomplete.Add(1)
				srv.closeSession(sess)
			}
			return
		}

		// SESSION_START is JSON metadata — apply a tighter size limit to prevent
		// a malicious (mTLS-authenticated) agent from triggering a 1 MB allocation.
		if msgType == protocol.MsgSessionStart && plen > protocol.MaxSessionStartPayload {
			log.Printf("SECURITY: SESSION_START payload too large from %s: %d bytes (max %d) — dropping connection",
				remote, plen, protocol.MaxSessionStartPayload)
			return
		}
		payload, err := protocol.ReadPayload(r, plen)
		if err != nil {
			log.Printf("read payload from %s: %v", remote, err)
			return
		}

		switch msgType {
		case protocol.MsgSessionStart:
			if sess != nil {
				log.Printf("SECURITY: duplicate session start attempt from %s — dropping connection", remote)
				return
			}
			var err error
			start, err = protocol.ParseSessionStart(payload)
			if err != nil {
				log.Printf("parse session start from %s: %v", remote, err)
				return
			}
			// Neutralize control characters before User/Host ever reach a log
			// line — sanitizeName() below is the authoritative validity check,
			// but that only runs on the Allow path, well after several
			// SECURITY:-prefixed lines have already been written.
			start.User = sanitizeForLog(start.User)
			start.Host = sanitizeForLog(start.Host)
			// Verify the claimed host matches the presenting TLS certificate.
			// With shared client certificates (default setup) this is advisory only
			// and logs a warning.  Enable -strict-cert-host to reject mismatches
			// when each machine has its own certificate (stronger isolation).
			certs := conn.ConnectionState().PeerCertificates
			if len(certs) > 0 && !certMatchesHost(certs[0], start.Host) {
				if *flagStrictCertHost {
					log.Printf("SECURITY: %s claimed host=%q but cert CN=%q DNSNames=%v — closing",
						remote, start.Host, certs[0].Subject.CommonName, certs[0].DNSNames)
					return
				}
				log.Printf("WARNING: %s claimed host=%q but cert CN=%q DNSNames=%v (use -strict-cert-host to enforce)",
					remote, start.Host, certs[0].Subject.CommonName, certs[0].DNSNames)
			}

			// ── Block policy check BEFORE creating the session directory ──────
			// Checking first avoids leaving an empty session.cast on disk for
			// every denied attempt (which clutters the replay index).
			blocked, msg, err := srv.sessionStore.IsBlocked(context.Background(), start.User, start.Host)
			if err != nil {
				log.Printf("SECURITY: [%s] block policy check failed for user=%s host=%s: %v",
					start.SessionID, start.User, start.Host, err)
				netWriteMu.Lock()
				_ = protocol.WriteMessage(w, protocol.MsgSessionError, []byte("internal block check error"))
				netWriteMu.Unlock()
				return
			}
			if blocked {
				log.Printf("SECURITY: [%s] user=%s host=%s denied by block policy",
					start.SessionID, start.User, start.Host)
				netWriteMu.Lock()
				_ = protocol.WriteMessage(w, protocol.MsgSessionDenied, []byte(msg))
				netWriteMu.Unlock()
				return
			}

			// ── JIT approval check ─────────────────────────────────────────────
			var result CheckResult
			whitelisted, err := srv.sessionStore.IsWhitelisted(context.Background(), start.User, start.Host)
			if err != nil {
				log.Printf("SECURITY: [%s] whitelist check failed for user=%s host=%s: %v",
					start.SessionID, start.User, start.Host, err)
				netWriteMu.Lock()
				_ = protocol.WriteMessage(w, protocol.MsgSessionError, []byte("internal whitelist check error"))
				netWriteMu.Unlock()
				return
			}
			if whitelisted {
				log.Printf("[%s] whitelist: user=%s host=%s — bypassing JIT approval", start.SessionID, start.User, start.Host)
			} else {
				result = srv.approvalMgr.Check(start.User, start.Host, start.RunasUser, start.Command,
					start.Groups, start.Justification)
				switch result.Result {
				case ApprovalResultNeedReason:
					// Check if there's already a pending request for this user@host
					// so we can give a more informative retry message.
					if msg := srv.approvalMgr.RetryMessage(start.User, start.Host); msg != "" {
						netWriteMu.Lock()
						_ = protocol.WriteMessage(w, protocol.MsgSessionDenied, []byte(msg))
						netWriteMu.Unlock()
					} else {
						netWriteMu.Lock()
						_ = protocol.WriteMessage(w, protocol.MsgSessionDenied, []byte(
							"sudo-logger: access requires justification. Run sudo again and provide a reason when prompted."))
						netWriteMu.Unlock()
					}
					log.Printf("[%s] approval: user=%s host=%s — no justification provided", start.SessionID, start.User, start.Host)
					return
				case ApprovalResultChallenge:
					if start.TtyPath == "" {
						// Non-TTY session (cron, script): cannot challenge for justification.
						// Fall back to a standard denial with instructions.
						netWriteMu.Lock()
						_ = protocol.WriteMessage(w, protocol.MsgSessionDenied, []byte(
							"sudo-logger: access requires justification. Provide reason via sudo-logger-agent or retry interactively."))
						netWriteMu.Unlock()
						log.Printf("[%s] approval: user=%s host=%s — non-TTY session requires justification", start.SessionID, start.User, start.Host)
						return
					}
					challenge := protocol.SessionChallenge{HasWebhook: result.HasWebhook}
					body, _ := json.Marshal(challenge)
					netWriteMu.Lock()
					_ = protocol.WriteMessage(w, protocol.MsgSessionChallenge, body)
					netWriteMu.Unlock()
					log.Printf("[%s] approval: user=%s host=%s — challenge sent", start.SessionID, start.User, start.Host)
					continue
				case ApprovalResultPending:
					msg := fmt.Sprintf("sudo-logger: approval request %s submitted.\nYou will be notified when approved. Retry sudo when notified.", result.RequestID)

					netWriteMu.Lock()
					_ = protocol.WriteMessage(w, protocol.MsgSessionDenied, []byte(msg))
					netWriteMu.Unlock()
					log.Printf("[%s] approval: user=%s host=%s — pending request %s created", start.SessionID, start.User, start.Host, result.RequestID)
					return
				case ApprovalResultDeny:
					log.Printf("SECURITY: [%s] user=%s host=%s denied by OPA policy",
						start.SessionID, start.User, start.Host)
					netWriteMu.Lock()
					_ = protocol.WriteMessage(w, protocol.MsgSessionDenied, []byte(
						"sudo-logger: access denied by policy."))
					netWriteMu.Unlock()
					return
				case ApprovalResultAllow:
					// Approved or exempt — continue normally.
				}
			}

			sess, err = srv.openSession(start)
			if err != nil {
				log.Printf("open session %s: %v", start.SessionID, err)
				return
			}
			diskSess.Store(sess)
			log.Printf("[%s] start user=%s host=%s runas=%s uid=%d cmd=%q resolved=%q cwd=%s tsid=%s",
				sess.id, sess.user, sess.host, sess.runas, start.RunasUID,
				sanitizeForLog(sess.command), sanitizeForLog(start.ResolvedCommand),
				sanitizeForLog(sess.cwd), sess.writer.TSID())

			readyBody, _ := json.Marshal(protocol.ServerReadyBody{SessionTTL: result.SessionTTL})
			netWriteMu.Lock()
			err = protocol.WriteMessage(w, protocol.MsgServerReady, readyBody)
			netWriteMu.Unlock()
			if err != nil {
				log.Printf("[%s] write SERVER_READY: %v", start.SessionID, err)
				srv.closeSession(sess)
				sess = nil
				return
			}

			sendMu.Lock()
			sessionID = start.SessionID
			sendMu.Unlock()

		case protocol.MsgSessionChallengeResponse:
			if sess != nil {
				log.Printf("SECURITY: duplicate session start attempt from %s — dropping connection", remote)
				return
			}
			if start == nil {
				log.Printf("challenge response before session_start from %s", remote)
				return
			}
			var resp protocol.SessionChallengeResponse
			if err := json.Unmarshal(payload, &resp); err != nil {
				log.Printf("[%s] parse challenge response: %v", start.SessionID, err)
				return
			}
			start.Justification = resp.Justification

			// Re-run the check with the newly provided justification.
			result := srv.approvalMgr.Check(start.User, start.Host, start.RunasUser, start.Command,
				start.Groups, start.Justification)
			switch result.Result {
			case ApprovalResultNeedReason, ApprovalResultChallenge:
				// They already had their chance.
				netWriteMu.Lock()
				_ = protocol.WriteMessage(w, protocol.MsgSessionDenied, []byte("sudo-logger: access requires justification."))
				netWriteMu.Unlock()
				return
			case ApprovalResultPending:
				msg := fmt.Sprintf("sudo-logger: approval request %s submitted.\nYou will be notified when approved. Retry sudo when notified.", result.RequestID)

				netWriteMu.Lock()
				_ = protocol.WriteMessage(w, protocol.MsgSessionDenied, []byte(msg))
				netWriteMu.Unlock()
				log.Printf("[%s] approval: user=%s host=%s — pending request %s created (via challenge)", start.SessionID, start.User, start.Host, result.RequestID)
				return
			case ApprovalResultDeny:
				log.Printf("SECURITY: [%s] user=%s host=%s denied by OPA policy (post-challenge)",
					start.SessionID, start.User, start.Host)
				netWriteMu.Lock()
				_ = protocol.WriteMessage(w, protocol.MsgSessionDenied, []byte("sudo-logger: access denied by policy."))
				netWriteMu.Unlock()
				return
			case ApprovalResultAllow:
				// Approved or exempt — continue normally.
			}

			var err error
			sess, err = srv.openSession(start)
			if err != nil {
				log.Printf("open session %s: %v", start.SessionID, err)
				return
			}
			diskSess.Store(sess)
			log.Printf("[%s] start user=%s host=%s runas=%s uid=%d cmd=%q resolved=%q cwd=%s tsid=%s",
				sess.id, sess.user, sess.host, sess.runas, start.RunasUID,
				sanitizeForLog(sess.command), sanitizeForLog(start.ResolvedCommand),
				sanitizeForLog(sess.cwd), sess.writer.TSID())

			readyBody2, _ := json.Marshal(protocol.ServerReadyBody{SessionTTL: result.SessionTTL})
			netWriteMu.Lock()
			err = protocol.WriteMessage(w, protocol.MsgServerReady, readyBody2)
			netWriteMu.Unlock()
			if err != nil {
				log.Printf("[%s] write SERVER_READY: %v", start.SessionID, err)
				srv.closeSession(sess)
				sess = nil
				return
			}

			sendMu.Lock()
			sessionID = start.SessionID
			sendMu.Unlock()

		case protocol.MsgChunk:
			if sess == nil {
				log.Printf("chunk before session_start from %s", remote)
				return
			}

			// Non-blocking handoff to disk writer if possible.
			task := diskTask{msgType, payload}
			select {
			case diskQueue <- task:
				// Fits in primary queue
			default:
				// Primary queue is full. Check if we can spawn an overflow goroutine.
				if overflowCount.Load() < maxOverflow {
					overflowCount.Add(1)
					diskWg.Add(1)
					go func(t diskTask) {
						defer diskWg.Done()
						defer overflowCount.Add(-1)
						// Use select so that closing diskDone (shutdown) unblocks
						// the goroutine instead of panicking on a closed channel.
						select {
						case diskQueue <- t:
						case <-diskDone:
						}
					}(task)
				} else {
					// Hard limit reached (VULN-001 protection). Apply backpressure by blocking
					// the main loop. This slows down the client via TCP flow control.
					diskQueue <- task
				}
			}

		case protocol.MsgResize:
			if sess == nil {
				log.Printf("resize before session_start from %s", remote)
				continue
			}
			diskQueue <- diskTask{msgType, payload}

		case protocol.MsgHeartbeat:
			sendMu.Lock()
			pendingHeartbeat = true
			sendCond.Signal()
			sendMu.Unlock()

		case protocol.MsgSessionEnd:
			// CRITICAL: Stop the background writer and wait for all data to hit disk
			// BEFORE we mark the session as cleanly finished.
			closeDisk()

			end, err := protocol.ParseSessionEnd(payload)
			if err != nil {
				log.Printf("parse session_end: %v", err)
			}
			if sess != nil {
				if end != nil {
					_ = sess.writer.WriteExitCode(end.ExitCode)
					log.Printf("[%s] end user=%s exit=%d seq=%d duration=%s",
						sess.id, sess.user, end.ExitCode, end.FinalSeq,
						time.Since(sess.startTime).Round(time.Second))
				}
				srv.closeSession(sess)
			}
			return

		case protocol.MsgSessionFreezing:
			// Sent by the agent on a NEW connection at markDead() time (~800 ms
			// after network loss), while the server is likely still reachable.
			// If the session is still active, set freezeCandidate so the TCP-drop
			// handler calls MarkNetworkOutage instead of MarkIncomplete.
			// If the session is already closed (TCP died before this message
			// arrived), upgrade the stored termination reason directly.
			sid := string(payload)
			log.Printf("SESSION_FREEZING from %s session_id=%s", remote, sid)
			srv.mu.Lock()
			activeSess := srv.sessions[sid]
			srv.mu.Unlock()
			if activeSess != nil {
				activeSess.freezeCandidate = true
			} else {
				if err := srv.sessionStore.MarkSessionNetworkOutage(context.Background(), sid); err != nil {
					log.Printf("mark network-outage session_id=%s: %v", sid, err)
				}
			}
			return

		case protocol.MsgSessionAbandon:
			// Fallback: sent by the agent on a NEW connection after freeze-timeout
			// fires (5 min), only if network has recovered.  Upgrades the stored
			// termination reason in case SESSION_FREEZING was not received earlier.
			if sess != nil {
				log.Printf("[%s] SESSION_ABANDON on active connection — ignoring", sess.id)
				return
			}
			sid := string(payload)
			log.Printf("SESSION_ABANDON from %s session_id=%s", remote, sid)
			if err := srv.sessionStore.MarkSessionNetworkOutage(context.Background(), sid); err != nil {
				log.Printf("mark network-outage session_id=%s: %v", sid, err)
			}
			return

		case protocol.MsgSandboxAlert:
			// Kernel LSM blocked an operation in a sandboxed session.
			// Must NOT return here — the session connection is still active.
			var alert protocol.SandboxAlert
			if err := json.Unmarshal(payload, &alert); err != nil {
				log.Printf("parse SANDBOX_ALERT from %s: %v", remote, err)
				continue
			}
			log.Printf("SECURITY ALERT: SANDBOX_VIOLATION from %s — process %q (PID %d) blocked (type %d) in session %s",
				remote, alert.Comm, alert.Pid, alert.Type, alert.SessionID)

			if alert.SessionID != "" {
				if err := srv.sessionStore.RecordSandboxViolation(context.Background(), alert.SessionID, alert); err != nil {
					log.Printf("[%s] record violation: %v", alert.SessionID, err)
				}
			}

		case protocol.MsgFetchConfig:
			// Agent requests a named config blob (e.g. "sandbox.yaml").
			// Respond immediately and keep reading — peer closes after receiving.
			key := strings.TrimSpace(string(payload))
			var content string
			if !agentFetchableConfigKey(key) {
				log.Printf("SECURITY: MsgFetchConfig for disallowed key %q from %s — denying", key, remote)
			} else if c, err := srv.sessionStore.GetConfig(context.Background(), key); err != nil {
				log.Printf("fetch config %q from %s: %v", key, remote, err)
			} else {
				content = c
			}
			netWriteMu.Lock()
			_ = protocol.WriteMessage(w, protocol.MsgConfigData, []byte(content))
			netWriteMu.Unlock()

		case protocol.MsgSudoersSnapshot:
			if plen > protocol.MaxSudoersPayload {
				log.Printf("SECURITY: MsgSudoersSnapshot too large from %s: %d bytes (max %d) — dropping",
					remote, plen, protocol.MaxSudoersPayload)
				return
			}
			var snap protocol.SudoersSnapshot
			if err := json.Unmarshal(payload, &snap); err != nil {
				log.Printf("parse MsgSudoersSnapshot from %s: %v", remote, err)
				return
			}
			if snap.Host == "" || len(snap.Host) > 255 || snap.Host[0] == '.' ||
				strings.ContainsAny(snap.Host, "/\\") || strings.Contains(snap.Host, "..") {
				log.Printf("SECURITY: MsgSudoersSnapshot invalid host %q from %s — dropping", snap.Host, remote)
				return
			}
			if err := srv.sessionStore.SaveSudoersSnapshot(context.Background(), &snap); err != nil {
				log.Printf("save sudoers snapshot host=%s: %v", snap.Host, err)
			}
			return

		case protocol.MsgSudoersError:
			var serr protocol.SudoersError
			if err := json.Unmarshal(payload, &serr); err != nil {
				log.Printf("parse MsgSudoersError from %s: %v", remote, err)
				return
			}
			if serr.Host == "" || len(serr.Host) > 255 || serr.Host[0] == '.' ||
				strings.ContainsAny(serr.Host, "/\\") || strings.Contains(serr.Host, "..") {
				log.Printf("SECURITY: MsgSudoersError invalid host %q from %s — dropping", serr.Host, remote)
				return
			}
			if err := srv.sessionStore.SaveSudoersError(context.Background(), serr); err != nil {
				log.Printf("save sudoers error host=%s: %v", serr.Host, err)
			}

		case protocol.MsgHeartbeatAgent:
			srv.handleAgentHeartbeat(remote, payload)
			return

		case protocol.MsgDivergenceAlert:
			// Agent detected a sudo/pkexec execve with no plugin SESSION_START.
			// This indicates sudo.conf was tampered with (Plugin line removed).
			var alert protocol.DivergenceAlert
			if err := json.Unmarshal(payload, &alert); err != nil {
				log.Printf("parse DIVERGENCE_ALERT from %s: %v", remote, err)
				return
			}
			alert.User = sanitizeForLog(alert.User)
			alert.Host = sanitizeForLog(alert.Host)
			log.Printf("SECURITY ALERT: DIVERGENCE_ALERT from %s — %s ran %q on %s at %s but plugin did not log it",
				remote, alert.User, alert.Comm, alert.Host,
				time.Unix(alert.Ts, 0).Format(time.RFC3339))
			// Create a session record so the alert appears in the replay UI.
			safeUser := nonIDChar.ReplaceAllLiteralString(alert.User, "-")
			safeHost := nonIDChar.ReplaceAllLiteralString(alert.Host, "-")
			synthID := fmt.Sprintf("div.%s.%s.%d", safeHost, safeUser, alert.Ts)
			if len(synthID) > 255 {
				synthID = synthID[:255]
			}
			synthSess, sErr := srv.openSession(&protocol.SessionStart{
				SessionID:        synthID,
				User:             alert.User,
				Host:             alert.Host,
				Command:          alert.Comm,
				Ts:               alert.Ts,
				Source:           "plugin",
				HasIO:            false,
				DivergenceStatus: "missing_plugin",
			})
			if sErr != nil {
				log.Printf("DIVERGENCE_ALERT: store synthetic session: %v", sErr)
			} else {
				srv.closeSession(synthSess)
			}
			return

		default:
			log.Printf("unknown msg 0x%02x len=%d from %s", msgType, plen, remote)
		}
	}
}

func (srv *server) openSession(start *protocol.SessionStart) (*session, error) {
	if !validSessionID.MatchString(start.SessionID) {
		return nil, fmt.Errorf("invalid session_id: %q", start.SessionID)
	}
	user, err := sanitizeName(start.User)
	if err != nil {
		return nil, fmt.Errorf("invalid user field: %w", err)
	}
	host, err := sanitizeName(start.Host)
	if err != nil {
		return nil, fmt.Errorf("invalid host field: %w", err)
	}

	startTime := time.Unix(start.Ts, 0)

	runasUser := start.RunasUser
	if runasUser == "" {
		runasUser = "root"
	}
	cwd := start.Cwd
	if cwd == "" {
		cwd = "/"
	}

	divStatus := start.DivergenceStatus
	// Only default to "unwitnessed" for plugin sessions (or old clients that
	// don't set Source).  eBPF-sourced sessions (ebpf-pkexec, ebpf-tty) have no
	// plugin counterpart by design, so divergence is not applicable.
	if divStatus == "" && (start.Source == "" || start.Source == "plugin") {
		divStatus = "unwitnessed"
	}
	w, err := srv.sessionStore.CreateSession(
		context.Background(),
		iolog.SessionMeta{
			SessionID:        start.SessionID,
			User:             user,
			Host:             host,
			RunasUser:        runasUser,
			RunasUID:         start.RunasUID,
			RunasGID:         start.RunasGID,
			Cwd:              cwd,
			Command:          start.Command,
			ResolvedCommand:  start.ResolvedCommand,
			Flags:            start.Flags,
			Rows:             start.Rows,
			Cols:             start.Cols,
			Source:           start.Source,
			ParentSessionID:  start.ParentSessionID,
			HasIO:            start.HasIO,
			DivergenceStatus: divStatus,
			CallerProcess:    start.CallerProcess,
		},
		startTime,
	)
	if err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}

	// Mark the session as active so the replay server can distinguish
	// "currently recording" from "ended cleanly" or "ended abruptly (INCOMPLETE)".
	// Removed by closeSession() regardless of how the session ends.
	_ = w.MarkActive()

	sess := &session{
		id:        start.SessionID,
		user:      start.User,
		host:      start.Host,
		runas:     runasUser,
		cwd:       cwd,
		command:   start.Command,
		startTime: startTime,
		writer:    w,
	}

	srv.mu.Lock()
	if _, exists := srv.sessions[sess.id]; exists {
		srv.mu.Unlock()
		w.Close()
		return nil, fmt.Errorf("duplicate session id: %s", start.SessionID)
	}
	srv.sessions[sess.id] = sess
	srv.mu.Unlock()

	return sess, nil
}

func (srv *server) closeSession(sess *session) {
	if sess == nil {
		return
	}
	_ = sess.writer.MarkDone()
	if err := sess.writer.Close(); err != nil {
		log.Printf("[%s] close writer: %v", sess.id, err)
	}
	srv.mu.Lock()
	delete(srv.sessions, sess.id)
	srv.mu.Unlock()
	srv.sessionsTotal.Add(1)
}

func (srv *server) buildACK(sessionID string, seq uint64) []byte {
	ts := time.Now().UnixNano()
	msg := protocol.AckSignMessage(sessionID, seq, ts)
	sigSlice := ed25519.Sign(srv.signKey, msg)
	var sig [64]byte
	copy(sig[:], sigSlice)
	return protocol.EncodeAck(seq, ts, sig)
}

// agentFetchableConfigKey reports whether key is one an agent may legitimately
// request via MsgFetchConfig. This is the only allowlist enforced on that
// message type — anything not listed here (e.g. approval-policy.yaml,
// jit-policy, siem.yaml) must never be handed to a peer over the wire.
func agentFetchableConfigKey(key string) bool {
	switch key {
	case "sandbox.yaml", "redaction_config":
		return true
	}
	return strings.HasPrefix(key, "sudoers/")
}

// certMatchesHost returns true if the TLS client certificate was issued for
// the given host name.  It checks DNS SANs first (per RFC 6125) then falls
// back to the Common Name.  A short hostname matches a fully-qualified cert
// name: host "gnarg" matches CN/SAN "gnarg.example.com".
func certMatchesHost(cert *x509.Certificate, host string) bool {
	h := strings.ToLower(host)
	for _, san := range cert.DNSNames {
		s := strings.ToLower(san)
		if s == h || strings.HasPrefix(s, h+".") {
			return true
		}
	}
	cn := strings.ToLower(cert.Subject.CommonName)
	return cn == h || strings.HasPrefix(cn, h+".")
}

// loadEd25519PrivKey reads a PEM-encoded PKCS8 ed25519 private key.
func loadEd25519PrivKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", path)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	ed, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key in %s is not ed25519", path)
	}
	return ed, nil
}

func buildTLSConfig() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(*flagCert, *flagKey)
	if err != nil {
		return nil, fmt.Errorf("load server cert: %w", err)
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
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}, nil
}
