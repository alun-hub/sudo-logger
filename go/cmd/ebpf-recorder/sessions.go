package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"sudo-logger/internal/protocol"
)

// IoEvent mirrors the C struct io_event in bpf/recorder.c.
// Must be kept in sync with the C definition (packed layout, little-endian).
type IoEvent struct {
	CgroupID    uint64
	TimestampNS uint64
	DataLen     uint32
	Stream      uint8
	Pad         [3]uint8
	Data        [4096]byte
}

// activeSession represents one ongoing login session being recorded.
type activeSession struct {
	id       string // unique session ID sent to logserver
	user     string
	host     string
	remote   string // remote IP (SSH) or empty for local TTY
	command  string // login shell or SSH_ORIGINAL_COMMAND
	cgroupID uint64

	mu   sync.Mutex
	conn net.Conn
	bw   *bufio.Writer
	seq  uint64
	done bool
}

// sessionTracker watches the cgroup hierarchy for new login sessions,
// manages the tracked_cgroups BPF map, and routes I/O events to the
// correct logserver connection.
type sessionTracker struct {
	bpfMap     *ebpf.Map
	serverAddr string
	tlsCfg     *tls.Config
	verifyKey  []byte
	hostname   string
	cgroupRoot string

	mu       sync.Mutex
	sessions map[uint64]*activeSession // keyed by cgroupID
}

func newSessionTracker(
	bpfMap *ebpf.Map,
	serverAddr string,
	tlsCfg *tls.Config,
	verifyKey []byte,
	hostname string,
	cgroupRoot string,
) *sessionTracker {
	return &sessionTracker{
		bpfMap:     bpfMap,
		serverAddr: serverAddr,
		tlsCfg:     tlsCfg,
		verifyKey:  verifyKey,
		hostname:   hostname,
		cgroupRoot: cgroupRoot,
		sessions:   make(map[uint64]*activeSession),
	}
}

// watch uses inotify to monitor the cgroup user.slice hierarchy.
// It picks up new session-N.scope directories (new logins) and their removal
// (session ends), and scans existing sessions on startup.
func (t *sessionTracker) watch() {
	userSlice := filepath.Join(t.cgroupRoot, "user.slice")

	ifd, err := syscall.InotifyInit1(syscall.IN_CLOEXEC)
	if err != nil {
		log.Fatalf("inotify_init: %v", err)
	}
	defer syscall.Close(ifd)

	// wdToDir maps inotify watch descriptor → absolute directory path.
	wdToDir := map[int32]string{}
	var wdMu sync.Mutex

	addWatch := func(path string) {
		wd, err := syscall.InotifyAddWatch(ifd, path, syscall.IN_CREATE|syscall.IN_DELETE|syscall.IN_ONLYDIR)
		if err != nil {
			return
		}
		wdMu.Lock()
		wdToDir[int32(wd)] = path
		wdMu.Unlock()
	}

	// Watch user.slice itself so we notice new user-UID.slice dirs.
	addWatch(userSlice)

	// Scan and watch any user-*.slice dirs that already exist.
	entries, _ := os.ReadDir(userSlice)
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), "user-") {
			userDir := filepath.Join(userSlice, e.Name())
			addWatch(userDir)
			// Scan sessions that were already running when we started.
			t.scanExistingSessions(userDir)
		}
	}

	buf := make([]byte, 4096)
	for {
		n, err := syscall.Read(ifd, buf)
		if err != nil || n == 0 {
			break
		}

		offset := 0
		for offset < n {
			if offset+syscall.SizeofInotifyEvent > n {
				break
			}
			ev := (*syscall.InotifyEvent)(unsafe.Pointer(&buf[offset]))
			nameLen := int(ev.Len)
			nameBytes := buf[offset+syscall.SizeofInotifyEvent : offset+syscall.SizeofInotifyEvent+nameLen]
			name := string(bytes.TrimRight(nameBytes, "\x00"))
			offset += syscall.SizeofInotifyEvent + nameLen

			wdMu.Lock()
			dir := wdToDir[ev.Wd]
			wdMu.Unlock()

			if dir == "" {
				continue
			}

			fullPath := filepath.Join(dir, name)

			// New user-*.slice appeared under user.slice.
			if dir == userSlice && ev.Mask&syscall.IN_CREATE != 0 &&
				strings.HasPrefix(name, "user-") {
				addWatch(fullPath)
				continue
			}

			// New session-*.scope under a user-*.slice dir.
			if strings.HasPrefix(name, "session-") && strings.HasSuffix(name, ".scope") {
				if ev.Mask&syscall.IN_CREATE != 0 {
					// Give systemd a moment to populate the cgroup.
					time.AfterFunc(200*time.Millisecond, func() {
						t.sessionStarted(fullPath, name)
					})
				} else if ev.Mask&syscall.IN_DELETE != 0 {
					t.sessionEnded(fullPath)
				}
			}
		}
	}
}

// scanExistingSessions registers sessions already running inside userDir.
func (t *sessionTracker) scanExistingSessions(userDir string) {
	entries, err := os.ReadDir(userDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), "session-") &&
			strings.HasSuffix(e.Name(), ".scope") {
			t.sessionStarted(filepath.Join(userDir, e.Name()), e.Name())
		}
	}
}

// sessionStarted is called when a new session-N.scope cgroup directory appears.
func (t *sessionTracker) sessionStarted(scopePath, scopeName string) {
	// Extract session number from "session-N.scope".
	num := strings.TrimPrefix(strings.TrimSuffix(scopeName, ".scope"), "session-")

	cgroupID, err := cgroupInode(scopePath)
	if err != nil {
		log.Printf("sessionStarted: stat %s: %v", scopePath, err)
		return
	}

	meta, err := loginctlSession(num)
	if err != nil {
		log.Printf("sessionStarted: loginctl session %s: %v", num, err)
		return
	}

	// Only record interactive TTY sessions (type=tty or type=unspecified).
	// Skip graphical sessions (type=x11/wayland/mir) and unattended services.
	if meta.stype != "" && meta.stype != "tty" && meta.stype != "unspecified" {
		return
	}

	sess := &activeSession{
		id:       generateSessionID(t.hostname, meta.user, num),
		user:     meta.user,
		host:     t.hostname,
		remote:   meta.remote,
		command:  meta.shell,
		cgroupID: cgroupID,
	}

	// Open logserver connection and send SESSION_START before registering
	// in the BPF map so that no events are dropped.
	if err := sess.connect(t.serverAddr, t.tlsCfg, t.verifyKey); err != nil {
		log.Printf("sessionStarted [%s]: connect to logserver: %v", sess.id, err)
		return
	}

	// Register in BPF map so the kernel starts capturing events.
	var key [64]byte
	copy(key[:], sess.id)
	if err := t.bpfMap.Put(cgroupID, key); err != nil {
		log.Printf("sessionStarted [%s]: bpf map put: %v", sess.id, err)
		sess.conn.Close()
		return
	}

	t.mu.Lock()
	t.sessions[cgroupID] = sess
	t.mu.Unlock()

	log.Printf("sessionStarted: %s user=%s remote=%s", sess.id, sess.user, sess.remote)
}

// sessionEnded is called when a session-N.scope directory is removed.
func (t *sessionTracker) sessionEnded(scopePath string) {
	cgroupID, err := cgroupInode(scopePath)
	if err != nil {
		// Directory already gone — find by path prefix is not feasible,
		// so we rely on the deferred cleanup in closeAll().
		return
	}

	t.mu.Lock()
	sess, ok := t.sessions[cgroupID]
	if ok {
		delete(t.sessions, cgroupID)
	}
	t.mu.Unlock()

	if !ok {
		return
	}

	_ = t.bpfMap.Delete(cgroupID)
	sess.close(0)
	log.Printf("sessionEnded: %s", sess.id)
}

// handleEvent decodes a ring buffer sample and routes it to the right session.
func (t *sessionTracker) handleEvent(raw []byte) {
	if len(raw) < int(unsafe.Sizeof(IoEvent{})) {
		return
	}
	var ev IoEvent
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &ev); err != nil {
		return
	}

	t.mu.Lock()
	sess, ok := t.sessions[ev.CgroupID]
	t.mu.Unlock()

	if !ok {
		return
	}

	data := ev.Data[:ev.DataLen]
	sess.sendChunk(int64(ev.TimestampNS), ev.Stream, data)
}

// closeAll sends SESSION_END for every active session (called on daemon shutdown).
func (t *sessionTracker) closeAll() {
	t.mu.Lock()
	sessions := make([]*activeSession, 0, len(t.sessions))
	for id, s := range t.sessions {
		sessions = append(sessions, s)
		_ = t.bpfMap.Delete(id)
	}
	t.sessions = map[uint64]*activeSession{}
	t.mu.Unlock()

	for _, s := range sessions {
		s.close(0)
	}
}

// ── activeSession methods ─────────────────────────────────────────────────────

// connect opens a TLS connection to the logserver and sends SESSION_START.
func (s *activeSession) connect(addr string, tlsCfg *tls.Config, verifyKey []byte) error {
	rawTCP, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("dial %s: %w", addr, err)
	}

	tc := rawTCP.(*net.TCPConn)
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(1 * time.Second)

	// Resolve ServerName from addr if not already set.
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

	// Send SESSION_START.
	start := protocol.SessionStart{
		SessionID: s.id,
		User:      s.user,
		Host:      s.host,
		Command:   s.command,
		Ts:        time.Now().Unix(),
		Pid:       os.Getpid(),
	}
	payload, err := json.Marshal(start)
	if err != nil {
		tlsConn.Close()
		return fmt.Errorf("marshal session start: %w", err)
	}
	if err := protocol.WriteMessage(s.bw, protocol.MsgSessionStart, payload); err != nil {
		tlsConn.Close()
		return fmt.Errorf("send session start: %w", err)
	}

	// Start background goroutines for heartbeat and ACK draining.
	go s.heartbeat()
	go s.drainACKs(verifyKey)

	return nil
}

// sendChunk encodes and sends one I/O event to the logserver.
func (s *activeSession) sendChunk(tsNS int64, stream uint8, data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.done || s.conn == nil {
		return
	}

	s.seq++
	payload := encodeChunk(s.seq, tsNS, stream, data)
	if err := protocol.WriteMessage(s.bw, protocol.MsgChunk, payload); err != nil {
		log.Printf("[%s] send chunk: %v", s.id, err)
		s.done = true
	}
}

// close sends SESSION_END and closes the connection.
func (s *activeSession) close(exitCode int32) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.done || s.conn == nil {
		return
	}
	s.done = true

	payload := encodeSessionEnd(s.seq, exitCode)
	_ = protocol.WriteMessage(s.bw, protocol.MsgSessionEnd, payload)
	s.conn.Close()
}

// heartbeat sends a HEARTBEAT every 400 ms (mirrors sudo-shipper behaviour).
func (s *activeSession) heartbeat() {
	ticker := time.NewTicker(400 * time.Millisecond)
	defer ticker.Stop()
	for range ticker.C {
		s.mu.Lock()
		done := s.done
		if !done {
			_ = protocol.WriteMessage(s.bw, protocol.MsgHeartbeat, nil)
		}
		s.mu.Unlock()
		if done {
			return
		}
	}
}

// drainACKs reads and discards ACK and HEARTBEAT_ACK messages from the server.
// Since the eBPF recorder cannot freeze processes, ACKs are only used for
// logging stalls.  Pass verifyKey != nil to log signature failures.
func (s *activeSession) drainACKs(verifyKey []byte) {
	br := bufio.NewReader(s.conn)
	lastACK := time.Now()

	for {
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
				ack, err := protocol.ParseAck(payload)
				if err == nil {
					if !verifyACK(ack, s.id, verifyKey) {
						log.Printf("[%s] ACK signature verification failed (seq %d)", s.id, ack.Seq)
					}
				}
			}
			lastACK = time.Now()

		case protocol.MsgHeartbeatAck:
			lastACK = time.Now()

		default:
			// Ignore unknown message types.
		}

		// Warn if no ACK/heartbeat for >5 seconds — server may be stalled.
		if time.Since(lastACK) > 5*time.Second {
			log.Printf("[%s] warning: no ACK from logserver for >5s", s.id)
			lastACK = time.Now() // reset to avoid log spam
		}
	}
}

// ── Helper functions ──────────────────────────────────────────────────────────

// cgroupInode returns the inode number of path, which equals the BPF cgroup ID.
func cgroupInode(path string) (uint64, error) {
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return 0, err
	}
	return st.Ino, nil
}

// sessionMeta holds metadata returned by loginctl.
type sessionMeta struct {
	user   string
	remote string // remote IP for SSH, empty for local tty
	shell  string // login shell / command
	stype  string // session type: tty, x11, wayland, mir, unspecified
}

// loginctlSession queries systemd-logind for session metadata.
// Requires logind to be running (always the case on Fedora with systemd).
func loginctlSession(num string) (sessionMeta, error) {
	props := []string{"Name", "RemoteHost", "Type", "Class"}
	args := append([]string{"show-session", "--value", "--property=" + strings.Join(props, ","), num})
	out, err := exec.Command("loginctl", args...).Output()
	if err != nil {
		return sessionMeta{}, fmt.Errorf("loginctl show-session %s: %w", num, err)
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) < len(props) {
		return sessionMeta{}, fmt.Errorf("loginctl returned %d lines, want %d", len(lines), len(props))
	}

	meta := sessionMeta{
		user:   lines[0],
		remote: lines[1],
		stype:  lines[2],
		// class is lines[3] — used for filtering in sessionStarted
	}

	// Get the login shell from /etc/passwd as a best-effort command name.
	if shell, err := userShell(meta.user); err == nil {
		meta.shell = shell
	} else {
		meta.shell = "/bin/bash"
	}

	return meta, nil
}

// userShell looks up the login shell for username in /etc/passwd.
func userShell(username string) (string, error) {
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return "", err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), ":")
		if len(fields) >= 7 && fields[0] == username {
			return fields[6], nil
		}
	}
	return "", fmt.Errorf("user %q not found", username)
}

// generateSessionID creates a unique session identifier compatible with the
// logserver's validSessionID regexp: [a-zA-Z0-9._-]{1,255}.
func generateSessionID(hostname, user, sessionNum string) string {
	ts := strconv.FormatInt(time.Now().UnixNano(), 10)
	// Sanitize components.
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
	id := fmt.Sprintf("ebpf.%s.%s.%s.%s", safe(hostname), safe(user), sessionNum, ts)
	if len(id) > 200 {
		id = id[:200]
	}
	return id
}

// encodeChunk encodes a CHUNK payload (mirrors loadgen's local helper and
// protocol.ParseChunk's expected layout: seq(8) ts(8) stream(1) len(4) data).
func encodeChunk(seq uint64, tsNS int64, stream uint8, data []byte) []byte {
	buf := make([]byte, 21+len(data))
	binary.BigEndian.PutUint64(buf[0:], seq)
	binary.BigEndian.PutUint64(buf[8:], uint64(tsNS))
	buf[16] = stream
	binary.BigEndian.PutUint32(buf[17:], uint32(len(data)))
	copy(buf[21:], data)
	return buf
}

// encodeSessionEnd encodes a SESSION_END payload: final_seq(8) exit_code(4).
func encodeSessionEnd(finalSeq uint64, exitCode int32) []byte {
	buf := make([]byte, 12)
	binary.BigEndian.PutUint64(buf[0:], finalSeq)
	binary.BigEndian.PutUint32(buf[8:], uint32(exitCode))
	return buf
}
