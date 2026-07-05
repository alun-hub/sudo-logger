// Package protocol defines the wire format shared between the C plugin,
// the local agent daemon, and the remote log server.
//
// Frame format (all integers big-endian):
//
//	[1 byte: type][4 bytes: payload length][N bytes: payload]
//
// Message types:
//
//	0x01  SESSION_START   plugin→agent→server  JSON payload (SessionStart)
//	0x02  CHUNK           plugin→agent→server  binary payload (Chunk)
//	0x03  SESSION_END     plugin→agent→server  binary payload (SessionEnd)
//	0x04  ACK             server→agent          binary payload (Ack)
//	0x05  ACK_QUERY       plugin→agent          empty
//	0x06  ACK_RESPONSE    agent→plugin          binary: last_ack_ts_ns(8) + last_seq(8)
//	0x07  SESSION_READY   agent→plugin          empty — server connection OK, sudo may proceed
//	0x08  SESSION_ERROR   agent→plugin          string error message — sudo blocked
//	0x09  HEARTBEAT       agent→server          empty — keepalive probe (every 400 ms)
//	0x0a  HEARTBEAT_ACK   server→agent          empty — immediate reply to HEARTBEAT
//	0x0b  SERVER_READY    server→agent          empty — session accepted, agent may send SESSION_READY
//	0x0c  SESSION_DENIED  server→agent,         string block message — policy denial, sudo blocked
//	                      agent→plugin
//	0x0d  FREEZE_TIMEOUT  agent→plugin          empty — server unreachable too long, session will be terminated
//	0x0e  SESSION_ABANDON agent→server (new conn) UTF-8 session_id — freeze-timeout fired
//	0x0f  SESSION_FREEZING agent→server (new conn) UTF-8 session_id — session frozen due to network loss
//	0x10  DIVERGENCE_ALERT agent→server         JSON — execve seen but no plugin SESSION_START within 30s
//	0x11  SANDBOX_ALERT   agent→server          JSON — sandbox violation blocked by kernel LSM
//	0x12  FETCH_CONFIG    agent→server          UTF-8 config key (e.g. "sandbox.yaml")
//	0x13  CONFIG_DATA     server→agent          UTF-8 YAML content (empty = not found)
//	0x14  SESSION_CHALLENGE server→agent→plugin JSON payload (SessionChallenge) — justification required
//	0x15  SESSION_CHALLENGE_RESPONSE plugin→agent→server JSON payload (SessionChallengeResponse)
//	0x16  SESSION_EXPIRED agent→plugin          empty — approval window expired, session is being terminated
//	0x17  SESSION_WARNING agent→plugin          UTF-8 seconds left — session will be terminated soon
//	0x18  SUDOERS_SNAPSHOT agent→server         JSON payload (SudoersSnapshot)
//	0x19  SUDOERS_ERROR   agent→server          JSON payload (SudoersError) — failed to apply config
//	0x1a  HEARTBEAT_AGENT agent→server          UTF-8 host — periodic liveness signal
//	0x1b  RESIZE          plugin→agent→server  binary: ts_ns(8BE)+cols(2BE)+rows(2BE); writes asciinema "r" event
//
// CHUNK stream types map to sudo's iolog event types (see iolog/iolog.go):
//
//	0x00  STREAM_STDIN    non-tty standard input
//	0x01  STREAM_STDOUT   non-tty standard output
//	0x02  STREAM_STDERR   standard error
//	0x03  STREAM_TTYIN    terminal input  (iolog EventTtyIn)
//	0x04  STREAM_TTYOUT   terminal output (iolog EventTtyOut)
package protocol

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"sync"
)

const (
	MsgSessionStart = uint8(0x01)
	MsgChunk        = uint8(0x02)
	MsgSessionEnd   = uint8(0x03)
	MsgAck          = uint8(0x04)
	MsgAckQuery     = uint8(0x05)
	MsgAckResponse  = uint8(0x06)
	MsgSessionReady  = uint8(0x07) // agent→plugin: server connection OK
	MsgSessionError  = uint8(0x08) // agent→plugin: server connection failed
	MsgHeartbeat     = uint8(0x09) // agent→server: keepalive probe
	MsgHeartbeatAck  = uint8(0x0a) // server→agent: keepalive reply
	MsgServerReady   = uint8(0x0b) // server→agent: session accepted, proceed
	MsgSessionDenied  = uint8(0x0c) // server→agent AND agent→plugin: policy denial
	MsgFreezeTimeout  = uint8(0x0d) // agent→plugin: server unreachable for too long, session will be terminated
	MsgSessionAbandon  = uint8(0x0e) // agent→server (new conn): freeze-timeout fired; payload = session_id UTF-8
	MsgSessionFreezing  = uint8(0x0f) // agent→server (new conn): session frozen due to network loss; payload = session_id UTF-8
	MsgDivergenceAlert  = uint8(0x10) // agent→server: sudo execve seen but no plugin SESSION_START within 30s
	MsgSandboxAlert     = uint8(0x11) // agent→server: sandbox violation blocked by kernel LSM
	MsgFetchConfig      = uint8(0x12) // agent→server: request named config; payload = UTF-8 key
	MsgConfigData       = uint8(0x13) // server→agent: config response;     payload = UTF-8 YAML (empty = not found)
	MsgSessionChallenge = uint8(0x14) // server→agent→plugin: justification required; payload = JSON (SessionChallenge)
	MsgSessionChallengeResponse = uint8(0x15) // plugin→agent→server: user response; payload = JSON (SessionChallengeResponse)
	MsgSessionExpired           = uint8(0x16) // agent→plugin: approval window expired, session is being terminated
	MsgSessionWarning           = uint8(0x17) // agent→plugin: session will be terminated soon; payload = UTF-8 seconds left
	MsgSudoersSnapshot          = uint8(0x18) // agent→server: sudoers state snapshot; payload = JSON (SudoersSnapshot)
	MsgSudoersError             = uint8(0x19) // agent→server: failed to apply config; payload = JSON (SudoersError)
	MsgHeartbeatAgent           = uint8(0x1a) // agent→server: periodic liveness signal; payload = UTF-8 host
	MsgResize                   = uint8(0x1b) // plugin→agent→server: terminal resize; payload = ts_ns(8BE)+cols(2BE)+rows(2BE)

	StreamStdin   = uint8(0x00)

	StreamStdout  = uint8(0x01)
	StreamStderr  = uint8(0x02)
	StreamTtyIn   = uint8(0x03)
	StreamTtyOut  = uint8(0x04)
)

// SessionStart is the JSON-encoded SESSION_START payload.
type SessionStart struct {
	SessionID string `json:"session_id"`
	User      string `json:"user"`
	Host      string `json:"host"`
	Command   string `json:"command"`
	Ts        int64  `json:"ts"`  // unix seconds
	Pid       int    `json:"pid"` // sudo process PID — used by the agent for cgroup setup
	// Extended metadata — populated by plugin v1.7.0+.
	// Older clients omit these fields; receivers must tolerate zero values.
	ResolvedCommand string `json:"resolved_command,omitempty"` // full binary path from command_info[]
	RunasUser       string `json:"runas_user,omitempty"`       // target user (-u), default "root"
	RunasUID        int    `json:"runas_uid"`                  // numeric UID from command_info[]
	RunasGID        int    `json:"runas_gid"`                  // numeric GID from command_info[]
	Cwd             string `json:"cwd,omitempty"`              // working directory from command_info[]
	Flags           string `json:"flags,omitempty"`            // set sudo flags: login_shell, preserve_env, implied_shell
	Rows            int    `json:"rows,omitempty"`             // terminal height from command_info[lines=]
	Cols            int    `json:"cols,omitempty"`             // terminal width from command_info[cols=]
	TtyPath         string `json:"tty_path,omitempty"`         // controlling terminal device, e.g. /dev/pts/3; empty for non-tty sessions
	UserUID         int    `json:"user_uid,omitempty"`         // invoking user's UID from user_info[]
	UserGID         int    `json:"user_gid,omitempty"`         // invoking user's primary GID from user_info[]
	// Source identifies the recording path (added by agent v2+).
	// "plugin" = sudo C plugin (default, omitempty means old agents look the same).
	// "ebpf-tty" = eBPF TTY session (SSH/su/screen without sudo).
	// "ebpf-pkexec" = polkit/pkexec privilege elevation.
	// Receivers must tolerate an empty value (treat as "plugin").
	Source          string `json:"source,omitempty"`
	// ParentSessionID links an ebpf-pkexec session to its parent SSH/TTY session.
	ParentSessionID string `json:"parent_session_id,omitempty"`
	// HasIO is false for pkexec background services that produce no TTY output.
	// Omitted (false) for all plugin sessions (backward compatible).
	HasIO           bool   `json:"has_io,omitempty"`
	// DivergenceStatus is set by the agent before forwarding to the server.
	// "confirmed" = eBPF witnessed the sudo execve; "unwitnessed" = eBPF was
	// not running or did not see the execve (plugin-only mode).
	// Empty is treated as "unwitnessed" for backward compatibility.
	DivergenceStatus string `json:"divergence_status,omitempty"`
	// CallerProcess is the process name that triggered the polkit authorization
	// (for dbus-polkit: process comm or inferred service name like "firewalld").
	// Empty for plugin and ebpf-tty sessions.
	CallerProcess string `json:"caller_process,omitempty"`
	// Justification is the reason the user provided when prompted by the plugin.
	// Empty when the host does not have require_justification enabled or when
	// the user ran sudo non-interactively (cron, scripts).
	Justification string `json:"justification,omitempty"`
	// NotifyVia is an optional contact handle the user supplied at prompt time
	// (e.g. a Slack username) so the notification system can route approvals.
	NotifyVia string `json:"notify_via,omitempty"`
	// Groups holds the invoking user's resolved group memberships at session time.
	// Populated by the agent via NSS (id -Gn equivalent), so SSSD/winbind/AD
	// groups are included automatically. Empty for older agents.
	Groups []string `json:"groups,omitempty"`
}

// DivergenceAlert is the JSON payload for MsgDivergenceAlert.
// Sent by the agent when eBPF sees a sudo/pkexec execve but no plugin
// SESSION_START arrives within 30 seconds — indicating tampered sudo.conf.
type DivergenceAlert struct {
	User    string `json:"user"`
	Host    string `json:"host"`
	Comm    string `json:"comm"`    // "sudo" or "pkexec"
	Ts      int64  `json:"ts"`      // Unix timestamp of the execve event
}

// SandboxAlert is the JSON payload for MsgSandboxAlert.
// Sent by the agent when the kernel LSM blocks an operation.
type SandboxAlert struct {
	SessionID string `json:"session_id,omitempty"` // mapped from cgroup_id in userspace
	Pid       uint32 `json:"pid"`
	Comm      string `json:"comm"`
	Type      uint32 `json:"type"`
	Ts        int64  `json:"ts"`
}

// ServerReadyBody is the optional JSON payload in a SERVER_READY message (server→agent).
// SessionTTL, when non-zero, is the number of seconds the session may remain active
// before the agent forcibly terminates it (approval-window or max_session_duration).
type ServerReadyBody struct {
	SessionTTL int64 `json:"session_ttl,omitempty"`
}

// SessionReadyBody is the optional JSON payload in a SESSION_READY message.
// Disclaimer, if non-empty, is printed to the user's terminal before sudo proceeds.
type SessionReadyBody struct {
	Disclaimer      string `json:"disclaimer,omitempty"`       // optional notice shown at session start
	SessionTTL      int64  `json:"session_ttl,omitempty"`      // mirrors ServerReadyBody; plugin may display a warning
	FreezeTimeoutSecs int64 `json:"freeze_timeout_secs,omitempty"` // seconds until frozen session is terminated
}

// SessionChallenge is the JSON payload for MsgSessionChallenge.
type SessionChallenge struct {
	HasWebhook bool `json:"has_webhook"`
}

// SessionChallengeResponse is the JSON payload for MsgSessionChallengeResponse.
type SessionChallengeResponse struct {
	Justification string `json:"justification"`
}

// SudoersSnapshot is the JSON payload for MsgSudoersSnapshot.
// The agent sends one on startup and again whenever /etc/sudoers or
// /etc/sudoers.d/* changes. Content is a concatenation of all sudoers files
// separated by "# --- <path> ---" section headers.
type SudoersSnapshot struct {
	Host    string        `json:"host"`
	Content string        `json:"content"` // full concatenated text of all files
	SHA256  string        `json:"sha256"`  // hex sha256 of Content
	Files   []SudoersFile `json:"files"`
}

// SudoersFile is a single file included in a SudoersSnapshot.
type SudoersFile struct {
	Path    string `json:"path"`
	Content string `json:"content"`
	SHA256  string `json:"sha256"`
}

// SudoersError is the JSON payload for MsgSudoersError.
// Sent by the agent when it fails to apply a received configuration (e.g. visudo -c fails).
type SudoersError struct {
	Host    string `json:"host"`
	Error   string `json:"error"`
	SHA256  string `json:"sha256"` // the sha256 of the config that failed to apply
	Ts      int64  `json:"ts"`     // unix seconds
}

// Chunk is a decoded CHUNK message.
type Chunk struct {
	Seq       uint64
	Timestamp int64 // unix nanoseconds
	Stream    uint8
	Data      []byte
}

// SessionEnd is a decoded SESSION_END message.
type SessionEnd struct {
	FinalSeq uint64
	ExitCode int32
}

// Ack is a decoded ACK message (server → agent).
//
// Payload layout: [8 seq][8 ts_ns][64 sig]
// sig is an ed25519 signature over AckSignMessage(sessionID, seq, ts_ns).
type Ack struct {
	Seq       uint64
	Timestamp int64
	Sig       [64]byte
}

// WriteMessage writes a framed message to w.
func WriteMessage(w *bufio.Writer, msgType uint8, payload []byte) error {
	if err := WriteMessageNoFlush(w, msgType, payload); err != nil {
		return err
	}
	return w.Flush()
}

// WriteMessageNoFlush writes a framed message to w without flushing.
func WriteMessageNoFlush(w *bufio.Writer, msgType uint8, payload []byte) error {
	hdr := [5]byte{msgType}
	binary.BigEndian.PutUint32(hdr[1:], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := w.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

// ReadHeader reads a 5-byte message header from r.
func ReadHeader(r io.Reader) (msgType uint8, payloadLen uint32, err error) {
	var hdr [5]byte
	if _, err = io.ReadFull(r, hdr[:]); err != nil {
		return
	}
	msgType = hdr[0]
	payloadLen = binary.BigEndian.Uint32(hdr[1:])
	return
}

// maxPayloadSize is the largest payload we will allocate for a single chunk.
// A single tty chunk is at most a few KB; 1 MB is generous.
const maxPayloadSize = uint32(1 * 1024 * 1024) // 1 MB

// MaxSessionStartPayload is the per-type size limit for SESSION_START messages.
// SESSION_START carries JSON metadata only — 64 KB is generous.
// Callers must check this before calling ReadPayload to prevent a malicious
// (mTLS-authenticated) agent from triggering a 1 MB allocation per connection.
const MaxSessionStartPayload = uint32(64 * 1024) // 64 KB

// MaxSudoersPayload is the per-type size limit for SUDOERS_SNAPSHOT messages.
// Sudoers files are text-only; 256 KB is generous for even large deployments.
const MaxSudoersPayload = uint32(256 * 1024) // 256 KB

// ReadPayload reads exactly payloadLen bytes from r.
// Returns an error if payloadLen exceeds maxPayloadSize to prevent
// a malicious client from triggering an OOM allocation.
func ReadPayload(r io.Reader, payloadLen uint32) ([]byte, error) {
	if payloadLen == 0 {
		return nil, nil
	}
	if payloadLen > maxPayloadSize {
		return nil, fmt.Errorf("payload length %d exceeds maximum %d", payloadLen, maxPayloadSize)
	}
	buf := make([]byte, payloadLen)
	_, err := io.ReadFull(r, buf)
	return buf, err
}

// ParseSessionStart decodes a SESSION_START payload.
func ParseSessionStart(payload []byte) (*SessionStart, error) {
	var s SessionStart
	if err := json.Unmarshal(payload, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// ParseChunk decodes a CHUNK payload.
// Layout: [8 seq][8 ts_ns][1 stream][4 datalen][data]
func ParseChunk(payload []byte) (*Chunk, error) {
	if len(payload) < 21 {
		return nil, fmt.Errorf("chunk payload too short: %d bytes", len(payload))
	}
	dlen := binary.BigEndian.Uint32(payload[17:21])
	// Compare in 64-bit space: "21+dlen" in uint32 wraps when dlen is near
	// 2^32, which would bypass this guard and lead to a ~4 GB allocation or a
	// slice-bounds panic in the copy below — a remotely triggerable crash for
	// any client holding a valid mTLS certificate.
	if uint64(dlen) > uint64(len(payload))-21 {
		return nil, fmt.Errorf("chunk data truncated")
	}
	c := &Chunk{
		Seq:       binary.BigEndian.Uint64(payload[0:8]),
		Timestamp: int64(binary.BigEndian.Uint64(payload[8:16])),
		Stream:    payload[16],
		Data:      make([]byte, dlen),
	}
	copy(c.Data, payload[21:21+dlen])
	return c, nil
}

// EncodeChunk encodes a CHUNK payload.
// Layout: [8 seq][8 ts_ns][1 stream][4 datalen][data]
func EncodeChunk(seq uint64, ts int64, stream uint8, data []byte) []byte {
	dlen := uint32(len(data))
	payload := make([]byte, 21+dlen)
	binary.BigEndian.PutUint64(payload[0:8], seq)
	binary.BigEndian.PutUint64(payload[8:16], uint64(ts))
	payload[16] = stream
	binary.BigEndian.PutUint32(payload[17:21], dlen)
	copy(payload[21:], data)
	return payload
}

// EncodeSessionEnd encodes a SESSION_END payload.
// Layout: [8 final_seq][4 exit_code]
func EncodeSessionEnd(finalSeq uint64, exitCode int32) []byte {
	payload := make([]byte, 12)
	binary.BigEndian.PutUint64(payload[0:8], finalSeq)
	binary.BigEndian.PutUint32(payload[8:12], uint32(exitCode))
	return payload
}

// ParseSessionEnd decodes a SESSION_END payload.
// Layout: [8 final_seq][4 exit_code]
func ParseSessionEnd(payload []byte) (*SessionEnd, error) {
	if len(payload) < 12 {
		return nil, fmt.Errorf("session_end payload too short")
	}
	return &SessionEnd{
		FinalSeq: binary.BigEndian.Uint64(payload[0:8]),
		ExitCode: int32(binary.BigEndian.Uint32(payload[8:12])),
	}, nil
}

// ParseAck decodes an ACK payload.
// Layout: [8 seq][8 ts_ns][64 sig]
func ParseAck(payload []byte) (*Ack, error) {
	if len(payload) < 80 {
		return nil, fmt.Errorf("ack payload too short")
	}
	a := &Ack{
		Seq:       binary.BigEndian.Uint64(payload[0:8]),
		Timestamp: int64(binary.BigEndian.Uint64(payload[8:16])),
	}
	copy(a.Sig[:], payload[16:80])
	return a, nil
}

// EncodeAck encodes an ACK payload with the given ed25519 signature.
// ts must be the same value used when computing sig.
func EncodeAck(seq uint64, ts int64, sig [64]byte) []byte {
	buf := make([]byte, 80)
	binary.BigEndian.PutUint64(buf[0:], seq)
	binary.BigEndian.PutUint64(buf[8:], uint64(ts))
	copy(buf[16:], sig[:])
	return buf
}

// AckSignMessage returns the canonical byte string signed by the server and
// verified by the agent for each ACK.  Including the session ID prevents a
// valid ACK for one session from being replayed against a different session.
//
// Layout: sessionID || 0x00 || seq_be(8) || ts_ns_be(8)
// The null separator prevents length-extension confusion between a short
// sessionID+long seq and a longer sessionID+shorter seq pair.
func AckSignMessage(sessionID string, seq uint64, ts int64) []byte {
	msg := make([]byte, len(sessionID)+1+8+8)
	n := copy(msg, sessionID)
	msg[n] = 0x00
	binary.BigEndian.PutUint64(msg[n+1:], seq)
	binary.BigEndian.PutUint64(msg[n+9:], uint64(ts))
	return msg
}

// EncodeAckResponse encodes an ACK_RESPONSE payload for the plugin.
func EncodeAckResponse(lastTs int64, lastSeq uint64) []byte {
	buf := make([]byte, 16)
	binary.BigEndian.PutUint64(buf[0:], uint64(lastTs))
	binary.BigEndian.PutUint64(buf[8:], lastSeq)
	return buf
}

// Resize carries the dimensions from a MsgResize event.
type Resize struct {
	Timestamp int64 // nanoseconds since epoch
	Cols      int
	Rows      int
}

// ParseResize decodes a MsgResize payload: ts_ns(8BE)+cols(2BE)+rows(2BE).
func ParseResize(payload []byte) (*Resize, error) {
	if len(payload) < 12 {
		return nil, fmt.Errorf("resize payload too short: %d bytes", len(payload))
	}
	return &Resize{
		Timestamp: int64(binary.BigEndian.Uint64(payload[0:8])),
		Cols:      int(binary.BigEndian.Uint16(payload[8:10])),
		Rows:      int(binary.BigEndian.Uint16(payload[10:12])),
	}, nil
}

// Writer provides synchronized access to a server connection.
type Writer struct {
	mu *sync.Mutex
	w  *bufio.Writer
}

func NewWriter(w *bufio.Writer, mu *sync.Mutex) *Writer {
	return &Writer{w: w, mu: mu}
}

func (w *Writer) WriteMessage(msgType uint8, payload []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return WriteMessage(w.w, msgType, payload)
}

func (w *Writer) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.w.Flush()
}
