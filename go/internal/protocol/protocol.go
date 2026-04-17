// Package protocol defines the wire format shared between the C plugin,
// the local shipper daemon, and the remote log server.
//
// Frame format (all integers big-endian):
//
//	[1 byte: type][4 bytes: payload length][N bytes: payload]
//
// Message types:
//
//	0x01  SESSION_START   plugin→shipper→server  JSON payload (SessionStart)
//	0x02  CHUNK           plugin→shipper→server  binary payload (Chunk)
//	0x03  SESSION_END     plugin→shipper→server  binary payload (SessionEnd)
//	0x04  ACK             server→shipper          binary payload (Ack)
//	0x05  ACK_QUERY       plugin→shipper          empty
//	0x06  ACK_RESPONSE    shipper→plugin          binary: last_ack_ts_ns(8) + last_seq(8)
//	0x07  SESSION_READY   shipper→plugin          empty — server connection OK, sudo may proceed
//	0x08  SESSION_ERROR   shipper→plugin          string error message — sudo blocked
//	0x09  HEARTBEAT       shipper→server          empty — keepalive probe (every 400 ms)
//	0x0a  HEARTBEAT_ACK   server→shipper          empty — immediate reply to HEARTBEAT
//	0x0b  SERVER_READY    server→shipper          empty — session accepted, shipper may send SESSION_READY
//	0x0c  SESSION_DENIED  server→shipper,         string block message — policy denial, sudo blocked
//	                      shipper→plugin
//
// CHUNK stream types map to sudo's iolog event types (see iolog/iolog.go):
//
//	0x00  STREAM_STDIN    non-tty standard input
//	0x01  STREAM_STDOUT   non-tty standard output
//	0x02  STREAM_STDERR   standard error
//	0x03  STREAM_TTYIN    terminal input  (iolog EventTtyIn)
//	0x04  STREAM_TTYOUT   terminal output (iolog EventTtyOut)
//	0x05  STREAM_SCREEN   JPEG frame from Wayland proxy (GUI sessions)
package protocol

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

const (
	MsgSessionStart = uint8(0x01)
	MsgChunk        = uint8(0x02)
	MsgSessionEnd   = uint8(0x03)
	MsgAck          = uint8(0x04)
	MsgAckQuery     = uint8(0x05)
	MsgAckResponse  = uint8(0x06)
	MsgSessionReady  = uint8(0x07) // shipper→plugin: server connection OK
	MsgSessionError  = uint8(0x08) // shipper→plugin: server connection failed
	MsgHeartbeat     = uint8(0x09) // shipper→server: keepalive probe
	MsgHeartbeatAck  = uint8(0x0a) // server→shipper: keepalive reply
	MsgServerReady   = uint8(0x0b) // server→shipper: session accepted, proceed
	MsgSessionDenied  = uint8(0x0c) // server→shipper AND shipper→plugin: policy denial
	MsgFreezeTimeout  = uint8(0x0d) // shipper→plugin: server unreachable for too long, session will be terminated
	MsgSessionAbandon  = uint8(0x0e) // shipper→server (new conn): freeze-timeout fired; payload = session_id UTF-8
	MsgSessionFreezing = uint8(0x0f) // shipper→server (new conn): session frozen due to network loss; payload = session_id UTF-8

	StreamStdin   = uint8(0x00)
	StreamStdout  = uint8(0x01)
	StreamStderr  = uint8(0x02)
	StreamTtyIn   = uint8(0x03)
	StreamTtyOut  = uint8(0x04)
	StreamScreen  = uint8(0x05) // JPEG frame from Wayland proxy
)

// SessionStart is the JSON-encoded SESSION_START payload.
type SessionStart struct {
	SessionID string `json:"session_id"`
	User      string `json:"user"`
	Host      string `json:"host"`
	Command   string `json:"command"`
	Ts        int64  `json:"ts"`  // unix seconds
	Pid       int    `json:"pid"` // sudo process PID — used by the shipper for cgroup setup
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
	WaylandDisplay  string `json:"wayland_display,omitempty"`  // $WAYLAND_DISPLAY from the invoking user's env; empty when not set
	XdgRuntimeDir   string `json:"xdg_runtime_dir,omitempty"`  // $XDG_RUNTIME_DIR from the invoking user's env
}

// SessionReadyBody is the optional JSON payload in a SESSION_READY message.
// When the shipper starts a Wayland proxy for a GUI session it populates
// ProxyDisplay so the plugin can patch WAYLAND_DISPLAY before exec.
type SessionReadyBody struct {
	ProxyDisplay string `json:"proxy_display,omitempty"` // path to proxy Wayland socket
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

// Ack is a decoded ACK message (server → shipper).
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
	return w.Flush()
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
// (mTLS-authenticated) shipper from triggering a 1 MB allocation per connection.
const MaxSessionStartPayload = uint32(64 * 1024) // 64 KB

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
	if uint32(len(payload)) < 21+dlen {
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
// verified by the shipper for each ACK.  Including the session ID prevents a
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
