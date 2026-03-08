// Package protocol defines the wire format shared between the C plugin,
// the local shipper daemon, and the remote log server.
//
// Frame format (all integers big-endian):
//   [1 byte: type][4 bytes: payload length][N bytes: payload]
//
// Message types:
//   0x01  SESSION_START  plugin→shipper→server  JSON payload
//   0x02  CHUNK          plugin→shipper→server  binary payload
//   0x03  SESSION_END    plugin→shipper→server  binary payload
//   0x04  ACK            server→shipper          binary payload
//   0x05  ACK_QUERY      plugin→shipper          empty
//   0x06  ACK_RESPONSE   shipper→plugin          binary payload
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

	StreamStdin  = uint8(0x00)
	StreamStdout = uint8(0x01)
	StreamStderr = uint8(0x02)
	StreamTtyIn  = uint8(0x03)
	StreamTtyOut = uint8(0x04)
)

// SessionStart is the JSON-encoded SESSION_START payload.
type SessionStart struct {
	SessionID string `json:"session_id"`
	User      string `json:"user"`
	Host      string `json:"host"`
	Command   string `json:"command"`
	Ts        int64  `json:"ts"`  // unix seconds
	Pid       int    `json:"pid"` // sudo process PID — used by the shipper for cgroup setup
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
// Payload layout: [8 seq][8 ts_ns][32 hmac]
type Ack struct {
	Seq       uint64
	Timestamp int64
	HMAC      [32]byte
}

// AckResponse is sent by the shipper to the plugin in reply to ACK_QUERY.
//
// Payload layout: [8 last_ack_ts_ns BE][8 last_ack_seq BE]
type AckResponse struct {
	LastAckTs  int64
	LastAckSeq uint64
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

// maxPayloadSize is the largest payload we will allocate.
// A single tty chunk is at most a few KB; 1 MB is generous.
const maxPayloadSize = uint32(1 * 1024 * 1024) // 1 MB

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
// Layout: [8 seq][8 ts_ns][32 hmac]
func ParseAck(payload []byte) (*Ack, error) {
	if len(payload) < 48 {
		return nil, fmt.Errorf("ack payload too short")
	}
	a := &Ack{
		Seq:       binary.BigEndian.Uint64(payload[0:8]),
		Timestamp: int64(binary.BigEndian.Uint64(payload[8:16])),
	}
	copy(a.HMAC[:], payload[16:48])
	return a, nil
}

// EncodeAck encodes an ACK payload with the given timestamp.
// ts must be the same value used when computing the HMAC.
func EncodeAck(seq uint64, ts int64, hmacBytes [32]byte) []byte {
	buf := make([]byte, 48)
	binary.BigEndian.PutUint64(buf[0:], seq)
	binary.BigEndian.PutUint64(buf[8:], uint64(ts))
	copy(buf[16:], hmacBytes[:])
	return buf
}

// EncodeAckResponse encodes an ACK_RESPONSE payload for the plugin.
func EncodeAckResponse(lastTs int64, lastSeq uint64) []byte {
	buf := make([]byte, 16)
	binary.BigEndian.PutUint64(buf[0:], uint64(lastTs))
	binary.BigEndian.PutUint64(buf[8:], lastSeq)
	return buf
}
