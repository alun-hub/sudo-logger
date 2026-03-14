package protocol_test

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"testing"

	"sudo-logger/internal/protocol"
)

// TestWriteReadMessage verifies the framing round-trip: write a message and
// read it back with ReadHeader + ReadPayload.
func TestWriteReadMessage(t *testing.T) {
	cases := []struct {
		msgType uint8
		payload []byte
	}{
		{protocol.MsgSessionStart, []byte(`{"session_id":"abc"}`)},
		{protocol.MsgHeartbeat, nil},
		{protocol.MsgSessionReady, nil},
		{protocol.MsgSessionError, []byte("connection refused")},
	}
	for _, tc := range cases {
		var buf bytes.Buffer
		w := bufio.NewWriter(&buf)
		if err := protocol.WriteMessage(w, tc.msgType, tc.payload); err != nil {
			t.Fatalf("WriteMessage type=0x%02x: %v", tc.msgType, err)
		}

		r := bufio.NewReader(&buf)
		gotType, plen, err := protocol.ReadHeader(r)
		if err != nil {
			t.Fatalf("ReadHeader type=0x%02x: %v", tc.msgType, err)
		}
		if gotType != tc.msgType {
			t.Errorf("type: got 0x%02x, want 0x%02x", gotType, tc.msgType)
		}
		gotPayload, err := protocol.ReadPayload(r, plen)
		if err != nil {
			t.Fatalf("ReadPayload: %v", err)
		}
		if !bytes.Equal(gotPayload, tc.payload) {
			t.Errorf("payload mismatch: got %q, want %q", gotPayload, tc.payload)
		}
	}
}

// TestParseChunkValid decodes a well-formed CHUNK payload.
func TestParseChunkValid(t *testing.T) {
	data := []byte("hello")
	var payload [21 + 5]byte
	binary.BigEndian.PutUint64(payload[0:], 42)          // seq
	binary.BigEndian.PutUint64(payload[8:], 1234567890)  // ts_ns
	payload[16] = protocol.StreamTtyOut                  // stream
	binary.BigEndian.PutUint32(payload[17:], uint32(len(data)))
	copy(payload[21:], data)

	c, err := protocol.ParseChunk(payload[:])
	if err != nil {
		t.Fatalf("ParseChunk: %v", err)
	}
	if c.Seq != 42 {
		t.Errorf("Seq: got %d, want 42", c.Seq)
	}
	if c.Stream != protocol.StreamTtyOut {
		t.Errorf("Stream: got 0x%02x, want 0x%02x", c.Stream, protocol.StreamTtyOut)
	}
	if !bytes.Equal(c.Data, data) {
		t.Errorf("Data mismatch: got %q, want %q", c.Data, data)
	}
}

// TestParseChunkTooShort verifies that a truncated payload returns an error.
func TestParseChunkTooShort(t *testing.T) {
	if _, err := protocol.ParseChunk([]byte{1, 2, 3}); err == nil {
		t.Error("expected error for too-short chunk payload")
	}
}

// TestParseSessionEnd decodes a valid SESSION_END payload.
func TestParseSessionEnd(t *testing.T) {
	var payload [12]byte
	binary.BigEndian.PutUint64(payload[0:], 99)  // final_seq
	binary.BigEndian.PutUint32(payload[8:], 42)  // exit_code

	end, err := protocol.ParseSessionEnd(payload[:])
	if err != nil {
		t.Fatalf("ParseSessionEnd: %v", err)
	}
	if end.FinalSeq != 99 {
		t.Errorf("FinalSeq: got %d, want 99", end.FinalSeq)
	}
	if end.ExitCode != 42 {
		t.Errorf("ExitCode: got %d, want 42", end.ExitCode)
	}
}

// TestParseSessionEndTooShort checks that a truncated payload returns an error.
func TestParseSessionEndTooShort(t *testing.T) {
	if _, err := protocol.ParseSessionEnd([]byte{0, 1, 2}); err == nil {
		t.Error("expected error for too-short session_end payload")
	}
}

// TestParseAckValid decodes a well-formed ACK payload.
func TestParseAckValid(t *testing.T) {
	var payload [80]byte
	binary.BigEndian.PutUint64(payload[0:], 7)           // seq
	binary.BigEndian.PutUint64(payload[8:], 9876543210)  // ts_ns
	for i := 16; i < 80; i++ {
		payload[i] = byte(i)
	}

	ack, err := protocol.ParseAck(payload[:])
	if err != nil {
		t.Fatalf("ParseAck: %v", err)
	}
	if ack.Seq != 7 {
		t.Errorf("Seq: got %d, want 7", ack.Seq)
	}
	if ack.Timestamp != 9876543210 {
		t.Errorf("Timestamp: got %d, want 9876543210", ack.Timestamp)
	}
}

// TestEncodeAckRoundtrip verifies EncodeAck → ParseAck roundtrip with ed25519,
// using AckSignMessage so the session ID is included in the signed payload.
func TestEncodeAckRoundtrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	sessionID := "testhost-alice-12345-1234567890123456789-abcd1234"
	seq := uint64(123)
	ts := int64(555000000000)

	msg := protocol.AckSignMessage(sessionID, seq, ts)
	sigSlice := ed25519.Sign(priv, msg)

	var sig [64]byte
	copy(sig[:], sigSlice)

	encoded := protocol.EncodeAck(seq, ts, sig)
	ack, err := protocol.ParseAck(encoded)
	if err != nil {
		t.Fatalf("ParseAck: %v", err)
	}
	if ack.Seq != seq {
		t.Errorf("Seq: got %d, want %d", ack.Seq, seq)
	}
	if ack.Sig != sig {
		t.Error("Sig mismatch after roundtrip")
	}
	if !ed25519.Verify(pub, msg, ack.Sig[:]) {
		t.Error("ed25519 signature verification failed after roundtrip")
	}
}

// TestReadPayloadSizeLimit ensures oversized payloads are rejected.
func TestReadPayloadSizeLimit(t *testing.T) {
	r := bufio.NewReader(bytes.NewReader(make([]byte, 0)))
	_, err := protocol.ReadPayload(r, 2*1024*1024) // 2 MB > max 1 MB
	if err == nil {
		t.Error("expected error for payload exceeding size limit")
	}
}

// TestEncodeAckResponse verifies the ACK_RESPONSE encoding matches manual encoding.
func TestEncodeAckResponse(t *testing.T) {
	resp := protocol.EncodeAckResponse(1234, 99)
	if len(resp) != 16 {
		t.Fatalf("EncodeAckResponse length: got %d, want 16", len(resp))
	}
	ts := int64(binary.BigEndian.Uint64(resp[0:8]))
	seq := binary.BigEndian.Uint64(resp[8:16])
	if ts != 1234 {
		t.Errorf("ts: got %d, want 1234", ts)
	}
	if seq != 99 {
		t.Errorf("seq: got %d, want 99", seq)
	}
}
