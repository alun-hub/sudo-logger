package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"sudo-logger/internal/protocol"
)

func TestHandleIO_BoundsCheck(t *testing.T) {
	// 1. Short raw bytes: should return early without panicking
	subsys := &ebpfSubsystem{
		sessions: make(map[uint64]*ebpfSession),
	}
	subsys.handleIO([]byte{1, 2, 3}) // Too short

	// 2. Normal event data length
	serverSide, agentSide := net.Pipe()
	defer serverSide.Close()
	defer agentSide.Close()

	sess := &ebpfSession{
		id:   "test-sess-1",
		conn: agentSide,
		bw:   bufio.NewWriter(agentSide),
	}
	subsys.sessions[12345] = sess

	normalData := []byte("hello")
	normalEvBytes := makeIOEventBytes(1, uint32(len(normalData)), 12345, normalData)

	type readResult struct {
		mType uint8
		plen  uint32
		err   error
	}

	resultChan := make(chan readResult, 1)
	go func() {
		r := bufio.NewReader(serverSide)
		mType, plen, err := protocol.ReadHeader(r)
		if err != nil {
			resultChan <- readResult{err: err}
			return
		}
		// Read payload to clear pipe
		_, _ = protocol.ReadPayload(r, plen)
		resultChan <- readResult{mType: mType, plen: plen}
	}()

	subsys.handleIO(normalEvBytes)
	sess.bw.Flush() // Flush since agent side uses buffered writer

	select {
	case res := <-resultChan:
		if res.err != nil {
			t.Errorf("ReadHeader error: %v", res.err)
		} else {
			if res.mType != protocol.MsgChunk {
				t.Errorf("Expected MsgChunk, got %d", res.mType)
			}
			expectedLen := uint32(21 + len(normalData))
			if res.plen != expectedLen {
				t.Errorf("Expected payload length %d, got %d", expectedLen, res.plen)
			}
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Timeout waiting for normal MsgChunk")
	}

	// 3. Corrupted/oversized event data length
	largeData := make([]byte, 4096)
	for i := range largeData {
		largeData[i] = 'A'
	}
	// Pass an oversized length value (e.g. 5000)
	corruptedEvBytes := makeIOEventBytes(1, 5000, 12345, largeData)

	resultChan2 := make(chan readResult, 1)
	go func() {
		r := bufio.NewReader(serverSide)
		mType, plen, err := protocol.ReadHeader(r)
		if err != nil {
			resultChan2 <- readResult{err: err}
			return
		}
		_, _ = protocol.ReadPayload(r, plen)
		resultChan2 <- readResult{mType: mType, plen: plen}
	}()

	subsys.handleIO(corruptedEvBytes)
	sess.bw.Flush()

	select {
	case res := <-resultChan2:
		if res.err != nil {
			t.Errorf("ReadHeader error: %v", res.err)
		} else {
			if res.mType != protocol.MsgChunk {
				t.Errorf("Expected MsgChunk, got %d", res.mType)
			}
			// DataLen should be clamped to 4096
			expectedLen := uint32(21 + 4096)
			if res.plen != expectedLen {
				t.Errorf("Expected clamped payload length %d, got %d", expectedLen, res.plen)
			}
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Timeout waiting for clamped MsgChunk")
	}
}

func makeIOEventBytes(stream uint8, dataLen uint32, cgroupID uint64, data []byte) []byte {
	var ev ioEvent
	ev.EventType = eventTypeIO
	ev.Stream = stream
	ev.DataLen = dataLen
	ev.CgroupID = cgroupID
	copy(ev.Data[:], data)

	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.LittleEndian, &ev)
	return buf.Bytes()
}
