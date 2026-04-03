package main

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"sudo-logger/internal/protocol"
)

var (
	flagSocket   = flag.String("socket", "/run/sudo-logger/plugin.sock", "Path to sudo-shipper Unix socket")
	flagChunks   = flag.Int("chunks", 10000, "Number of 1KB chunks to send per session")
	flagParallel = flag.Int("parallel", 1, "Number of parallel sessions to run")
)

func main() {
	flag.Parse()

	var wg sync.WaitGroup
	startAll := time.Now()

	log.Printf("Startar %d parallella sessioner med %d chunks var...", *flagParallel, *flagChunks)

	for i := 0; i < *flagParallel; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			runSession(fmt.Sprintf("loadtest-p%d-%d", id, time.Now().Unix()), *flagChunks)
		}(i)
	}

	wg.Wait()

	duration := time.Since(startAll)
	totalMB := float64((*flagParallel) * (*flagChunks) * 1024) / 1024 / 1024
	log.Printf("ALLA KLARA! Skickade totalt %.2f MB på %v (%.2f MB/s totalt)", totalMB, duration, totalMB/duration.Seconds())
}

func runSession(sessionID string, numChunks int) {
	// 1. Anslut till shippern
	conn, err := net.Dial("unix", *flagSocket)
	if err != nil {
		log.Printf("[%s] Kunde inte ansluta: %v", sessionID, err)
		return
	}
	defer conn.Close()

	pr := bufio.NewReader(conn)
	pw := bufio.NewWriter(conn)

	// 2. Skicka SESSION_START
	start := protocol.SessionStart{
		SessionID: sessionID,
		User:      "loadgen-bot",
		Host:      "fedora-perf-test",
		Command:   fmt.Sprintf("stress-test-parallel-%s", sessionID),
		Ts:        time.Now().Unix(),
		Pid:       os.Getpid(),
	}
	startPayload, _ := json.Marshal(start)
	if err := protocol.WriteMessage(pw, protocol.MsgSessionStart, startPayload); err != nil {
		log.Printf("[%s] Misslyckades att skicka SESSION_START: %v", sessionID, err)
		return
	}

	// 3. Vänta på SESSION_READY
	msgType, _, err := protocol.ReadHeader(pr)
	if err != nil || msgType != protocol.MsgSessionReady {
		log.Printf("[%s] Väntade på SESSION_READY, fick 0x%02x: %v", sessionID, msgType, err)
		return
	}

	// 4. Pumpa ut chunks
	data := make([]byte, 1024) // 1KB per paket
	for i := range data {
		data[i] = 'X'
	}

	for i := uint64(0); i < uint64(numChunks); i++ {
		chunkPayload := encodeChunk(i, time.Now().UnixNano(), protocol.StreamStdout, data)
		if err := protocol.WriteMessage(pw, protocol.MsgChunk, chunkPayload); err != nil {
			log.Printf("[%s] Fel vid sändning av chunk %d: %v", sessionID, i, err)
			return
		}
	}

	// 5. Skicka SESSION_END
	endPayload := make([]byte, 12)
	binary.BigEndian.PutUint64(endPayload[0:], uint64(numChunks))
	binary.BigEndian.PutUint32(endPayload[8:], 0)
	protocol.WriteMessage(pw, protocol.MsgSessionEnd, endPayload)
}

func encodeChunk(seq uint64, ts int64, stream uint8, data []byte) []byte {
	buf := make([]byte, 21+len(data))
	binary.BigEndian.PutUint64(buf[0:], seq)
	binary.BigEndian.PutUint64(buf[8:], uint64(ts))
	buf[16] = stream
	binary.BigEndian.PutUint32(buf[17:], uint32(len(data)))
	copy(buf[21:], data)
	return buf
}
