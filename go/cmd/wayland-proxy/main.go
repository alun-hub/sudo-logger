// wayland-proxy: transparent Wayland compositor proxy that intercepts
// wl_surface_commit calls to capture screen frames from a GUI session.
//
// Usage:
//
//	wayland-proxy --real <path-to-real-wayland-socket> --socket <proxy-socket-path>
//
// The proxy:
//  1. Creates a Unix socket at --socket.
//  2. Accepts exactly one client connection (the sudo'd GUI app).
//  3. Proxies all Wayland protocol messages bidirectionally to the real compositor.
//  4. Intercepts wl_surface_commit to read SHM buffer pixel data.
//  5. JPEG-encodes each captured frame and writes it to stdout as:
//     [4 bytes big-endian: frame_size][frame_size bytes: JPEG data]
//  6. Exits when the client disconnects.
//
// Rate-limit: at most one frame every 500 ms (≤2 fps).
// DMA-buf buffers are silently skipped (only SHM is supported).
package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"image"
	"image/color"
	"image/jpeg"
	"log"
	"net"
	"os"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// Wayland wire format constants.
const waylandHdrSize = 8 // sender_id(4) + opcode(2) + size(2)

// Wayland core interface opcodes (client → server requests).
const (
	// wl_display requests
	opDisplayGetRegistry = 1

	// wl_registry requests
	opRegistryBind = 0

	// wl_compositor requests
	opCompositorCreateSurface = 0

	// wl_shm requests
	opShmCreatePool = 0

	// wl_shm_pool requests
	opShmPoolCreateBuffer = 0
	opShmPoolDestroy      = 1
	opShmPoolResize       = 2

	// wl_surface requests
	opSurfaceDestroy = 0
	opSurfaceAttach  = 1
	opSurfaceCommit  = 6

	// wl_buffer requests
	opBufferDestroy = 0
)

// Wayland core event opcodes (server → client).
const (
	opDisplayDeleteID  = 1
	opRegistryGlobal   = 0
)

// wl_shm pixel formats we can handle.
const (
	fmtARGB8888 = 0
	fmtXRGB8888 = 1
)

// objectKind tracks what Wayland interface an object ID is bound to.
type objectKind uint8

const (
	kindUnknown   objectKind = iota
	kindRegistry             // wl_registry
	kindCompositor           // wl_compositor
	kindShm                  // wl_shm
	kindShmPool              // wl_shm_pool
	kindBuffer               // wl_buffer (shm-backed)
	kindSurface              // wl_surface
)

type shmPool struct {
	data []byte // mmap'd
	size int32
}

type bufInfo struct {
	poolID uint32
	offset int32
	width  int32
	height int32
	stride int32
	format uint32
}

type proxyState struct {
	mu sync.Mutex

	objects  map[uint32]objectKind
	pools    map[uint32]*shmPool
	buffers  map[uint32]*bufInfo
	attached map[uint32]uint32 // surfaceID → bufferID

	// IDs of global objects we care about (from registry).
	// We track interface names from wl_registry::global events.
	globalNames map[uint32]string // global name → interface name

	// Pending FDs received via SCM_RIGHTS on current message.
	pendingFDs []int

	lastFrame time.Time
	minPeriod time.Duration
}

func newProxyState() *proxyState {
	return &proxyState{
		objects:     make(map[uint32]objectKind),
		pools:       make(map[uint32]*shmPool),
		buffers:     make(map[uint32]*bufInfo),
		attached:    make(map[uint32]uint32),
		globalNames: make(map[uint32]string),
		minPeriod:   300 * time.Millisecond,
	}
}

// ── argument parsing helpers ─────────────────────────────────────────────────

func readUint32(b []byte) uint32 { return binary.LittleEndian.Uint32(b) }
func readInt32(b []byte) int32   { return int32(binary.LittleEndian.Uint32(b)) }

// forceCapture captures the current state of all surfaces immediately,
// ignoring the rate-limit timer. Used for the final frame before exit.
func (p *proxyState) forceCapture(out *os.File) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Capture all known surfaces that have a buffer attached.
	for surfaceID := range p.attached {
		p.doCapture(surfaceID, out, true)
	}
}

// readString parses a Wayland string: uint32 len (including NUL), bytes, padding.
func readString(b []byte) (string, int) {
	if len(b) < 4 {
		return "", 0
	}
	strLen := int(readUint32(b))
	if strLen == 0 {
		return "", 4
	}
	total := 4 + pad4(strLen)
	if len(b) < total {
		return "", total
	}
	s := string(b[4 : 4+strLen-1]) // strip NUL
	return s, total
}

func pad4(n int) int { return (n + 3) &^ 3 }

// ── frame capture ─────────────────────────────────────────────────────────────

func (p *proxyState) captureCommit(surfaceID uint32, out *os.File) {
	p.doCapture(surfaceID, out, false)
}

func (p *proxyState) doCapture(surfaceID uint32, out *os.File, force bool) {
	bufID, ok := p.attached[surfaceID]
	if !ok {
		return
	}
	buf, ok := p.buffers[bufID]
	if !ok {
		return
	}
	pool, ok := p.pools[buf.poolID]
	if !ok {
		return
	}

	now := time.Now()
	if !force && now.Sub(p.lastFrame) < p.minPeriod {
		return
	}

	if buf.format != fmtARGB8888 && buf.format != fmtXRGB8888 {
		return // unsupported format
	}

	offset := int(buf.offset)
	stride := int(buf.stride)
	w := int(buf.width)
	h := int(buf.height)

	if offset < 0 || stride < 0 || w <= 0 || h <= 0 {
		return
	}
	needed := offset + stride*h
	if pool.data == nil || needed > len(pool.data) {
		return
	}

	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	src := pool.data[offset:]
	for y := 0; y < h; y++ {
		row := src[y*stride : y*stride+w*4]
		for x := 0; x < w; x++ {
			b := row[x*4+0]
			g := row[x*4+1]
			r := row[x*4+2]
			// alpha ignored — treat as fully opaque
			img.SetNRGBA(x, y, color.NRGBA{R: r, G: g, B: b, A: 255})
		}
	}

	var buf2 bytes.Buffer
	if err := jpeg.Encode(&buf2, img, &jpeg.Options{Quality: 75}); err != nil {
		log.Printf("jpeg encode: %v", err)
		return
	}

	frame := buf2.Bytes()
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(frame)))
	out.Write(hdr[:])
	out.Write(frame)

	p.lastFrame = now
}

// ── message parsing (client → server direction) ───────────────────────────────

// parseClientMsg inspects a client→server message for state we need to track.
// msg is the full message bytes (header + args). fds are any FDs received
// along with this message via SCM_RIGHTS.
func (p *proxyState) parseClientMsg(msg []byte, fds []int, out *os.File) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(msg) < waylandHdrSize {
		return
	}
	senderID := readUint32(msg[0:4])
	opcode := binary.LittleEndian.Uint16(msg[4:6])
	args := msg[waylandHdrSize:]

	kind := p.objects[senderID]

	switch {
	// wl_display (id=1): get_registry(new_id)
	case senderID == 1 && opcode == opDisplayGetRegistry:
		if len(args) >= 4 {
			newID := readUint32(args[0:4])
			p.objects[newID] = kindRegistry
		}

	// wl_registry: bind(name, interface_name, version, new_id)
	case kind == kindRegistry && opcode == opRegistryBind:
		if len(args) < 4 {
			return
		}
		// name (uint32)
		off := 4
		// interface_name (string)
		iface, slen := readString(args[off:])
		off += slen
		if off+8 > len(args) {
			return
		}
		// version (uint32) + new_id (uint32)
		newID := readUint32(args[off+4 : off+8])
		switch iface {
		case "wl_compositor":
			p.objects[newID] = kindCompositor
		case "wl_shm":
			p.objects[newID] = kindShm
		}

	// wl_compositor: create_surface(new_id)
	case kind == kindCompositor && opcode == opCompositorCreateSurface:
		if len(args) >= 4 {
			newID := readUint32(args[0:4])
			p.objects[newID] = kindSurface
		}

	// wl_shm: create_pool(new_id, fd, size)
	// FD arrives via SCM_RIGHTS; inline args are new_id(4) + size(4).
	case kind == kindShm && opcode == opShmCreatePool:
		if len(args) < 8 || len(fds) == 0 {
			// close any leaked FDs
			for _, fd := range fds {
				syscall.Close(fd)
			}
			return
		}
		newID := readUint32(args[0:4])
		size := readInt32(args[4:8])
		fd := fds[0]
		// mmap the SHM pool
		data, err := syscall.Mmap(fd, 0, int(size),
			syscall.PROT_READ, syscall.MAP_SHARED)
		if err != nil {
			log.Printf("mmap shm pool: %v", err)
			return
		}
		p.pools[newID] = &shmPool{data: data, size: size}
		p.objects[newID] = kindShmPool
		// close remaining FDs (shouldn't be any more)
		for _, fd := range fds[1:] {
			syscall.Close(fd)
		}

	// wl_shm_pool: create_buffer(new_id, offset, width, height, stride, format)
	case kind == kindShmPool && opcode == opShmPoolCreateBuffer:
		if len(args) < 24 {
			return
		}
		newID := readUint32(args[0:4])
		p.buffers[newID] = &bufInfo{
			poolID: senderID,
			offset: readInt32(args[4:8]),
			width:  readInt32(args[8:12]),
			height: readInt32(args[12:16]),
			stride: readInt32(args[16:20]),
			format: readUint32(args[20:24]),
		}
		p.objects[newID] = kindBuffer

	// wl_shm_pool: resize(new_size) — re-mmap to new size
	case kind == kindShmPool && opcode == opShmPoolResize:
		if len(args) < 4 {
			return
		}
		pool, ok := p.pools[senderID]
		if !ok {
			return
		}
		newSize := readInt32(args[0:4])
		syscall.Munmap(pool.data)
		// The pool FD is gone; we need to get the new mapping from /proc/self/fd.
		// Since we already closed the FD after mmap, we can't resize properly.
		// Just mark the pool data as nil — future captures of this pool will skip.
		pool.data = nil
		pool.size = newSize

	// wl_shm_pool: destroy
	case kind == kindShmPool && opcode == opShmPoolDestroy:
		if pool, ok := p.pools[senderID]; ok {
			if pool.data != nil {
				syscall.Munmap(pool.data)
			}
			delete(p.pools, senderID)
		}
		delete(p.objects, senderID)

	// wl_surface: attach(buffer, x, y)
	case kind == kindSurface && opcode == opSurfaceAttach:
		if len(args) >= 4 {
			bufID := readUint32(args[0:4])
			if bufID == 0 {
				delete(p.attached, senderID)
			} else {
				p.attached[senderID] = bufID
			}
		}

	// wl_surface: commit() — capture frame
	case kind == kindSurface && opcode == opSurfaceCommit:
		p.captureCommit(senderID, out)

	// wl_surface: destroy
	case kind == kindSurface && opcode == opSurfaceDestroy:
		delete(p.attached, senderID)
		delete(p.objects, senderID)

	// wl_buffer: destroy
	case kind == kindBuffer && opcode == opBufferDestroy:
		delete(p.buffers, senderID)
		delete(p.objects, senderID)
	}
}

// parseServerMsg handles server→client events we need to track.
func (p *proxyState) parseServerMsg(msg []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(msg) < waylandHdrSize {
		return
	}
	senderID := readUint32(msg[0:4])
	opcode := binary.LittleEndian.Uint16(msg[4:6])
	args := msg[waylandHdrSize:]

	// wl_display::delete_id — server signals object is gone
	if senderID == 1 && opcode == opDisplayDeleteID {
		if len(args) >= 4 {
			deadID := readUint32(args[0:4])
			if pool, ok := p.pools[deadID]; ok {
				if pool.data != nil {
					syscall.Munmap(pool.data)
				}
				delete(p.pools, deadID)
			}
			delete(p.objects, deadID)
			delete(p.buffers, deadID)
			delete(p.attached, deadID)
		}
	}

	// wl_registry::global — track interface names
	if p.objects[senderID] == kindRegistry && opcode == opRegistryGlobal {
		if len(args) < 4 {
			return
		}
		name := readUint32(args[0:4])
		iface, _ := readString(args[4:])
		p.globalNames[name] = iface
	}
}

// ── low-level connection I/O ──────────────────────────────────────────────────

// readMsg reads one complete Wayland message from conn, also collecting any
// FDs sent via SCM_RIGHTS in the ancillary data.
func readMsg(conn *net.UnixConn) (msg []byte, fds []int, err error) {
	// Read the 8-byte header first to learn the message size.
	var hdr [waylandHdrSize]byte
	oob := make([]byte, 1024)

	n, oobn, _, _, err := conn.ReadMsgUnix(hdr[:], oob)
	if err != nil || n < waylandHdrSize {
		if err == nil {
			err = net.ErrClosed
		}
		return nil, nil, err
	}

	fds = parseFDs(oob[:oobn])
	msgSize := int(binary.LittleEndian.Uint16(hdr[6:8]))
	if msgSize < waylandHdrSize {
		msgSize = waylandHdrSize
	}

	msg = make([]byte, msgSize)
	copy(msg[:waylandHdrSize], hdr[:])

	if msgSize > waylandHdrSize {
		rest := msg[waylandHdrSize:]
		// More bytes may come in subsequent reads (TCP-style framing).
		off := 0
		for off < len(rest) {
			extraOOB := make([]byte, 512)
			nr, noobn, _, _, rerr := conn.ReadMsgUnix(rest[off:], extraOOB)
			if rerr != nil {
				return nil, fds, rerr
			}
			if noobn > 0 {
				fds = append(fds, parseFDs(extraOOB[:noobn])...)
			}
			off += nr
		}
	}
	return msg, fds, nil
}

// parseFDs extracts file descriptors from SCM_RIGHTS control message data.
func parseFDs(oob []byte) []int {
	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return nil
	}
	var fds []int
	for _, m := range msgs {
		got, err := syscall.ParseUnixRights(&m)
		if err == nil {
			fds = append(fds, got...)
		}
	}
	return fds
}

// writeMsg sends a Wayland message with optional FDs via SCM_RIGHTS.
func writeMsg(conn *net.UnixConn, msg []byte, fds []int) error {
	var oob []byte
	if len(fds) > 0 {
		oob = syscall.UnixRights(fds...)
	}
	_, _, err := conn.WriteMsgUnix(msg, oob, nil)
	return err
}

// ── proxy goroutines ──────────────────────────────────────────────────────────

// forwardClientToServer reads from client, parses for state, forwards to server.
func forwardClientToServer(
	client, server *net.UnixConn,
	state *proxyState,
	out *os.File,
	done chan<- struct{},
) {
	defer func() {
		server.CloseWrite()
		close(done)
	}()
	for {
		msg, fds, err := readMsg(client)
		if err != nil {
			return
		}

		// We need to dup the FDs before forwarding: one copy goes to the
		// compositor, one stays here for mmap'ing.
		var localFDs []int
		var remoteFDs []int
		for _, fd := range fds {
			dup, dupErr := syscall.Dup(fd)
			if dupErr != nil {
				localFDs = append(localFDs, fd) // keep original, can't dup
			} else {
				localFDs = append(localFDs, fd)
				remoteFDs = append(remoteFDs, dup)
			}
		}

		state.parseClientMsg(msg, localFDs, out)

		// Close local FDs now that parseClientMsg is done with them.
		for _, fd := range localFDs {
			syscall.Close(fd)
		}

		if err := writeMsg(server, msg, remoteFDs); err != nil {
			for _, fd := range remoteFDs {
				syscall.Close(fd)
			}
			return
		}
		for _, fd := range remoteFDs {
			syscall.Close(fd)
		}
	}
}

// forwardServerToClient reads from server, parses events, forwards to client.
func forwardServerToClient(
	server, client *net.UnixConn,
	state *proxyState,
) {
	defer client.CloseWrite()
	for {
		msg, fds, err := readMsg(server)
		if err != nil {
			return
		}
		state.parseServerMsg(msg)
		if err := writeMsg(client, msg, fds); err != nil {
			for _, fd := range fds {
				syscall.Close(fd)
			}
			return
		}
		for _, fd := range fds {
			syscall.Close(fd)
		}
	}
}

// ── main ──────────────────────────────────────────────────────────────────────

func main() {
	flagReal   := flag.String("real", "", "Path to the real Wayland compositor socket")
	flagSocket := flag.String("socket", "", "Path for our proxy socket (create and bind)")
	flagFD     := flag.Int("fd", 0, "Already-listening socket fd passed by the shipper")
	flagPeriod := flag.Int("period", 300, "Screen capture period in milliseconds")
	flag.Parse()

	if *flagReal == "" {
		log.Fatal("--real is required")
	}
	if *flagFD == 0 && *flagSocket == "" {
		log.Fatal("one of --fd or --socket is required")
	}

	log.Printf("wayland-proxy uid=%d gid=%d", os.Getuid(), os.Getgid())

	state := newProxyState()
	if *flagPeriod > 0 {
		state.minPeriod = time.Duration(*flagPeriod) * time.Millisecond
	}

	var ln net.Listener
	var err error
	if *flagFD > 0 {
		// Socket was created and is already listening; shipper passed the fd.
		f := os.NewFile(uintptr(*flagFD), "proxy-socket")
		ln, err = net.FileListener(f)
		f.Close()
		if err != nil {
			log.Fatalf("FileListener fd=%d: %v", *flagFD, err)
		}
	} else {
		os.Remove(*flagSocket)
		ln, err = net.Listen("unix", *flagSocket)
		if err != nil {
			log.Fatalf("listen %s: %v", *flagSocket, err)
		}
		if err := os.Chmod(*flagSocket, 0700); err != nil {
			log.Fatalf("chmod proxy socket: %v", err)
		}
		defer os.Remove(*flagSocket)
	}

	socketDesc := *flagSocket
	if socketDesc == "" {
		socketDesc = fmt.Sprintf("fd:%d", *flagFD)
	}
	log.Printf("wayland-proxy: listening on %s → %s", socketDesc, *flagReal)

	// Accept exactly one client connection.
	clientConn, err := ln.Accept()
	if err != nil {
		log.Fatalf("accept: %v", err)
	}
	ln.Close()
	log.Printf("wayland-proxy: client connected")

	// Connect to the real compositor.
	serverConn, err := net.Dial("unix", *flagReal)
	if err != nil {
		log.Fatalf("connect to compositor %s: %v", *flagReal, err)
	}

	clientUnix := clientConn.(*net.UnixConn)
	serverUnix := serverConn.(*net.UnixConn)

	out := os.Stdout

	done := make(chan struct{})
	go forwardClientToServer(clientUnix, serverUnix, state, out, done)
	go forwardServerToClient(serverUnix, clientUnix, state)

	<-done

	// Capture the final frame before exiting.
	state.forceCapture(out)

	serverUnix.Close()
	clientUnix.Close()

	// Cleanup mmap'd pools.
	for _, pool := range state.pools {
		if pool.data != nil {
			syscall.Munmap(pool.data)
		}
	}
}

// Ensure unsafe is used (needed for pointer operations in parseFDs path).
var _ = unsafe.Sizeof(0)
