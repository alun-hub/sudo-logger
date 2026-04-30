// sudo-logger-agent: merged plugin handler (formerly sudo-shipper) and eBPF
// session recorder (formerly ebpf-recorder) in a single daemon.
//
// Start order:
//   1. Load config and TLS credentials.
//   2. Check kernel BTF availability.  If available (kernel ≥ 5.8 with
//      CONFIG_DEBUG_INFO_BTF=y), load eBPF objects and attach tracepoints.
//      Otherwise, log a warning and continue in plugin-only mode.
//   3. Open the Unix plugin socket (always).
//   4. Handle SIGTERM/SIGINT for graceful shutdown.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
)

var flagConfig = flag.String("config", "/etc/sudo-logger/shipper.conf", "Path to configuration file")

// Package-level state shared across plugin.go, ebpf.go, cgroup.go.
var (
	cfg        agentConfig
	verifyKey  ed25519.PublicKey
	tlsCfg     *tls.Config
	div        *divergenceTracker
	ebpfSys    *ebpfSubsystem
)

// debugLog is a no-op by default; replaced with log.Printf when debug=true.
var debugLog = func(format string, args ...any) {}

func main() {
	flag.Parse()

	var err error
	cfg, err = loadConfig(*flagConfig)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	if cfg.Debug {
		debugLog = log.Printf
	}

	verifyKey, err = loadEd25519PubKey(cfg.VerifyKey)
	if err != nil {
		log.Fatalf("load verify key: %v", err)
	}

	tlsCfg, err = buildTLSConfig(cfg)
	if err != nil {
		log.Fatalf("build TLS config: %v", err)
	}

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	div = newDivergenceTracker(hostname, func(user, host, comm string, ts time.Time) {
		log.Printf("ALERT: divergence detected — %s ran %q on %s without plugin logging", user, comm, host)
		go sendDivergenceAlert(user, host, comm, ts)
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Try to start the eBPF subsystem.
	if cfg.Ebpf {
		if err := checkBTFSupport(); err != nil {
			log.Printf("ebpf: %v — running in plugin-only mode", err)
		} else {
			ebpfSys = newEBPFSubsystem(cfg, tlsCfg, hostname, div)
			if err := ebpfSys.start(ctx); err != nil {
				log.Printf("ebpf: start failed: %v — running in plugin-only mode", err)
				ebpfSys = nil
			}
		}
	} else {
		log.Printf("ebpf: disabled by config — running in plugin-only mode")
	}

	// Remove stale socket from previous run.
	if err := os.Remove(cfg.Socket); err != nil && !os.IsNotExist(err) {
		log.Printf("remove stale socket: %v", err)
	}
	if err := os.MkdirAll("/run/sudo-logger", 0750); err != nil {
		log.Fatalf("mkdir /run/sudo-logger: %v", err)
	}

	ln, err := net.Listen("unix", cfg.Socket)
	if err != nil {
		log.Fatalf("listen unix %s: %v", cfg.Socket, err)
	}
	defer ln.Close()
	if err := os.Chmod(cfg.Socket, 0600); err != nil {
		log.Fatalf("chmod socket: %v", err)
	}

	// Graceful shutdown.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sigCh
		log.Printf("sudo-logger-agent shutting down")
		cancel()
		cleanupAllCgs()
		if ebpfSys != nil {
			ebpfSys.stop()
		}
		os.Exit(0)
	}()

	mode := "plugin-only"
	if ebpfSys != nil {
		mode = "plugin+eBPF"
	}
	log.Printf("sudo-logger-agent listening on %s, forwarding to %s [mode: %s]",
		cfg.Socket, cfg.Server, mode)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		if !isSudoConn(conn) {
			log.Printf("rejected non-root connection on plugin socket")
			conn.Close()
			continue
		}
		go handlePluginConn(conn)
	}
}

// checkBTFSupport verifies that the kernel exposes BTF data required by CO-RE.
func checkBTFSupport() error {
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		return fmt.Errorf("/sys/kernel/btf/vmlinux not found — requires CONFIG_DEBUG_INFO_BTF=y (RHEL 8.3+, Fedora 31+, Ubuntu 20.10+)")
	}
	var uts syscall.Utsname
	if err := syscall.Uname(&uts); err != nil {
		return fmt.Errorf("uname: %w", err)
	}
	// Require kernel >= 5.8 (BPF_MAP_TYPE_RINGBUF and cgroup_id() stability).
	var major, minor int
	release := utsnameToString(uts.Release[:])
	if n, _ := fmt.Sscanf(release, "%d.%d", &major, &minor); n < 2 {
		return fmt.Errorf("cannot parse kernel version %q", release)
	}
	if major < 5 || (major == 5 && minor < 8) {
		return fmt.Errorf("kernel %d.%d is too old — requires 5.8+ for ring buffer and stable cgroup IDs", major, minor)
	}
	return nil
}

// utsnameToString converts a fixed-size int8 array (from Utsname) to a string.
func utsnameToString(arr []int8) string {
	b := make([]byte, 0, len(arr))
	for _, c := range arr {
		if c == 0 {
			break
		}
		b = append(b, byte(c))
	}
	return string(b)
}
