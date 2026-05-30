package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"gopkg.in/yaml.v3"
)

type sandboxYAML struct {
	Features struct {
		DenyNetlink         *bool `yaml:"deny_netlink"`
		DenyMount           *bool `yaml:"deny_mount"`
		DenyPtrace          *bool `yaml:"deny_ptrace"`
		DenyCapAuditControl *bool `yaml:"deny_cap_audit_control"`
		DenyCapNetAdmin     *bool `yaml:"deny_cap_net_admin"`
		DenyCapSysModule    *bool `yaml:"deny_cap_sys_module"`
		DenySystemdIPC      *bool `yaml:"deny_systemd_ipc"`
	} `yaml:"features"`
	Protect struct {
		Files     []string `yaml:"files"`
		Forbidden []string `yaml:"forbidden"`
		Noexec    []string `yaml:"noexec"`
		Devices   []string `yaml:"devices"`
		Proc      []string `yaml:"proc"`
		Sockets   []string `yaml:"sockets"`
		Processes []string `yaml:"processes"`
	} `yaml:"protect"`
}

// resolvedFeatures holds feature flags with defaults applied.
// All flags default to true (deny) when absent from sandbox.yaml.
type resolvedFeatures struct {
	DenyNetlink         bool
	DenyMount           bool
	DenyPtrace          bool
	DenyCapAuditControl bool
	DenyCapNetAdmin     bool
	DenyCapSysModule    bool
	DenySystemdIPC      bool
}

// featureDefault returns v's value, or true if v is nil (absent from YAML).
func featureDefault(v *bool) bool {
	if v == nil {
		return true
	}
	return *v
}

// featureDefaultFalse returns v's value, or false if v is nil. Used for
// protections that are off by default because they break common workflows
// (e.g. deny_systemd_ipc also blocks systemctl/loginctl inside a session).
func featureDefaultFalse(v *bool) bool {
	if v == nil {
		return false
	}
	return *v
}

type resolvedSandbox struct {
	Features   resolvedFeatures
	Inodes     []SandboxInodeKey
	Forbidden  []SandboxInodeKey // forbidden_binaries (bprm_check_security)
	Noexec     []SandboxInodeKey // noexec_inodes (bprm_check_security parent dir check)
	IPCInodes  []SandboxInodeKey // systemd/D-Bus control-socket inodes (deny_systemd_ipc)
	PathInodes map[string]SandboxInodeKey // protected path → its current inode key
	Processes  []string
}

// systemdIPCPaths are the control sockets whose connect() is denied inside the
// sandbox when deny_systemd_ipc is enabled. These are the channels through which
// a session can ask PID 1 to spawn a process outside the sandbox (systemd-run,
// busctl StartTransientUnit, machinectl).
var systemdIPCPaths = []string{
	"/run/systemd/private",
	"/run/dbus/system_bus_socket",
}

// resolveInodeKey resolves an absolute path to its BPF inode key {ino, dev},
// using mountinfo for s_dev to match what the BPF program reads.
func resolveInodeKey(p string) (SandboxInodeKey, bool) {
	var st syscall.Stat_t
	if err := syscall.Stat(p, &st); err != nil {
		debugLog("sandbox: stat %s: %v (skipping)", p, err)
		return SandboxInodeKey{}, false
	}
	dev, err := mountDev(p)
	if err != nil {
		dev = uint32(st.Dev)
	}
	return SandboxInodeKey{Ino: st.Ino, Dev: dev}, true
}

// mountDev returns the kernel dev_t (MKDEV(major, minor)) for the filesystem
// containing path by parsing /proc/self/mountinfo. This matches i_sb->s_dev
// read by the BPF program, which on Btrfs differs from stat().st_dev (the
// subvolume anon_dev) — both are anonymous devices (major 0) but different
// minor numbers.
func mountDev(path string) (uint32, error) {
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return 0, fmt.Errorf("read mountinfo: %w", err)
	}
	bestLen := -1
	var bestDev uint32
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		mountPoint := fields[4]
		if mountPoint != "/" && path != mountPoint && !strings.HasPrefix(path, mountPoint+"/") {
			continue
		}
		if len(mountPoint) <= bestLen {
			continue
		}
		parts := strings.SplitN(fields[2], ":", 2)
		if len(parts) != 2 {
			continue
		}
		major, err1 := strconv.ParseUint(parts[0], 10, 32)
		minor, err2 := strconv.ParseUint(parts[1], 10, 32)
		if err1 != nil || err2 != nil {
			continue
		}
		bestLen = len(mountPoint)
		bestDev = (uint32(major) << 20) | uint32(minor)
	}
	if bestLen < 0 {
		return 0, fmt.Errorf("no mount entry found for %s", path)
	}
	return bestDev, nil
}

func loadSandboxConfig(path string) (*resolvedSandbox, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read sandbox config %s: %w", path, err)
	}
	return loadSandboxConfigFromBytes(data)
}

// loadSandboxConfigFromBytes parses and resolves a sandbox YAML payload.
// It is used both by loadSandboxConfig (file path) and reloadSandboxFromContent
// (content received from the log server).
func loadSandboxConfigFromBytes(data []byte) (*resolvedSandbox, error) {
	var cfg sandboxYAML
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse sandbox config: %w", err)
	}

	res := &resolvedSandbox{
		PathInodes: make(map[string]SandboxInodeKey),
		Features: resolvedFeatures{
			DenyNetlink:         featureDefault(cfg.Features.DenyNetlink),
			DenyMount:           featureDefault(cfg.Features.DenyMount),
			DenyPtrace:          featureDefault(cfg.Features.DenyPtrace),
			DenyCapAuditControl: featureDefault(cfg.Features.DenyCapAuditControl),
			DenyCapNetAdmin:     featureDefault(cfg.Features.DenyCapNetAdmin),
			DenyCapSysModule:    featureDefault(cfg.Features.DenyCapSysModule),
			DenySystemdIPC:      featureDefaultFalse(cfg.Features.DenySystemdIPC),
		},
	}

	// Resolve systemd/D-Bus control-socket inodes (for deny_systemd_ipc).
	// Always resolved so the map is populated regardless of the flag's current
	// value; the BPF hook only consults it when deny_systemd_ipc is enabled.
	for _, p := range systemdIPCPaths {
		if key, ok := resolveInodeKey(p); ok {
			res.IPCInodes = append(res.IPCInodes, key)
			debugLog("sandbox: systemd-ipc socket %s {ino=%d dev=%d}", p, key.Ino, key.Dev)
		}
	}
	seen := make(map[SandboxInodeKey]bool)

	// Use a queue to implement recursive directory traversal.
	// To prevent Denial of Service, we track depth and limit the total number
	// of resolved nodes.
	type node struct {
		path  string
		depth int
	}
	queue := make([]node, 0,
		len(cfg.Protect.Files)+len(cfg.Protect.Devices)+
			len(cfg.Protect.Proc)+len(cfg.Protect.Sockets))
	for _, p := range cfg.Protect.Files {
		queue = append(queue, node{p, 0})
	}
	for _, p := range cfg.Protect.Devices {
		queue = append(queue, node{p, 0})
	}
	for _, p := range cfg.Protect.Proc {
		queue = append(queue, node{p, 0})
	}
	for _, p := range cfg.Protect.Sockets {
		queue = append(queue, node{p, 0})
	}

	const maxNodes = 4096
	const maxDepth = 3

	// Paths that are themselves large filesystem roots. Recursing into them
	// would stat millions of files. We still protect the top-level inode but
	// skip ReadDir. Subdirectories of these (e.g. /usr/lib/systemd/system) are
	// fine — they arrive as explicit entries with their own depth counter.
	dangerousRoots := map[string]bool{
		"/": true, "/usr": true, "/bin": true, "/sbin": true,
		"/lib": true, "/lib64": true, "/lib32": true,
		"/proc": true, "/sys": true, "/dev": true, "/run": true,
	}

	for i := 0; i < len(queue); i++ {
		if len(res.PathInodes) >= maxNodes {
			log.Printf("sandbox: max nodes (%d) reached, skipping remaining paths", maxNodes)
			break
		}

		n := queue[i]
		p := n.path

		// Require absolute paths to prevent relative traversal.
		if !filepath.IsAbs(p) {
			log.Printf("sandbox: skipping non-absolute path %q", p)
			continue
		}

		fi, err := os.Stat(p)
		if err != nil {
			debugLog("sandbox: stat %s: %v (skipping)", p, err)
			continue
		}

		if fi.IsDir() && n.depth < maxDepth && !dangerousRoots[filepath.Clean(p)] {
			entries, err := os.ReadDir(p)
			if err != nil {
				log.Printf("sandbox: readdir %s: %v", p, err)
			} else {
				for _, entry := range entries {
					queue = append(queue, node{filepath.Join(p, entry.Name()), n.depth + 1})
				}
			}
		} else if fi.IsDir() && dangerousRoots[filepath.Clean(p)] {
			log.Printf("sandbox: skipping recursive scan of large root %q (protecting inode only)", p)
		}

		var st syscall.Stat_t
		if err := syscall.Stat(p, &st); err != nil {
			continue
		}
		// Use mountinfo to get i_sb->s_dev (what BPF reads) rather than
		// stat().st_dev.
		dev, devErr := mountDev(p)
		if devErr != nil {
			log.Printf("sandbox: mountDev %s: %v (falling back to stat dev)", p, devErr)
			dev = uint32(st.Dev)
		}
		debugLog("sandbox: protecting %s {ino=%d dev=%d}", p, st.Ino, dev)
		key := SandboxInodeKey{Ino: st.Ino, Dev: dev}
		res.PathInodes[p] = key

		if !seen[key] {
			seen[key] = true
			res.Inodes = append(res.Inodes, key)
		}
	}

	// Resolve forbidden binaries (exact paths, no recursion)
	for _, p := range cfg.Protect.Forbidden {
		if !filepath.IsAbs(p) {
			continue
		}
		var st syscall.Stat_t
		if err := syscall.Stat(p, &st); err != nil {
			continue
		}
		dev, _ := mountDev(p)
		if dev == 0 {
			dev = uint32(st.Dev)
		}
		key := SandboxInodeKey{Ino: st.Ino, Dev: dev}
		if !seen[key] {
			seen[key] = true
			res.Forbidden = append(res.Forbidden, key)
		}
	}

	// Resolve noexec directories (exact paths, BPF will traverse up to them)
	for _, p := range cfg.Protect.Noexec {
		if !filepath.IsAbs(p) {
			continue
		}
		var st syscall.Stat_t
		if err := syscall.Stat(p, &st); err != nil {
			continue
		}
		dev, _ := mountDev(p)
		if dev == 0 {
			dev = uint32(st.Dev)
		}
		key := SandboxInodeKey{Ino: st.Ino, Dev: dev}
		if !seen[key] {
			seen[key] = true
			res.Noexec = append(res.Noexec, key)
		}
	}


	for _, name := range cfg.Protect.Processes {
		if len(name) > 15 {
			log.Printf("sandbox: process name %q exceeds 15 chars, truncating", name)
			name = name[:15]
		}
		res.Processes = append(res.Processes, name)
	}

	return res, nil
}
