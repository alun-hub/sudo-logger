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
	Protect struct {
		Files     []string `yaml:"files"`
		Devices   []string `yaml:"devices"`
		Proc      []string `yaml:"proc"`
		Sockets   []string `yaml:"sockets"`
		Processes []string `yaml:"processes"`
	} `yaml:"protect"`
}

type resolvedSandbox struct {
	Inodes     []SandboxInodeKey
	PathInodes map[string]SandboxInodeKey // protected path → its current inode key
	Processes  []string
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
	}
	seen := make(map[SandboxInodeKey]bool)

	// Use a queue to implement recursive directory traversal.
	queue := make([]string, 0,
		len(cfg.Protect.Files)+len(cfg.Protect.Devices)+
			len(cfg.Protect.Proc)+len(cfg.Protect.Sockets))
	queue = append(queue, cfg.Protect.Files...)
	queue = append(queue, cfg.Protect.Devices...)
	queue = append(queue, cfg.Protect.Proc...)
	queue = append(queue, cfg.Protect.Sockets...)

	for i := 0; i < len(queue); i++ {
		p := queue[i]
		fi, err := os.Stat(p)
		if err != nil {
			debugLog("sandbox: stat %s: %v (skipping)", p, err)
			continue
		}

		if fi.IsDir() {
			entries, err := os.ReadDir(p)
			if err != nil {
				log.Printf("sandbox: readdir %s: %v", p, err)
			} else {
				for _, entry := range entries {
					queue = append(queue, filepath.Join(p, entry.Name()))
				}
			}
		}

		var st syscall.Stat_t
		if err := syscall.Stat(p, &st); err != nil {
			continue
		}
		// Use mountinfo to get i_sb->s_dev (what BPF reads) rather than
		// stat().st_dev. On Btrfs both are anonymous devices (major 0) but
		// with different minor numbers: stat returns the subvolume anon_dev
		// while the kernel superblock uses a separate anon_dev.
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

	for _, name := range cfg.Protect.Processes {
		if len(name) > 15 {
			log.Printf("sandbox: process name %q exceeds 15 chars, truncating", name)
			name = name[:15]
		}
		res.Processes = append(res.Processes, name)
	}

	return res, nil
}
