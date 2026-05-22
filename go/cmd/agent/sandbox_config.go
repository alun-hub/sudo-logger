package main

import (
	"fmt"
	"log"
	"os"
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

// inodeKey matches struct inode_key in sandbox.bpf.c — layout must be identical.
type inodeKey struct {
	Ino uint64
	Dev uint32
	Pad uint32
}

type resolvedSandbox struct {
	Inodes     []inodeKey
	PathInodes map[string]inodeKey // protected path → its current inode key
	Processes  []string
}

// mountDev returns the kernel dev_t (MKDEV(major, minor)) for the filesystem
// containing path, by parsing /proc/self/mountinfo. This matches the value that
// the BPF program reads from inode->i_sb->s_dev, which differs from stat().st_dev
// on Btrfs (where stat returns the subvolume anon_dev, not the superblock dev).
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
		majMin := fields[2]
		// Check if this mount point is a prefix of path.
		if mountPoint != "/" {
			if path != mountPoint && !strings.HasPrefix(path, mountPoint+"/") {
				continue
			}
		}
		if len(mountPoint) <= bestLen {
			continue
		}
		parts := strings.SplitN(majMin, ":", 2)
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
	var cfg sandboxYAML
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse sandbox config: %w", err)
	}

	res := &resolvedSandbox{
		PathInodes: make(map[string]inodeKey),
	}
	seen := make(map[inodeKey]bool)

	allPaths := make([]string, 0,
		len(cfg.Protect.Files)+len(cfg.Protect.Devices)+
			len(cfg.Protect.Proc)+len(cfg.Protect.Sockets))
	allPaths = append(allPaths, cfg.Protect.Files...)
	allPaths = append(allPaths, cfg.Protect.Devices...)
	allPaths = append(allPaths, cfg.Protect.Proc...)
	allPaths = append(allPaths, cfg.Protect.Sockets...)

	for _, p := range allPaths {
		var st syscall.Stat_t
		if err := syscall.Stat(p, &st); err != nil {
			log.Printf("sandbox: stat %s: %v (skipping)", p, err)
			continue
		}
		dev, devErr := mountDev(p)
		if devErr != nil {
			log.Printf("sandbox: mountDev %s: %v (falling back to stat dev)", p, devErr)
			dev = uint32(st.Dev)
		}
		key := inodeKey{Ino: st.Ino, Dev: dev}
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
