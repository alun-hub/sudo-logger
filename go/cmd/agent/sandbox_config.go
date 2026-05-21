package main

import (
	"fmt"
	"log"
	"os"
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
	Inodes    []inodeKey
	Processes []string
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

	res := &resolvedSandbox{}
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
		key := inodeKey{Ino: st.Ino, Dev: uint32(st.Dev)}
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
