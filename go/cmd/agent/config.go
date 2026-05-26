package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"
)

type agentConfig struct {
	Server       string
	Socket       string
	Cert         string
	Key          string
	CA           string
	VerifyKey    string
	MaskPatterns    []string
	FreezeTimeout   time.Duration
	IdleTimeout     time.Duration
	Disclaimer      string
	DisclaimerColor string
	Debug           bool
	// Ebpf controls whether the eBPF subsystem is enabled.
	// Defaults to true; set to false on kernels without BTF support.
	Ebpf bool
	// SandboxConfig is the path to the sandbox YAML deny-list.
	// Empty (default) disables the sandbox subsystem.
	SandboxConfig string
}

func defaultConfig() agentConfig {
	return agentConfig{
		Server:        "logserver:9876",
		Socket:        "/run/sudo-logger/plugin.sock",
		Cert:          "/etc/sudo-logger/client.crt",
		Key:           "/etc/sudo-logger/client.key",
		CA:            "/etc/sudo-logger/ca.crt",
		VerifyKey:     "/etc/sudo-logger/ack-verify.key",
		MaskPatterns:  []string{},
		FreezeTimeout: 3 * time.Minute,
		Debug:         false,
		Ebpf:          true,
	}
}

// loadConfig parses a key = value config file (agent.conf or legacy agent.conf).
// Unknown keys are silently ignored so the agent remains backward-compatible
// when reading older configs.
func loadConfig(path string) (agentConfig, error) {
	cfg := defaultConfig()

	f, err := os.Open(path)
	if err != nil {
		return cfg, fmt.Errorf("open config %s: %w", path, err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	lineNum := 0
	for sc.Scan() {
		lineNum++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.IndexByte(line, '=')
		if idx < 0 {
			return cfg, fmt.Errorf("%s:%d: missing '='", path, lineNum)
		}
		k := strings.TrimSpace(line[:idx])
		v := strings.TrimSpace(line[idx+1:])
		if ci := strings.Index(v, " #"); ci >= 0 {
			v = strings.TrimSpace(v[:ci])
		}

		switch k {
		case "server", "LOGSERVER":
			cfg.Server = v
		case "socket":
			cfg.Socket = v
		case "cert":
			cfg.Cert = v
		case "key":
			cfg.Key = v
		case "ca":
			cfg.CA = v
		case "verify_key":
			cfg.VerifyKey = v
		case "mask_pattern":
			cfg.MaskPatterns = append(cfg.MaskPatterns, v)
		case "freeze_timeout":
			d, err := time.ParseDuration(v)
			if err != nil {
				return cfg, fmt.Errorf("%s:%d: freeze_timeout: %w", path, lineNum, err)
			}
			cfg.FreezeTimeout = d
		case "idle_timeout":
			d, err := time.ParseDuration(v)
			if err != nil {
				return cfg, fmt.Errorf("%s:%d: idle_timeout: %w", path, lineNum, err)
			}
			cfg.IdleTimeout = d
		case "debug":
			cfg.Debug = v == "true" || v == "1" || v == "yes"
		case "disclaimer":
			cfg.Disclaimer = expandEscapes(v)
		case "disclaimer_color":
			cfg.DisclaimerColor = v
		case "ebpf":
			cfg.Ebpf = v != "false" && v != "0" && v != "no"
		case "sandbox_config":
			cfg.SandboxConfig = v
		default:
			// Silently ignore unknown keys for backward compatibility.
		}
	}
	return cfg, sc.Err()
}

func expandEscapes(s string) string {
	s = strings.ReplaceAll(s, `\n`, "\n")
	s = strings.ReplaceAll(s, `\t`, "\t")
	return s
}
