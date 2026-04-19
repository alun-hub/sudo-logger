package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"
)

type shipperConfig struct {
	Server        string
	Socket        string
	Cert          string
	Key           string
	CA            string
	VerifyKey     string
	ProxyBin      string
	ProxyPeriod   int
	MaskPatterns     []string
	FreezeTimeout    time.Duration
	Disclaimer       string // raw text after escape expansion (\n → newline, \t → tab)
	DisclaimerColor  string // red, green, blue, orange, bold_red, bold_green, bold_blue, bold_orange
	Debug            bool
	Wayland          bool
}

func defaultConfig() shipperConfig {
	return shipperConfig{
		Server:        "logserver:9876",
		Socket:        "/run/sudo-logger/plugin.sock",
		Cert:          "/etc/sudo-logger/client.crt",
		Key:           "/etc/sudo-logger/client.key",
		CA:            "/etc/sudo-logger/ca.crt",
		VerifyKey:     "/etc/sudo-logger/ack-verify.key",
		ProxyBin:      "/usr/libexec/sudo-logger/wayland-proxy",
		ProxyPeriod:   300,
		MaskPatterns:  []string{},
		FreezeTimeout: 3 * time.Minute,
		Debug:         false,
		Wayland:       true,
	}
}

// loadConfig parses a key = value config file. Lines starting with # and
// blank lines are ignored. Unknown keys are rejected to catch typos.
func loadConfig(path string) (shipperConfig, error) {
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
		// Strip trailing inline comment (space + #).
		if ci := strings.Index(v, " #"); ci >= 0 {
			v = strings.TrimSpace(v[:ci])
		}

		switch k {
		case "server", "LOGSERVER": // LOGSERVER: legacy key from EnvironmentFile era
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
		case "proxy_bin":
			cfg.ProxyBin = v
		case "proxy_period":
			var val int
			if _, err := fmt.Sscanf(v, "%d", &val); err != nil {
				return cfg, fmt.Errorf("%s:%d: proxy_period: %w", path, lineNum, err)
			}
			cfg.ProxyPeriod = val
		case "mask_pattern":
			cfg.MaskPatterns = append(cfg.MaskPatterns, v)
		case "freeze_timeout":
			d, err := time.ParseDuration(v)
			if err != nil {
				return cfg, fmt.Errorf("%s:%d: freeze_timeout: %w", path, lineNum, err)
			}
			cfg.FreezeTimeout = d
		case "debug":
			cfg.Debug = v == "true" || v == "1" || v == "yes"
		case "wayland":
			cfg.Wayland = v != "false" && v != "0" && v != "no"
		case "disclaimer":
			cfg.Disclaimer = expandEscapes(v)
		case "disclaimer_color":
			cfg.DisclaimerColor = v
		default:
			return cfg, fmt.Errorf("%s:%d: unknown key %q", path, lineNum, k)
		}
	}
	return cfg, sc.Err()
}

// expandEscapes replaces literal \n and \t sequences in config values with
// the corresponding control characters, matching shell-like expectation for
// multiline and tabbed disclaimer text.
func expandEscapes(s string) string {
	s = strings.ReplaceAll(s, `\n`, "\n")
	s = strings.ReplaceAll(s, `\t`, "\t")
	return s
}
