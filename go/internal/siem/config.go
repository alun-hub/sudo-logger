// Package siem forwards completed sudo session events to an external SIEM.
//
// Supported transports: https, syslog (udp / tcp / tcp-tls).
// Supported formats:    json, cef, ocsf.
//
// Configuration is loaded from a YAML file at startup and re-checked every
// 30 seconds so that changes written by the replay-server GUI take effect
// without restarting the log server.
package siem

import (
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the top-level SIEM forwarding configuration.
type Config struct {
	Enabled       bool      `yaml:"enabled"         json:"enabled"`
	Transport     string    `yaml:"transport"       json:"transport"`        // https | syslog
	Format        string    `yaml:"format"          json:"format"`           // json | cef | ocsf
	HTTPS         HTTPSCfg  `yaml:"https"           json:"https"`
	Syslog        SyslogCfg `yaml:"syslog"          json:"syslog"`
	ReplayURLBase string    `yaml:"replay_url_base" json:"replay_url_base"`  // e.g. https://replay.example.com
}

// HTTPSCfg configures the HTTPS transport.
type HTTPSCfg struct {
	URL   string `yaml:"url"   json:"url"`
	Token string `yaml:"token" json:"token"` // optional bearer / Splunk HEC token
	TLS   TLSCfg `yaml:"tls"   json:"tls"`
}

// SyslogCfg configures the syslog transport.
type SyslogCfg struct {
	Addr     string `yaml:"addr"     json:"addr"`     // host:port
	Protocol string `yaml:"protocol" json:"protocol"` // udp | tcp | tcp-tls
	TLS      TLSCfg `yaml:"tls"      json:"tls"`
}

// TLSCfg holds file-system paths for mTLS certificate material.
// CA only → one-way TLS.  CA + Cert + Key → mTLS.
type TLSCfg struct {
	CA   string `yaml:"ca"   json:"ca"`
	Cert string `yaml:"cert" json:"cert"`
	Key  string `yaml:"key"  json:"key"`
}

var (
	cfgMu    sync.RWMutex
	cfgCur   Config
	cfgPath  string
	cfgMtime time.Time
)

// Load initialises the package from path and starts a background poller that
// re-reads the file every 30 seconds when the modification time changes.
// A missing file at startup is not fatal — SIEM forwarding stays disabled
// until the file is created.
func Load(path string) {
	cfgPath = path
	if err := reloadConfig(); err != nil && !os.IsNotExist(err) {
		log.Printf("siem: load %s: %v", path, err)
	}
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for range t.C {
			if err := reloadConfig(); err != nil && !os.IsNotExist(err) {
				log.Printf("siem: reload: %v", err)
			}
		}
	}()
}

// LoadWithFunc is like Load but uses loader to fetch the raw YAML text each
// cycle instead of reading a file. Use this in distributed deployments where
// the config is stored in a database rather than on disk.
func LoadWithFunc(loader func() (string, error)) {
	applyLoader(loader)
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for range t.C {
			applyLoader(loader)
		}
	}()
}

// Set directly replaces the current in-memory configuration.
// Call this after writing a new config to persistent storage so that the
// running process picks up the change immediately without waiting for the
// next reload cycle.
func Set(cfg Config) {
	cfgMu.Lock()
	cfgCur = cfg
	cfgMu.Unlock()
	log.Printf("siem: config applied (enabled=%v transport=%s format=%s replay_url_base=%q)",
		cfg.Enabled, cfg.Transport, cfg.Format, cfg.ReplayURLBase)
}

func applyLoader(loader func() (string, error)) {
	text, err := loader()
	if err != nil {
		log.Printf("siem: load error: %v", err)
		return
	}
	if text == "" {
		return // not configured yet
	}
	var cfg Config
	if err := yaml.Unmarshal([]byte(text), &cfg); err != nil {
		log.Printf("siem: parse config: %v", err)
		return
	}
	cfgMu.Lock()
	cfgCur = cfg
	cfgMu.Unlock()
	log.Printf("siem: config loaded (enabled=%v transport=%s format=%s replay_url_base=%q)",
		cfg.Enabled, cfg.Transport, cfg.Format, cfg.ReplayURLBase)
}

// Get returns a snapshot of the current configuration.
func Get() Config {
	cfgMu.RLock()
	defer cfgMu.RUnlock()
	return cfgCur
}

func reloadConfig() error {
	info, err := os.Stat(cfgPath)
	if err != nil {
		return err
	}
	cfgMu.RLock()
	unchanged := info.ModTime().Equal(cfgMtime)
	cfgMu.RUnlock()
	if unchanged {
		return nil
	}
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		return err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("parse %s: %w", cfgPath, err)
	}
	cfgMu.Lock()
	cfgCur = cfg
	cfgMtime = info.ModTime()
	cfgMu.Unlock()
	log.Printf("siem: config loaded (enabled=%v transport=%s format=%s replay_url_base=%q)",
		cfg.Enabled, cfg.Transport, cfg.Format, cfg.ReplayURLBase)
	return nil
}
