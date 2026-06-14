package main

import (
	"encoding/json"
	"log"
	"sync"
	"time"
)

var (
	redactionMu        sync.RWMutex
	globalMaskPatterns []string
)

// startRedactionPoller launches a background goroutine that fetches
// "redaction_config" from the log server every 60 seconds.
func startRedactionPoller() {
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()

		for {
			content, err := fetchConfigFromServer(cfg.Server, "redaction_config")
			if err != nil {
				debugLog("redaction poller: %v", err)
			} else if content != "" {
				var patterns []string
				if err := json.Unmarshal([]byte(content), &patterns); err != nil {
					log.Printf("redaction poller: parse: %v", err)
				} else {
					redactionMu.Lock()
					globalMaskPatterns = patterns
					redactionMu.Unlock()
				}
			}
			<-ticker.C
		}
	}()
}

// getEffectiveMaskPatterns returns the union of local and global patterns.
func getEffectiveMaskPatterns() []string {
	redactionMu.RLock()
	defer redactionMu.RUnlock()

	out := make([]string, 0, len(cfg.MaskPatterns)+len(globalMaskPatterns))
	out = append(out, cfg.MaskPatterns...)
	out = append(out, globalMaskPatterns...)
	return out
}
