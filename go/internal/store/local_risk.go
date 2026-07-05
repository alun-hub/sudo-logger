package store

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
)

// GetRiskCache implements SessionStore.
func (ls *LocalStore) GetRiskCache(_ context.Context, tsid, rulesHash string) (*RiskCache, error) {
	sessDir, err := ls.resolveSessionDir(tsid)
	if err != nil {
		return nil, err
	}
	rc := localLoadRiskCache(sessDir, rulesHash)
	if rc == nil {
		return nil, nil
	}
	return rc, nil
}

// SaveRiskCache implements SessionStore.
func (ls *LocalStore) SaveRiskCache(_ context.Context, tsid, rulesHash string, score int, reasons []string) error {
	sessDir, err := ls.resolveSessionDir(tsid)
	if err != nil {
		return err
	}
	localSaveRiskCache(sessDir, rulesHash, score, reasons)
	return nil
}

// localLoadRiskCache reads risk.json from sessDir and returns it if the stored
// rules hash matches rulesHash.  Returns nil on cache miss or mismatch.
func localLoadRiskCache(sessDir, rulesHash string) *RiskCache {
	data, err := os.ReadFile(filepath.Join(sessDir, "risk.json"))
	if err != nil {
		return nil
	}
	var rc struct {
		RulesHash string   `json:"rules_hash"`
		Score     int      `json:"score"`
		Level     string   `json:"level"`
		Reasons   []string `json:"reasons"`
	}
	if err := json.Unmarshal(data, &rc); err != nil {
		return nil
	}
	if rc.RulesHash != rulesHash {
		return nil // rules changed — cache is stale
	}
	return &RiskCache{
		RulesHash: rc.RulesHash,
		Score:     rc.Score,
		Level:     rc.Level,
		Reasons:   rc.Reasons,
	}
}

// localSaveRiskCache writes the risk score to risk.json in sessDir.
// Failures are silently ignored (replay server may lack write access).
func localSaveRiskCache(sessDir, rulesHash string, score int, reasons []string) {
	rc := struct {
		RulesHash string   `json:"rules_hash"`
		Score     int      `json:"score"`
		Level     string   `json:"level"`
		Reasons   []string `json:"reasons"`
	}{
		RulesHash: rulesHash,
		Score:     score,
		Level:     RiskLevel(score),
		Reasons:   reasons,
	}
	data, err := json.Marshal(rc)
	if err != nil {
		return
	}
	_ = os.WriteFile(filepath.Join(sessDir, "risk.json"), data, 0o644)
}
