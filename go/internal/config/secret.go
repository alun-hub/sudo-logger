package config

import (
	"fmt"
	"os"
	"strings"
)

// ResolveSecret returns the first non-empty value from: flag value, environment
// variable envVar, or the contents of flagFile. Returns an error only when
// flagFile is set but cannot be read.
func ResolveSecret(flagVal, flagFile, envVar string) (string, error) {
	if flagVal != "" {
		return flagVal, nil
	}
	if v := os.Getenv(envVar); v != "" {
		return v, nil
	}
	if flagFile != "" {
		data, err := os.ReadFile(flagFile)
		if err != nil {
			return "", fmt.Errorf("read secret file %q: %w", flagFile, err)
		}
		return strings.TrimRight(string(data), "\r\n"), nil
	}
	return "", nil
}
