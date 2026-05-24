//go:build !windows

package config

import "path/filepath"

func defaultAgentSocketPath(home string) string {
	return filepath.Join(home, ".keyward-ssh", "agent.sock")
}

func normalizeAgentSocketPath(path string, home string) string {
	if path == "" {
		return defaultAgentSocketPath(home)
	}
	return path
}