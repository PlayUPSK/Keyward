//go:build windows

package config

import "strings"

const (
	defaultWindowsAgentPipe = `\\.\pipe\openssh-ssh-agent`
	keywardWindowsAgentPipe = `\\.\pipe\keyward-agent`
	legacyWindowsAgentPipe  = `\\.\pipe\passkey-ssh-agent`
)

func defaultAgentSocketPath(home string) string {
	_ = home
	return defaultWindowsAgentPipe
}

func normalizeAgentSocketPath(path string, home string) string {
	_ = home
	if path == "" {
		return defaultWindowsAgentPipe
	}
	if path == legacyWindowsAgentPipe {
		return keywardWindowsAgentPipe
	}
	if !strings.HasPrefix(path, `\\.\pipe\`) {
		return defaultWindowsAgentPipe
	}
	return path
}
