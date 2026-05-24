//go:build windows

package opensshcfg

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/playup/keyward/agents/device-client/internal/config"
)

const includeFileName = "keyward-agent.conf"

func EnsureIdentityAgentConfig(agentPipe string) error {
	configuredPipe := identityAgentValue(agentPipe)

	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		return err
	}

	includePath := filepath.Join(sshDir, includeFileName)
	includeBody := fmt.Sprintf("# Managed by keyward-tray\nHost *\n  IdentityAgent %s\n", configuredPipe)
	if err := os.WriteFile(includePath, []byte(includeBody), 0o600); err != nil {
		return err
	}

	mainConfigPath := filepath.Join(sshDir, "config")
	includeDirective := fmt.Sprintf("Include %s", filepath.ToSlash(includePath))

	current, err := os.ReadFile(mainConfigPath)
	if err != nil {
		if os.IsNotExist(err) {
			return os.WriteFile(mainConfigPath, []byte(includeDirective+"\n"), 0o600)
		}
		return err
	}

	configText := string(current)
	if strings.Contains(configText, includeDirective) || strings.Contains(configText, includeFileName) {
		return nil
	}

	updated := includeDirective + "\n" + configText
	return os.WriteFile(mainConfigPath, []byte(updated), 0o600)
}

func ConfigPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".ssh", includeFileName)
}

func ConfiguredPipe(cfg config.Config) string {
	return identityAgentValue(cfg.AgentSocketPath)
}

func identityAgentValue(agentPipe string) string {
	return strings.ReplaceAll(agentPipe, `\`, "/")
}
