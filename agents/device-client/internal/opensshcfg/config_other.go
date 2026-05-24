//go:build !windows

package opensshcfg

import "github.com/playup/keyward/agents/device-client/internal/config"

func EnsureIdentityAgentConfig(agentPipe string) error {
	_ = agentPipe
	return nil
}

func ConfigPath() string {
	return ""
}

func ConfiguredPipe(cfg config.Config) string {
	return cfg.AgentSocketPath
}