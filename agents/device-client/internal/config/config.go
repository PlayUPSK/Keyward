package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

type Config struct {
	PlatformURL              string `json:"platform_url"`
	AgentSocketPath          string `json:"agent_socket_path"`
	DeviceKeyPath            string `json:"device_key_path"`
	LocalCallbackURL         string `json:"local_callback_url"`
	UserPresenceMode         string `json:"user_presence_mode"`
	UserPresenceCommand      string `json:"user_presence_command,omitempty"`
	UserPresenceCacheSeconds int    `json:"user_presence_cache_seconds"`
	DeviceID                 string `json:"device_id,omitempty"`
}

func Default() Config {
	home, _ := os.UserHomeDir()
	return Config{
		PlatformURL:              "http://localhost:8443",
		AgentSocketPath:          defaultAgentSocketPath(home),
		DeviceKeyPath:            filepath.Join(home, ".keyward-ssh", "device_ed25519"),
		LocalCallbackURL:         "http://127.0.0.1:17657/callback",
		UserPresenceMode:         "auto",
		UserPresenceCacheSeconds: 30,
	}
}

func DefaultPath() string {
	home, _ := os.UserHomeDir()
	if path := os.Getenv("KEYWARD_CLIENT_CONFIG"); path != "" {
		return path
	}
	return filepath.Join(home, ".keyward-ssh", "config.json")
}

func LoadDefault() (Config, error) {
	path := DefaultPath()
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if legacyData, legacyErr := os.ReadFile(legacyDefaultPath()); legacyErr == nil {
				data = legacyData
			} else {
				return Default(), nil
			}
		} else {
			return Config{}, err
		}
	}

	cfg := Default()
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, err
	}
	cfg.AgentSocketPath = normalizeAgentSocketPath(cfg.AgentSocketPath, homeDir())
	return cfg, nil
}

func WriteDefault(cfg Config) error {
	path := DefaultPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, append(data, '\n'), 0o600)
}

func (cfg Config) DefaultIdentityPath() string {
	return filepath.Join(filepath.Dir(cfg.DeviceKeyPath), "ephemeral_ed25519")
}

func homeDir() string {
	home, _ := os.UserHomeDir()
	return home
}

func legacyDefaultPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".passkey-ssh", "config.json")
}
