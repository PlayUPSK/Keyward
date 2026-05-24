package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

type Config struct {
	PlatformURL       string `json:"platform_url"`
	ServerID          string `json:"server_id,omitempty"`
	StateDir          string `json:"state_dir"`
	TrustedUserCAPath string `json:"trusted_user_ca_path"`
	SSHDIncludePath   string `json:"sshd_include_path"`
	RevocationPath    string `json:"revocation_path"`
	RevokedKeysPath   string `json:"revoked_keys_path"`
}

func Default() Config {
	return Config{
		PlatformURL:       "http://localhost:8443",
		StateDir:          "/etc/ssh/keyward",
		TrustedUserCAPath: "/etc/ssh/keyward/trusted_user_ca.pub",
		SSHDIncludePath:   "/etc/ssh/sshd_config.d/keyward.conf",
		RevocationPath:    "/etc/ssh/keyward/revocation-state.json",
		RevokedKeysPath:   "/etc/ssh/keyward/revoked.krl",
	}
}

func DefaultPath() string {
	if path := os.Getenv("KEYWARD_SERVER_AGENT_CONFIG"); path != "" {
		return path
	}
	if path := os.Getenv("PASSKEY_SERVER_AGENT_CONFIG"); path != "" {
		return path
	}
	return filepath.Join("/etc", "keyward-server-agent", "config.json")
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
	return cfg, nil
}

func legacyDefaultPath() string {
	return filepath.Join("/etc", "passkey-server-agent", "config.json")
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
