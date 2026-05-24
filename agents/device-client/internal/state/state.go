package state

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

type State struct {
	Company       string    `json:"company"`
	UserEmail     string    `json:"user_email"`
	DeviceStatus  string    `json:"device_status"`
	DeviceID      string    `json:"device_id"`
	ServerCount   int       `json:"server_count"`
	IdentityCount int       `json:"identity_count"`
	LastSyncAt    time.Time `json:"last_sync_at"`
	LastSyncError string    `json:"last_sync_error,omitempty"`
}

func DefaultPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".keyward-ssh", "state.json")
}

func Load(path string) (State, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return State{}, nil
		}
		return State{}, err
	}
	var state State
	if err := json.Unmarshal(data, &state); err != nil {
		return State{}, err
	}
	return state, nil
}

func Save(path string, state State) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}
