package devicesync

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/playup/keyward/agents/device-client/internal/certrequest"
	"github.com/playup/keyward/agents/device-client/internal/config"
	"github.com/playup/keyward/agents/device-client/internal/deviceinfo"
	"github.com/playup/keyward/agents/device-client/internal/devicekey"
	"github.com/playup/keyward/agents/device-client/internal/state"
)

var unsafeIdentityPathChars = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

type accessResponse struct {
	Company string `json:"company"`
	User    struct {
		Email string `json:"email"`
	} `json:"user"`
	Device struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	} `json:"device"`
	Servers []struct {
		ID         string   `json:"id"`
		Hostname   string   `json:"hostname"`
		Principals []string `json:"principals"`
	} `json:"servers"`
	Error string `json:"error"`
}

func Sync(ctx context.Context, cfg config.Config) (state.State, error) {
	if cfg.DeviceID == "" {
		return state.State{}, fmt.Errorf("device is not enrolled")
	}
	if err := updateInventory(ctx, cfg); err != nil {
		return state.State{}, err
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		cfg.PlatformURL+"/api/v1/devices/"+cfg.DeviceID+"/access",
		nil,
	)
	if err != nil {
		return state.State{}, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return state.State{}, err
	}
	defer resp.Body.Close()

	var result accessResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return state.State{}, err
	}
	if resp.StatusCode != http.StatusOK {
		if result.Error == "" {
			result.Error = resp.Status
		}
		return state.State{}, fmt.Errorf("%s", result.Error)
	}

	identityCount, err := syncIssuedIdentities(ctx, cfg, result.Servers)
	if err != nil {
		return state.State{}, err
	}

	return state.State{
		Company:       result.Company,
		UserEmail:     result.User.Email,
		DeviceStatus:  result.Device.Status,
		DeviceID:      result.Device.ID,
		ServerCount:   len(result.Servers),
		IdentityCount: identityCount,
		LastSyncAt:    time.Now().UTC(),
	}, nil
}

func updateInventory(ctx context.Context, cfg config.Config) error {
	body, err := json.Marshal(map[string]any{
		"posture": deviceinfo.Collect(ctx),
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		cfg.PlatformURL+"/api/v1/devices/"+cfg.DeviceID+"/inventory",
		strings.NewReader(string(body)),
	)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("inventory update returned %s", resp.Status)
	}
	return nil
}

func syncIssuedIdentities(ctx context.Context, cfg config.Config, servers []struct {
	ID         string   `json:"id"`
	Hostname   string   `json:"hostname"`
	Principals []string `json:"principals"`
}) (int, error) {
	keyPair, err := devicekey.LoadOrCreate(cfg.DeviceKeyPath)
	if err != nil {
		return 0, err
	}

	identityCount := 0
	wantedIdentities := map[string]struct{}{}
	for _, server := range servers {
		if server.Hostname == "" {
			continue
		}
		for _, principal := range server.Principals {
			if principal == "" {
				continue
			}
			identityPath := identityPathForServer(cfg, server.Hostname, principal)
			wantedIdentities[identityPath] = struct{}{}

			if _, err := certrequest.Issue(ctx, cfg, ed25519.PrivateKey(keyPair.PrivateKey), certrequest.IssueOptions{
				Server:       server.Hostname,
				SSHPrincipal: principal,
				IdentityPath: identityPath,
			}); err != nil {
				return 0, fmt.Errorf("issue cert for %s as %s: %w", server.Hostname, principal, err)
			}
			identityCount++
		}
	}

	if err := removeStaleIdentities(cfg, wantedIdentities); err != nil {
		return 0, err
	}

	return identityCount, nil
}

func identityPathForServer(cfg config.Config, hostname string, principal string) string {
	baseDir := filepath.Dir(cfg.DeviceKeyPath)
	serverPart := sanitizeIdentityName(hostname)
	principalPart := sanitizeIdentityName(principal)
	return filepath.Join(baseDir, serverPart+"--"+principalPart)
}

func sanitizeIdentityName(value string) string {
	cleaned := unsafeIdentityPathChars.ReplaceAllString(value, "-")
	if cleaned == "" {
		return "identity"
	}
	return cleaned
}

func removeStaleIdentities(cfg config.Config, wanted map[string]struct{}) error {
	identityDir := filepath.Dir(cfg.DeviceKeyPath)
	entries, err := os.ReadDir(identityDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read identity directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !filepath.IsLocal(entry.Name()) || !strings.HasSuffix(entry.Name(), "-cert.pub") {
			continue
		}
		certPath := filepath.Join(identityDir, entry.Name())
		identityPath := certPath[:len(certPath)-len("-cert.pub")]
		if _, ok := wanted[identityPath]; ok {
			continue
		}
		for _, path := range []string{identityPath, identityPath + ".pub", identityPath + "-cert.pub", identityPath + ".keyward.json"} {
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("remove stale identity %s: %w", path, err)
			}
		}
	}
	return nil
}
