package sync

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/playup/keyward/agents/server-agent/internal/config"
	"github.com/playup/keyward/agents/server-agent/internal/openssh"
)

type trustedUserCAResponse struct {
	TrustedUserCAPublicKey string `json:"trusted_user_ca_public_key"`
	FingerprintSHA256      string `json:"fingerprint_sha256"`
	Error                  string `json:"error"`
}

type revocationStateResponse struct {
	RevokedDevices            []map[string]string `json:"revoked_devices"`
	RevokedCertificateSerials []int64             `json:"revoked_certificate_serials"`
	RevokedCertificateReasons map[string]string   `json:"revoked_certificate_reasons"`
	GeneratedAt               string              `json:"generated_at"`
}

type Options struct {
	Quiet bool
}

func Run(ctx context.Context, cfg config.Config) error {
	return RunWithOptions(ctx, cfg, Options{})
}

func RunWithOptions(ctx context.Context, cfg config.Config, options Options) error {
	ca, err := fetchTrustedUserCA(ctx, cfg)
	if err != nil {
		return err
	}

	if err := atomicWrite(cfg.TrustedUserCAPath, []byte(ca.TrustedUserCAPublicKey+"\n"), 0o644); err != nil {
		return fmt.Errorf("write trusted user CA: %w", err)
	}

	revocationState, err := fetchRevocationState(ctx, cfg)
	if err != nil {
		return err
	}
	revocationBytes, err := json.MarshalIndent(revocationState, "", "  ")
	if err != nil {
		return err
	}
	if err := atomicWrite(cfg.RevocationPath, append(revocationBytes, '\n'), 0o644); err != nil {
		return fmt.Errorf("write revocation state: %w", err)
	}
	if err := writeRevokedKeysKRL(cfg, revocationState); err != nil {
		return fmt.Errorf("write revoked keys KRL: %w", err)
	}

	include := openssh.RenderTrustedUserCAAndRevocationConfig(cfg.TrustedUserCAPath, cfg.RevokedKeysPath)
	if err := atomicWrite(cfg.SSHDIncludePath, []byte(include), 0o644); err != nil {
		return fmt.Errorf("write sshd include config: %w", err)
	}

	if !options.Quiet {
		fmt.Printf("synced trusted user CA %s\n", ca.FingerprintSHA256)
		fmt.Printf("wrote %s\n", cfg.TrustedUserCAPath)
		fmt.Printf("wrote %s\n", cfg.SSHDIncludePath)
		fmt.Printf("wrote %s\n", cfg.RevocationPath)
		fmt.Printf("wrote %s (%d revoked certificate serials)\n", cfg.RevokedKeysPath, len(revocationState.RevokedCertificateSerials))
	}
	return nil
}

func Watch(ctx context.Context, cfg config.Config, interval time.Duration) error {
	if interval <= 0 {
		interval = 2 * time.Second
	}

	if err := RunWithOptions(ctx, cfg, Options{Quiet: true}); err != nil {
		return err
	}
	fmt.Printf("watching platform revocation state every %s\n", interval)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := RunWithOptions(ctx, cfg, Options{Quiet: true}); err != nil {
				fmt.Fprintf(os.Stderr, "warning: sync failed: %v\n", err)
			}
		}
	}
}

func fetchTrustedUserCA(ctx context.Context, cfg config.Config) (trustedUserCAResponse, error) {
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		cfg.PlatformURL+"/api/v1/servers/trusted-user-ca",
		nil,
	)
	if err != nil {
		return trustedUserCAResponse{}, err
	}
	if cfg.ServerID != "" {
		req.Header.Set("X-Keyward-Server-ID", cfg.ServerID)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return trustedUserCAResponse{}, err
	}
	defer resp.Body.Close()

	var result trustedUserCAResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return trustedUserCAResponse{}, err
	}
	if resp.StatusCode != http.StatusOK {
		if result.Error == "" {
			result.Error = resp.Status
		}
		return trustedUserCAResponse{}, fmt.Errorf("platform returned %s: %s", resp.Status, result.Error)
	}
	if result.TrustedUserCAPublicKey == "" {
		return trustedUserCAResponse{}, fmt.Errorf("platform returned an empty trusted user CA")
	}
	return result, nil
}

func fetchRevocationState(ctx context.Context, cfg config.Config) (revocationStateResponse, error) {
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		cfg.PlatformURL+"/api/v1/servers/revocation-state",
		nil,
	)
	if err != nil {
		return revocationStateResponse{}, err
	}
	if cfg.ServerID != "" {
		req.Header.Set("X-Keyward-Server-ID", cfg.ServerID)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return revocationStateResponse{}, err
	}
	defer resp.Body.Close()

	var result revocationStateResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return revocationStateResponse{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return revocationStateResponse{}, fmt.Errorf("platform returned %s while fetching revocation state", resp.Status)
	}
	return result, nil
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = os.Remove(tmpPath)
	}()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpPath, mode); err != nil {
		return err
	}

	existing, err := os.ReadFile(path)
	if err == nil && bytes.Equal(existing, data) {
		return os.Remove(tmpPath)
	}

	return os.Rename(tmpPath, path)
}

func writeRevokedKeysKRL(cfg config.Config, state revocationStateResponse) error {
	if err := os.MkdirAll(filepath.Dir(cfg.RevokedKeysPath), 0o755); err != nil {
		return err
	}

	specContent := revokedSerialSpec(state)
	cachePath := cfg.RevokedKeysPath + ".serials"
	if cached, err := os.ReadFile(cachePath); err == nil && bytes.Equal(cached, []byte(specContent)) {
		if _, err := os.Stat(cfg.RevokedKeysPath); err == nil {
			return nil
		}
	}

	spec, err := os.CreateTemp(filepath.Dir(cfg.RevokedKeysPath), "revoked-serials-*.krlspec")
	if err != nil {
		return err
	}
	specPath := spec.Name()
	defer func() {
		_ = os.Remove(specPath)
	}()

	if _, err := spec.WriteString(specContent); err != nil {
		_ = spec.Close()
		return err
	}
	if err := spec.Close(); err != nil {
		return err
	}

	tmpKRL, err := os.CreateTemp(filepath.Dir(cfg.RevokedKeysPath), filepath.Base(cfg.RevokedKeysPath)+".tmp-*")
	if err != nil {
		return err
	}
	tmpKRLPath := tmpKRL.Name()
	if err := tmpKRL.Close(); err != nil {
		_ = os.Remove(tmpKRLPath)
		return err
	}
	defer func() {
		_ = os.Remove(tmpKRLPath)
	}()

	cmd := exec.Command("ssh-keygen", "-k", "-f", tmpKRLPath, "-s", cfg.TrustedUserCAPath, specPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ssh-keygen krl generation failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	if err := os.Chmod(tmpKRLPath, 0o644); err != nil {
		return err
	}

	existing, err := os.ReadFile(cfg.RevokedKeysPath)
	generated, readErr := os.ReadFile(tmpKRLPath)
	if err == nil && readErr == nil && bytes.Equal(existing, generated) {
		return os.Remove(tmpKRLPath)
	}
	if err := os.Rename(tmpKRLPath, cfg.RevokedKeysPath); err != nil {
		return err
	}
	return atomicWrite(cachePath, []byte(specContent), 0o644)
}

func revokedSerialSpec(state revocationStateResponse) string {
	var builder strings.Builder
	for _, serial := range state.RevokedCertificateSerials {
		if serial <= 0 {
			continue
		}
		fmt.Fprintf(&builder, "serial: %d\n", serial)
	}
	return builder.String()
}
