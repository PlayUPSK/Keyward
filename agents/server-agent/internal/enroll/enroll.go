package enroll

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/playup/keyward/agents/server-agent/internal/config"
)

type TokenResult struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
}

type CreateTokenRequest struct {
	Hostname    string
	Environment string
}

type RedeemTokenRequest struct {
	Token        string
	PublicKey    string
	AgentVersion string
	Hostname     string
}

type RedeemTokenResult struct {
	ServerID string `json:"server_id"`
	Hostname string `json:"hostname"`
	Status   string `json:"status"`
}

func CreateToken(ctx context.Context, cfg config.Config, createRequest CreateTokenRequest) (TokenResult, error) {
	body, err := json.Marshal(map[string]string{
		"hostname":    createRequest.Hostname,
		"environment": createRequest.Environment,
	})
	if err != nil {
		return TokenResult{}, err
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		cfg.PlatformURL+"/api/v1/servers/enrollment-tokens",
		bytes.NewReader(body),
	)
	if err != nil {
		return TokenResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return TokenResult{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return TokenResult{}, fmt.Errorf("platform returned %s", resp.Status)
	}

	var result TokenResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return TokenResult{}, err
	}
	return result, nil
}

func RedeemToken(ctx context.Context, cfg config.Config, redeemRequest RedeemTokenRequest) (RedeemTokenResult, error) {
	body, err := json.Marshal(map[string]string{
		"token":         redeemRequest.Token,
		"public_key":    redeemRequest.PublicKey,
		"agent_version": redeemRequest.AgentVersion,
		"hostname":      redeemRequest.Hostname,
	})
	if err != nil {
		return RedeemTokenResult{}, err
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		cfg.PlatformURL+"/api/v1/servers/enroll",
		bytes.NewReader(body),
	)
	if err != nil {
		return RedeemTokenResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return RedeemTokenResult{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return RedeemTokenResult{}, fmt.Errorf("platform returned %s", resp.Status)
	}

	var result RedeemTokenResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return RedeemTokenResult{}, err
	}
	return result, nil
}
