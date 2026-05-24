package enroll

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/playup/keyward/agents/device-client/internal/config"
)

type StartResult struct {
	EnrollmentID string `json:"enrollment_id"`
	Challenge    string `json:"challenge"`
	ExpiresAt    string `json:"expires_at"`
	Status       string `json:"status"`
	UserCode     string `json:"user_code"`
	VerifyURI    string `json:"verification_uri"`
	CompleteURI  string `json:"verification_uri_complete"`
	Interval     int    `json:"interval_seconds"`
	UserEmail    string `json:"user_email"`
}

type FinishRequest struct {
	EnrollmentID       string
	PublicKey          string
	Fingerprint        string
	ChallengeSignature string
	Posture            map[string]any
}

type FinishResult struct {
	DeviceID   string `json:"device_id"`
	UserID     string `json:"user_id"`
	Status     string `json:"status"`
	TrustLevel string `json:"trust_level"`
}

type StartRequest struct {
	DeviceName  string
	Platform    string
	CallbackURL string
}

func Start(ctx context.Context, cfg config.Config, startRequest StartRequest) (StartResult, error) {
	body, err := json.Marshal(map[string]string{
		"name":         startRequest.DeviceName,
		"platform":     startRequest.Platform,
		"callback_url": startRequest.CallbackURL,
	})
	if err != nil {
		return StartResult{}, err
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		cfg.PlatformURL+"/api/v1/devices/enroll/start-login",
		bytes.NewReader(body),
	)
	if err != nil {
		return StartResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return StartResult{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		if resp.StatusCode != http.StatusCreated {
			return StartResult{}, fmt.Errorf("platform returned %s", resp.Status)
		}
	}

	var result StartResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return StartResult{}, err
	}
	return result, nil
}

func PollApproved(ctx context.Context, cfg config.Config, enrollmentID string, intervalSeconds int) (StartResult, error) {
	if intervalSeconds <= 0 {
		intervalSeconds = 3
	}
	ticker := time.NewTicker(time.Duration(intervalSeconds) * time.Second)
	defer ticker.Stop()

	for {
		result, statusCode, err := pollOnce(ctx, cfg, enrollmentID)
		if err != nil {
			return StartResult{}, err
		}
		if statusCode == http.StatusOK && result.Status == "approved" {
			return result, nil
		}
		if statusCode != http.StatusAccepted {
			return StartResult{}, fmt.Errorf("enrollment status %s", result.Status)
		}

		select {
		case <-ctx.Done():
			return StartResult{}, ctx.Err()
		case <-ticker.C:
		}
	}
}

func PollOnce(ctx context.Context, cfg config.Config, enrollmentID string) (StartResult, error) {
	result, statusCode, err := pollOnce(ctx, cfg, enrollmentID)
	if err != nil {
		return StartResult{}, err
	}
	if statusCode != http.StatusOK || result.Status != "approved" {
		return StartResult{}, fmt.Errorf("enrollment status %s", result.Status)
	}
	return result, nil
}

func pollOnce(ctx context.Context, cfg config.Config, enrollmentID string) (StartResult, int, error) {
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		cfg.PlatformURL+"/api/v1/devices/enroll/"+enrollmentID+"/poll",
		nil,
	)
	if err != nil {
		return StartResult{}, 0, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return StartResult{}, 0, err
	}
	defer resp.Body.Close()

	var result StartResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return StartResult{}, resp.StatusCode, err
	}
	return result, resp.StatusCode, nil
}

func StartDirect(ctx context.Context, cfg config.Config, startRequest StartRequest, userEmail string) (StartResult, error) {
	body, err := json.Marshal(map[string]string{
		"name":       startRequest.DeviceName,
		"user_email": userEmail,
		"platform":   startRequest.Platform,
	})
	if err != nil {
		return StartResult{}, err
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		cfg.PlatformURL+"/api/v1/devices/enroll/start",
		bytes.NewReader(body),
	)
	if err != nil {
		return StartResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return StartResult{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		return StartResult{}, fmt.Errorf("platform returned %s", resp.Status)
	}

	var result StartResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return StartResult{}, err
	}
	return result, nil
}

func Finish(ctx context.Context, cfg config.Config, finishRequest FinishRequest) (FinishResult, error) {
	body, err := json.Marshal(map[string]any{
		"enrollment_id":       finishRequest.EnrollmentID,
		"public_key":          finishRequest.PublicKey,
		"fingerprint":         finishRequest.Fingerprint,
		"challenge_signature": finishRequest.ChallengeSignature,
		"posture":             finishRequest.Posture,
	})
	if err != nil {
		return FinishResult{}, err
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		cfg.PlatformURL+"/api/v1/devices/enroll/finish",
		bytes.NewReader(body),
	)
	if err != nil {
		return FinishResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return FinishResult{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return FinishResult{}, fmt.Errorf("platform returned %s", resp.Status)
	}

	var result FinishResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return FinishResult{}, err
	}
	return result, nil
}
