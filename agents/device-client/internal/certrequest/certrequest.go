package certrequest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/playup/keyward/agents/device-client/internal/config"
	"golang.org/x/crypto/ssh"
)

type Request struct {
	RequestID             string `json:"request_id"`
	DeviceID              string `json:"device_id"`
	Server                string `json:"server"`
	SSHPrincipal          string `json:"ssh_principal"`
	EphemeralSSHPublicKey string `json:"ephemeral_ssh_public_key"`
	PublicKeyFingerprint  string `json:"public_key_fingerprint"`
	Nonce                 string `json:"nonce"`
	Timestamp             string `json:"timestamp"`
	Signature             string `json:"signature"`
}

type Response struct {
	Decision    string `json:"decision"`
	Reason      string `json:"reason"`
	Certificate string `json:"certificate"`
	ValidBefore string `json:"valid_before"`
	Serial      int64  `json:"serial"`
	KeyID       string `json:"key_id"`
	Constraints struct {
		RequireUserPresence bool `json:"require_user_presence"`
	} `json:"constraints"`
}

type IssueOptions struct {
	Server       string
	SSHPrincipal string
	IdentityPath string
}

func Issue(ctx context.Context, cfg config.Config, devicePrivateKey ed25519.PrivateKey, options IssueOptions) (Response, error) {
	if cfg.DeviceID == "" {
		return Response{}, fmt.Errorf("device is not enrolled; run enroll first")
	}
	if options.Server == "" || options.SSHPrincipal == "" {
		return Response{}, fmt.Errorf("server and principal are required")
	}

	identityPath := options.IdentityPath
	if identityPath == "" {
		identityPath = filepath.Join(filepath.Dir(cfg.DeviceKeyPath), "ephemeral_ed25519")
	}

	publicKey, err := generateEphemeralSSHKey(identityPath)
	if err != nil {
		return Response{}, err
	}

	request, err := buildSignedRequest(cfg.DeviceID, publicKey, devicePrivateKey, options)
	if err != nil {
		return Response{}, err
	}

	response, err := send(ctx, cfg, request)
	if err != nil {
		return Response{}, err
	}
	if response.Decision != "allow" {
		return response, fmt.Errorf("certificate request denied: %s", response.Reason)
	}

	certPath := identityPath + "-cert.pub"
	if err := os.WriteFile(certPath, []byte(response.Certificate+"\n"), 0o600); err != nil {
		return Response{}, err
	}
	if err := writeIdentityMetadata(identityPath, response); err != nil {
		return Response{}, err
	}

	return response, nil
}

func CanonicalRequest(request Request) ([]byte, error) {
	canonical := map[string]string{
		"device_id":                request.DeviceID,
		"ephemeral_ssh_public_key": request.EphemeralSSHPublicKey,
		"nonce":                    request.Nonce,
		"request_id":               request.RequestID,
		"server":                   request.Server,
		"ssh_principal":            request.SSHPrincipal,
		"timestamp":                request.Timestamp,
	}
	return json.Marshal(canonical)
}

func buildSignedRequest(deviceID string, publicKey string, privateKey ed25519.PrivateKey, options IssueOptions) (Request, error) {
	requestID, err := randomHex(16)
	if err != nil {
		return Request{}, err
	}
	nonce, err := randomHex(24)
	if err != nil {
		return Request{}, err
	}

	request := Request{
		RequestID:             requestID,
		DeviceID:              deviceID,
		Server:                options.Server,
		SSHPrincipal:          options.SSHPrincipal,
		EphemeralSSHPublicKey: strings.TrimSpace(publicKey),
		PublicKeyFingerprint:  fingerprint(publicKey),
		Nonce:                 nonce,
		Timestamp:             time.Now().UTC().Format(time.RFC3339),
	}

	canonical, err := CanonicalRequest(request)
	if err != nil {
		return Request{}, err
	}
	signature := ed25519.Sign(privateKey, canonical)
	request.Signature = base64.StdEncoding.EncodeToString(signature)
	return request, nil
}

func send(ctx context.Context, cfg config.Config, request Request) (Response, error) {
	body, err := json.Marshal(request)
	if err != nil {
		return Response{}, err
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		cfg.PlatformURL+"/api/v1/ssh-certificates/request",
		bytes.NewReader(body),
	)
	if err != nil {
		return Response{}, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return Response{}, err
	}
	defer resp.Body.Close()

	var result Response
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return Response{}, err
	}
	if resp.StatusCode != http.StatusCreated {
		return result, fmt.Errorf("platform returned %s: %s", resp.Status, result.Reason)
	}
	return result, nil
}

func generateEphemeralSSHKey(identityPath string) (string, error) {
	if err := os.MkdirAll(filepath.Dir(identityPath), 0o700); err != nil {
		return "", err
	}
	_ = os.Remove(identityPath)
	_ = os.Remove(identityPath + ".pub")
	_ = os.Remove(identityPath + "-cert.pub")

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	privateBlock, err := ssh.MarshalPrivateKey(privateKey, "keyward-ephemeral")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(identityPath, pem.EncodeToMemory(privateBlock), 0o600); err != nil {
		return "", err
	}
	sshPublicKey, err := ssh.NewPublicKey(publicKey)
	if err != nil {
		return "", err
	}
	publicKeyLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPublicKey))) + " keyward-ephemeral\n"

	if err := os.Chmod(identityPath, 0o600); err != nil {
		return "", err
	}
	if err := os.WriteFile(identityPath+".pub", []byte(publicKeyLine), 0o644); err != nil {
		return "", err
	}
	return strings.TrimSpace(publicKeyLine), nil
}

func randomHex(bytesLen int) (string, error) {
	value := make([]byte, bytesLen)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

func fingerprint(publicKey string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(publicKey)))
	return "SHA256:" + base64.RawURLEncoding.EncodeToString(sum[:])
}

func writeIdentityMetadata(identityPath string, response Response) error {
	metadata := map[string]any{
		"serial":                 response.Serial,
		"key_id":                 response.KeyID,
		"valid_before":           response.ValidBefore,
		"require_user_presence":  response.Constraints.RequireUserPresence,
		"presence_policy_source": "platform_policy",
	}
	data, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(identityPath+".keyward.json", append(data, '\n'), 0o600)
}
