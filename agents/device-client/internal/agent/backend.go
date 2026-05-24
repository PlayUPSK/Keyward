package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/playup/keyward/agents/device-client/internal/config"
	"github.com/playup/keyward/agents/device-client/internal/presence"
	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
)

var (
	errReadOnlyAgent      = errors.New("Keyward SSH agent is read-only; use issue-cert to refresh identities")
	errExpiredCertificate = errors.New("ssh certificate expired")
)

type dynamicAgent struct {
	config config.Config
}

func newDynamicAgent(cfg config.Config) *dynamicAgent {
	return &dynamicAgent{config: cfg}
}

func (a *dynamicAgent) List() ([]*sshagent.Key, error) {
	keyring, err := a.loadKeyring()
	if err != nil {
		return nil, err
	}
	return keyring.List()
}

func (a *dynamicAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	if err := a.verifyPresenceIfRequired(key); err != nil {
		return nil, err
	}
	keyring, err := a.loadKeyring()
	if err != nil {
		return nil, err
	}
	return keyring.Sign(key, data)
}

func (a *dynamicAgent) SignWithFlags(key ssh.PublicKey, data []byte, flags sshagent.SignatureFlags) (*ssh.Signature, error) {
	if err := a.verifyPresenceIfRequired(key); err != nil {
		return nil, err
	}
	keyring, err := a.loadKeyring()
	if err != nil {
		return nil, err
	}
	if extended, ok := keyring.(sshagent.ExtendedAgent); ok {
		return extended.SignWithFlags(key, data, flags)
	}
	return keyring.Sign(key, data)
}

func (a *dynamicAgent) verifyPresenceIfRequired(key ssh.PublicKey) error {
	requirements, err := loadPresenceRequirements(a.config)
	if err != nil {
		return err
	}
	if !requirements[publicKeyID(key)] {
		return nil
	}
	return presence.Verify(context.Background(), a.config, "Approve SSH login with Keyward")
}

func (a *dynamicAgent) Add(key sshagent.AddedKey) error {
	_ = key
	return errReadOnlyAgent
}

func (a *dynamicAgent) Remove(key ssh.PublicKey) error {
	_ = key
	return errReadOnlyAgent
}

func (a *dynamicAgent) RemoveAll() error {
	return errReadOnlyAgent
}

func (a *dynamicAgent) Lock(passphrase []byte) error {
	_ = passphrase
	return errReadOnlyAgent
}

func (a *dynamicAgent) Unlock(passphrase []byte) error {
	_ = passphrase
	return errReadOnlyAgent
}

func (a *dynamicAgent) Signers() ([]ssh.Signer, error) {
	keyring, err := a.loadKeyring()
	if err != nil {
		return nil, err
	}
	return keyring.Signers()
}

func (a *dynamicAgent) Extension(extensionType string, contents []byte) ([]byte, error) {
	_ = extensionType
	_ = contents
	return nil, sshagent.ErrExtensionUnsupported
}

func (a *dynamicAgent) loadKeyring() (sshagent.Agent, error) {
	log.Printf("agent/backend: building keyring from %s", filepath.Dir(a.config.DefaultIdentityPath()))
	keyring := sshagent.NewKeyring()

	identities, err := loadIssuedIdentities(a.config)
	if err != nil {
		log.Printf("agent/backend: loadIssuedIdentities failed: %v", err)
		return nil, err
	}
	log.Printf("agent/backend: loaded %d identities from disk", len(identities))

	for _, identity := range identities {
		if err := keyring.Add(identity); err != nil {
			log.Printf("agent/backend: failed adding identity %q to keyring: %v", identity.Comment, err)
			return nil, err
		}
		log.Printf("agent/backend: added identity %q to keyring", identity.Comment)
	}

	return keyring, nil
}

func serveRawRequest(cfg config.Config, request []byte) ([]byte, error) {
	log.Printf("agent/backend: serving raw request (%d bytes)", len(request))
	rw := &bufferReadWriter{reader: bytes.NewReader(request)}
	if err := sshagent.ServeAgent(newDynamicAgent(cfg), rw); err != nil && !errors.Is(err, io.EOF) {
		log.Printf("agent/backend: raw request failed: %v", err)
		return nil, err
	}
	log.Printf("agent/backend: raw request produced %d bytes", rw.writer.Len())
	return rw.writer.Bytes(), nil
}

type bufferReadWriter struct {
	reader *bytes.Reader
	writer bytes.Buffer
}

func (rw *bufferReadWriter) Read(p []byte) (int, error) {
	return rw.reader.Read(p)
}

func (rw *bufferReadWriter) Write(p []byte) (int, error) {
	return rw.writer.Write(p)
}

func loadIssuedIdentities(cfg config.Config) ([]sshagent.AddedKey, error) {
	identityDir := filepath.Dir(cfg.DefaultIdentityPath())
	log.Printf("agent/backend: scanning identity directory %s", identityDir)
	entries, err := os.ReadDir(identityDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			log.Printf("agent/backend: identity directory does not exist: %s", identityDir)
			return nil, nil
		}
		log.Printf("agent/backend: failed reading identity directory %s: %v", identityDir, err)
		return nil, err
	}

	identities := make([]sshagent.AddedKey, 0, len(entries))
	for _, entry := range entries {
		log.Printf("agent/backend: found directory entry %s", entry.Name())
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), "-cert.pub") {
			continue
		}

		identity, err := loadIdentityPair(filepath.Join(identityDir, entry.Name()))
		if err != nil {
			if errors.Is(err, errExpiredCertificate) {
				log.Printf("agent/backend: skipping expired identity %s", entry.Name())
				continue
			}
			log.Printf("agent/backend: failed loading identity pair %s: %v", entry.Name(), err)
			return nil, err
		}
		identities = append(identities, identity)
	}
	log.Printf("agent/backend: finished scanning identities, found %d usable identities", len(identities))

	return identities, nil
}

func IssuedIdentityCount(cfg config.Config) (int, error) {
	identities, err := loadIssuedIdentities(cfg)
	if err != nil {
		return 0, err
	}
	return len(identities), nil
}

func loadIdentityPair(certPath string) (sshagent.AddedKey, error) {
	privateKeyPath := strings.TrimSuffix(certPath, "-cert.pub")
	log.Printf("agent/backend: loading identity pair private=%s cert=%s", privateKeyPath, certPath)

	privateKeyPEM, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return sshagent.AddedKey{}, fmt.Errorf("read private key %s: %w", privateKeyPath, err)
	}

	privateKey, err := ssh.ParseRawPrivateKey(privateKeyPEM)
	if err != nil {
		return sshagent.AddedKey{}, fmt.Errorf("parse private key %s: %w", privateKeyPath, err)
	}

	var signerKey ed25519.PrivateKey
	switch value := privateKey.(type) {
	case ed25519.PrivateKey:
		signerKey = value
	case *ed25519.PrivateKey:
		signerKey = *value
	default:
		return sshagent.AddedKey{}, fmt.Errorf("private key %s is %T; only ed25519 identities are supported", privateKeyPath, privateKey)
	}

	certData, err := os.ReadFile(certPath)
	if err != nil {
		return sshagent.AddedKey{}, fmt.Errorf("read certificate %s: %w", certPath, err)
	}

	publicKey, _, _, _, err := ssh.ParseAuthorizedKey(certData)
	if err != nil {
		return sshagent.AddedKey{}, fmt.Errorf("parse certificate %s: %w", certPath, err)
	}

	certificate, ok := publicKey.(*ssh.Certificate)
	if !ok {
		return sshagent.AddedKey{}, fmt.Errorf("public key %s is not an SSH certificate", certPath)
	}
	if certificate.ValidBefore <= uint64(time.Now().Unix()) {
		return sshagent.AddedKey{}, fmt.Errorf("%w: %s", errExpiredCertificate, certPath)
	}
	log.Printf("agent/backend: loaded identity %s", filepath.Base(privateKeyPath))

	return sshagent.AddedKey{
		PrivateKey:  signerKey,
		Certificate: certificate,
		Comment:     filepath.Base(privateKeyPath),
	}, nil
}

type identityMetadata struct {
	RequireUserPresence bool `json:"require_user_presence"`
}

func loadPresenceRequirements(cfg config.Config) (map[string]bool, error) {
	identityDir := filepath.Dir(cfg.DefaultIdentityPath())
	entries, err := os.ReadDir(identityDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return map[string]bool{}, nil
		}
		return nil, err
	}

	requirements := map[string]bool{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), "-cert.pub") {
			continue
		}
		certPath := filepath.Join(identityDir, entry.Name())
		metadata, err := readIdentityMetadata(strings.TrimSuffix(certPath, "-cert.pub") + ".keyward.json")
		if err != nil || !metadata.RequireUserPresence {
			continue
		}
		certData, err := os.ReadFile(certPath)
		if err != nil {
			return nil, err
		}
		publicKey, _, _, _, err := ssh.ParseAuthorizedKey(certData)
		if err != nil {
			return nil, err
		}
		requirements[publicKeyID(publicKey)] = true
	}
	return requirements, nil
}

func readIdentityMetadata(path string) (identityMetadata, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return identityMetadata{}, err
	}
	var metadata identityMetadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		return identityMetadata{}, err
	}
	return metadata, nil
}

func publicKeyID(key ssh.PublicKey) string {
	return base64.StdEncoding.EncodeToString(key.Marshal())
}
