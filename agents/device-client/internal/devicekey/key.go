package devicekey

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

type KeyPair struct {
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
}

func LoadOrCreate(path string) (KeyPair, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		return parsePrivateKeyPEM(data)
	}
	if !os.IsNotExist(err) {
		return KeyPair{}, err
	}

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return KeyPair{}, err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return KeyPair{}, err
	}

	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return KeyPair{}, err
	}
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		return KeyPair{}, err
	}

	return KeyPair{PublicKey: publicKey, PrivateKey: privateKey}, nil
}

func PublicKeyPEM(publicKey ed25519.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), nil
}

func Fingerprint(publicKey ed25519.PublicKey) string {
	sum := sha256.Sum256(publicKey)
	return "SHA256:" + base64.RawURLEncoding.EncodeToString(sum[:])
}

func SignChallenge(privateKey ed25519.PrivateKey, challenge string) string {
	signature := ed25519.Sign(privateKey, []byte(challenge))
	return base64.StdEncoding.EncodeToString(signature)
}

func parsePrivateKeyPEM(data []byte) (KeyPair, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return KeyPair{}, fmt.Errorf("device key is not PEM encoded")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return KeyPair{}, err
	}

	privateKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return KeyPair{}, fmt.Errorf("device key is not Ed25519")
	}

	publicKey, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok {
		return KeyPair{}, fmt.Errorf("device public key is not Ed25519")
	}

	return KeyPair{PublicKey: publicKey, PrivateKey: privateKey}, nil
}
