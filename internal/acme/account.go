package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"github.com/go-acme/lego/v4/registration"
)

// Account implements registration.User for lego.
type Account struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (a *Account) GetEmail() string                        { return a.Email }
func (a *Account) GetRegistration() *registration.Resource { return a.Registration }
func (a *Account) GetPrivateKey() crypto.PrivateKey        { return a.key }

// LoadOrCreateAccount loads an existing account key from keyPath,
// or generates a new ECDSA P-256 key and saves it.
func LoadOrCreateAccount(email, keyPath string) (*Account, error) {
	if data, err := os.ReadFile(keyPath); err == nil {
		key, err := parseECKey(data)
		if err != nil {
			return nil, fmt.Errorf("parse existing key: %w", err)
		}
		return &Account{Email: email, key: key}, nil
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal key: %w", err)
	}

	pemData := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})

	if err := os.MkdirAll(filepath.Dir(keyPath), 0o755); err != nil {
		return nil, fmt.Errorf("create key dir: %w", err)
	}
	if err := os.WriteFile(keyPath, pemData, 0o600); err != nil {
		return nil, fmt.Errorf("write key: %w", err)
	}

	return &Account{Email: email, key: key}, nil
}

func parseECKey(data []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	return x509.ParseECPrivateKey(block.Bytes)
}
