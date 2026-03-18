package acme

import (
	"crypto/ecdsa"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-acme/lego/v4/registration"
)

func TestLoadOrCreateAccount_CreatesNewKey(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "subdir", "account.key")

	acc, err := LoadOrCreateAccount("test@example.com", keyPath)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	if acc.Email != "test@example.com" {
		t.Errorf("email = %q, want %q", acc.Email, "test@example.com")
	}

	if _, ok := acc.key.(*ecdsa.PrivateKey); !ok {
		t.Error("key should be *ecdsa.PrivateKey")
	}

	if _, err := os.Stat(keyPath); err != nil {
		t.Errorf("key file should exist: %v", err)
	}
}

func TestLoadOrCreateAccount_LoadsExistingKey(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "account.key")

	acc1, err := LoadOrCreateAccount("test@example.com", keyPath)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	acc2, err := LoadOrCreateAccount("test@example.com", keyPath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	k1 := acc1.key.(*ecdsa.PrivateKey)
	k2 := acc2.key.(*ecdsa.PrivateKey)
	if !k1.Equal(k2) {
		t.Error("loaded key should equal original key")
	}
}

func TestAccount_ImplementsRegistrationUser(t *testing.T) {
	acc := &Account{Email: "test@example.com"}
	var _ registration.User = acc
}
