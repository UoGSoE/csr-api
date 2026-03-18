package auth

import (
	"testing"
)

func TestGenerateToken_Length(t *testing.T) {
	token, err := GenerateToken()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if len(token) != 64 {
		t.Errorf("length = %d, want 64", len(token))
	}
}

func TestGenerateToken_Unique(t *testing.T) {
	t1, _ := GenerateToken()
	t2, _ := GenerateToken()
	if t1 == t2 {
		t.Error("two generated tokens should not be equal")
	}
}

func TestHashToken_Deterministic(t *testing.T) {
	h1 := HashToken("test-token-123")
	h2 := HashToken("test-token-123")
	if h1 != h2 {
		t.Errorf("hash not deterministic: %q != %q", h1, h2)
	}
	if len(h1) != 64 {
		t.Errorf("hash length = %d, want 64 (SHA-256 hex)", len(h1))
	}
}

func TestTokenPrefix_Length(t *testing.T) {
	p := TokenPrefix("abcdef1234567890")
	if len(p) != 8 {
		t.Errorf("prefix length = %d, want 8", len(p))
	}
	if p != "abcdef12" {
		t.Errorf("prefix = %q, want %q", p, "abcdef12")
	}
}
