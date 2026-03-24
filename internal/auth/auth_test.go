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

func TestSafeDirName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"physics", "physics"},
		{"alice", "alice"},
		{"jim@chemistry", "jim-chemistry"},
		{"steve@james watt (south)", "steve-james-watt-south"},
		{"  Physics  ", "physics"},
		{"../../etc", "etc"},
		{"../../../passwd", "passwd"},
		{"foo///bar", "foo-bar"},
		{"hello---world", "hello-world"},
		{"  ", "unknown"},
		{"", "unknown"},
		{"@@@", "unknown"},
		{"Glasgow-IT", "glasgow-it"},
		{"Computing Science (Level 4)", "computing-science-level-4"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := SafeDirName(tt.input)
			if got != tt.want {
				t.Errorf("SafeDirName(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
