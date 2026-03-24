package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

// GenerateToken returns a 64-char hex token (32 random bytes).
func GenerateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("read random bytes: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// HashToken returns the SHA-256 hex digest of the raw token.
func HashToken(rawToken string) string {
	h := sha256.Sum256([]byte(rawToken))
	return hex.EncodeToString(h[:])
}

// TokenPrefix returns the first 8 characters of the raw token.
func TokenPrefix(rawToken string) string {
	if len(rawToken) < 8 {
		return rawToken
	}
	return rawToken[:8]
}

var nonAlnum = regexp.MustCompile(`[^a-z0-9]+`)

// SafeDirName converts a for_whom string into a filesystem-friendly directory
// name. It lowercases, replaces runs of non-alphanumeric characters with a
// single hyphen, and trims leading/trailing hyphens. If the result is empty
// it falls back to "unknown".
func SafeDirName(name string) string {
	s := strings.ToLower(strings.TrimSpace(name))
	s = nonAlnum.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if s == "" {
		return "unknown"
	}
	return s
}
