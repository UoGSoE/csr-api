package auth

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/billyraycyrus/csr-api/internal/store"
)

var testLogger = slog.Default()

func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.New(":memory:")
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func insertTestToken(t *testing.T, s *store.Store, rawToken string) {
	t.Helper()
	err := s.InsertToken(&store.AuthToken{
		TokenHash:   HashToken(rawToken),
		TokenPrefix: TokenPrefix(rawToken),
		ForWhom:     "test",
		CreatedAt:   time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		t.Fatalf("insert token: %v", err)
	}
}

func TestBearerAuth_ValidToken(t *testing.T) {
	s := newTestStore(t)
	rawToken := "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	insertTestToken(t, s, rawToken)

	handler := BearerAuth(s, testLogger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+rawToken)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestBearerAuth_MissingHeader(t *testing.T) {
	s := newTestStore(t)

	handler := BearerAuth(s, testLogger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}

	var body map[string]string
	json.NewDecoder(rec.Body).Decode(&body)
	if body["error"] == "" {
		t.Error("expected error message in body")
	}
}

func TestBearerAuth_InvalidToken(t *testing.T) {
	s := newTestStore(t)

	handler := BearerAuth(s, testLogger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer invalid-token-that-does-not-exist")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestBearerAuth_RevokedToken(t *testing.T) {
	s := newTestStore(t)
	rawToken := "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	insertTestToken(t, s, rawToken)
	tok, _ := s.GetTokenByHash(HashToken(rawToken))
	s.RevokeTokenByID(tok.ID)

	handler := BearerAuth(s, testLogger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+rawToken)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}
