package auth

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/billyraycyrus/csr-api/internal/store"
)

// BearerAuth returns middleware that validates Authorization: Bearer <token>.
func BearerAuth(st *store.Store, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			header := r.Header.Get("Authorization")
			if !strings.HasPrefix(header, "Bearer ") {
				writeAuthError(w, "missing or invalid Authorization header")
				return
			}

			rawToken := strings.TrimPrefix(header, "Bearer ")
			hash := HashToken(rawToken)

			token, err := st.GetTokenByHash(hash)
			if err != nil {
				logger.Error("auth lookup failed", "err", err)
				writeAuthError(w, "internal error")
				return
			}
			if token == nil || token.Revoked {
				logger.Warn("auth rejected", "prefix", TokenPrefix(rawToken))
				writeAuthError(w, "invalid or revoked token")
				return
			}

			if err := st.TouchTokenLastUsed(token.ID); err != nil {
				logger.Warn("touch last_used failed", "err", err)
			}

			next.ServeHTTP(w, r)
		})
	}
}

func writeAuthError(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
