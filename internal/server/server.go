package server

import (
	"log/slog"
	"net/http"

	"github.com/billyraycyrus/csr-api/internal/acme"
	"github.com/billyraycyrus/csr-api/internal/store"
	"github.com/go-chi/chi/v5"
)

type Server struct {
	obtainer acme.CertObtainer
	store    *store.Store
	router   chi.Router
	logger   *slog.Logger
}

type Config struct {
	Obtainer acme.CertObtainer
	Store    *store.Store
	Logger   *slog.Logger
}

func New(cfg Config) *Server {
	s := &Server{
		obtainer: cfg.Obtainer,
		store:    cfg.Store,
		logger:   cfg.Logger,
	}
	s.setupRoutes()
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}
