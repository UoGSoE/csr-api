package server

import (
	"log/slog"
	"net/http"

	"github.com/billyraycyrus/csr-api/internal/store"
	"github.com/go-chi/chi/v5"
)

type Server struct {
	store   *store.Store
	router  chi.Router
	logger  *slog.Logger
	csrsDir string
}

type Config struct {
	Store   *store.Store
	Logger  *slog.Logger
	CSRsDir string
}

func New(cfg Config) *Server {
	s := &Server{
		store:   cfg.Store,
		logger:  cfg.Logger,
		csrsDir: cfg.CSRsDir,
	}
	s.setupRoutes()
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}
