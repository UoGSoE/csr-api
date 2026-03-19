package server

import (
	"github.com/billyraycyrus/csr-api/internal/auth"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func (s *Server) setupRoutes() {
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)

	r.Group(func(r chi.Router) {
		r.Use(auth.BearerAuth(s.store, s.logger))
		r.Post("/submit-csr", s.handleSubmitCSR)
		r.Get("/status/{hostname}", s.handleGetStatus)
	})

	s.router = r
}
