package server

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"strings"
	"os"
	"path/filepath"
	"time"

	"github.com/billyraycyrus/csr-api/internal/auth"
	"github.com/billyraycyrus/csr-api/internal/store"
	"github.com/go-chi/chi/v5"
)

type submitCSRIn struct {
	Hostname string `json:"hostname"`
	B64CSR   string `json:"b64_csr"`
}

type submitCSROut struct {
	Hostname    string `json:"hostname"`
	SubmittedBy string `json:"submitted_by"`
	Status      string `json:"status"`
	Message     string `json:"message"`
}

type statusOut struct {
	Hostname    string  `json:"hostname"`
	SubmittedBy string  `json:"submitted_by"`
	Status      string  `json:"status"`
	CreatedAt   string  `json:"created_at"`
	CompletedAt *string `json:"completed_at"`
}

func (s *Server) handleSubmitCSR(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10) // 32 KB

	var req submitCSRIn
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	if req.Hostname == "" {
		writeError(w, http.StatusBadRequest, "hostname is required")
		return
	}

	csrPEM, err := base64.StdEncoding.DecodeString(req.B64CSR)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid base64 in b64_csr")
		return
	}

	if err := validateCSR(csrPEM, req.Hostname); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	submittedBy := auth.ForWhomFromContext(r.Context())

	// Save CSR to disk: {csrs-dir}/{submitted-by}/{hostname}.csr
	ownerDir := filepath.Join(s.csrsDir, submittedBy)
	if err := os.MkdirAll(ownerDir, 0o755); err != nil {
		s.logger.Error("create csr dir failed", "path", ownerDir, "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	csrPath := filepath.Join(ownerDir, req.Hostname+".csr")
	if !filepath.IsAbs(csrPath) || filepath.Dir(csrPath) != ownerDir {
		writeError(w, http.StatusBadRequest, "invalid hostname")
		return
	}
	if err := os.WriteFile(csrPath, csrPEM, 0o644); err != nil {
		s.logger.Error("write csr failed", "path", csrPath, "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	now := time.Now().UTC().Format(time.RFC3339)
	_, err = s.store.InsertCertRequest(&store.CertRequest{
		Hostname:    req.Hostname,
		CSRPEM:      string(csrPEM),
		CSRPath:     csrPath,
		SubmittedBy: submittedBy,
		Status:      "submitted",
		CreatedAt:   now,
	})
	if err != nil {
		s.logger.Error("insert request failed", "hostname", req.Hostname, "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	s.logger.Info("csr submitted", "hostname", req.Hostname, "submitted_by", submittedBy, "path", csrPath)

	writeJSON(w, http.StatusAccepted, submitCSROut{
		Hostname:    req.Hostname,
		SubmittedBy: submittedBy,
		Status:      "submitted",
		Message:     "CSR received and saved. It will be processed shortly.",
	})
}

func (s *Server) handleGetStatus(w http.ResponseWriter, r *http.Request) {
	hostname := chi.URLParam(r, "hostname")
	owner := auth.ForWhomFromContext(r.Context())

	cr, err := s.store.GetLatestByHostnameAndOwner(hostname, owner)
	if err != nil {
		s.logger.Error("get status failed", "hostname", hostname, "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if cr == nil {
		writeError(w, http.StatusNotFound, "no request found")
		return
	}

	writeJSON(w, http.StatusOK, statusOut{
		Hostname:    cr.Hostname,
		SubmittedBy: cr.SubmittedBy,
		Status:      cr.Status,
		CreatedAt:   cr.CreatedAt,
		CompletedAt: cr.CompletedAt,
	})
}

func validateCSR(csrPEM []byte, hostname string) error {
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return &validationError{"no PEM block found in CSR"}
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return &validationError{"invalid CSR: " + err.Error()}
	}
	if csr.Subject.CommonName == "" && len(csr.DNSNames) == 0 {
		return &validationError{"CSR has no CN and no SANs"}
	}
	if err := csr.CheckSignature(); err != nil {
		return &validationError{"CSR signature verification failed"}
	}
	if !csrMatchesHostname(csr, hostname) {
		return &validationError{"hostname does not match CSR's CN or SANs"}
	}
	return nil
}

func csrMatchesHostname(csr *x509.CertificateRequest, hostname string) bool {
	if strings.EqualFold(csr.Subject.CommonName, hostname) {
		return true
	}
	for _, san := range csr.DNSNames {
		if strings.EqualFold(san, hostname) {
			return true
		}
	}
	return false
}

type validationError struct {
	msg string
}

func (e *validationError) Error() string { return e.msg }

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
