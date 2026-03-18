package server

import (
	"encoding/base64"
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
)

type certRequestIn struct {
	Hostname string `json:"hostname"`
	B64CSR   string `json:"b64_csr"`
}

type certRequestOut struct {
	Hostname       string `json:"hostname"`
	TXTRecordName  string `json:"txt_record_name"`
	TXTRecordValue string `json:"txt_record_value"`
	Message        string `json:"message"`
}

type statusOut struct {
	Hostname    string  `json:"hostname"`
	Status      string  `json:"status"`
	TXTValue    string  `json:"txt_value"`
	CreatedAt   string  `json:"created_at"`
	CompletedAt *string `json:"completed_at"`
}

func (s *Server) handleRequestCert(w http.ResponseWriter, r *http.Request) {
	var req certRequestIn
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	csrPEM, err := base64.StdEncoding.DecodeString(req.B64CSR)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid base64 in b64_csr")
		return
	}

	challenge, err := s.obtainer.ObtainCert(r.Context(), csrPEM, req.Hostname)
	if err != nil {
		s.logger.Error("obtain cert failed", "hostname", req.Hostname, "err", err)
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, certRequestOut{
		Hostname:       req.Hostname,
		TXTRecordName:  challenge.FQDN,
		TXTRecordValue: challenge.Value,
		Message:        "Create this TXT record in DNS. We will poll and finalise automatically.",
	})
}

func (s *Server) handleGetStatus(w http.ResponseWriter, r *http.Request) {
	hostname := chi.URLParam(r, "hostname")

	cr, err := s.store.GetLatestByHostname(hostname)
	if err != nil {
		s.logger.Error("get status failed", "hostname", hostname, "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if cr == nil {
		writeError(w, http.StatusNotFound, "No request found")
		return
	}

	writeJSON(w, http.StatusOK, statusOut{
		Hostname:    cr.Hostname,
		Status:      cr.Status,
		TXTValue:    cr.TXTValue,
		CreatedAt:   cr.CreatedAt,
		CompletedAt: cr.CompletedAt,
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
