package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/billyraycyrus/csr-api/internal/auth"
	"github.com/billyraycyrus/csr-api/internal/store"
	"github.com/go-chi/chi/v5"
)

func newTestServer(t *testing.T) (*Server, *store.Store) {
	t.Helper()
	st, err := store.New(":memory:")
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	srv := &Server{
		store:   st,
		logger:  slog.Default(),
		csrsDir: t.TempDir(),
	}
	return srv, st
}

// makeCSRPEM generates a real CSR PEM for testing.
func makeCSRPEM(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatalf("create csr: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
}

func withForWhom(r *http.Request, forWhom string) *http.Request {
	ctx := context.WithValue(r.Context(), auth.ForWhomKey(), forWhom)
	return r.WithContext(ctx)
}

func TestHandleSubmitCSR_Success(t *testing.T) {
	srv, st := newTestServer(t)

	csrPEM := makeCSRPEM(t, "test.example.com")
	body, _ := json.Marshal(submitCSRIn{
		Hostname: "test.example.com",
		B64CSR:   base64.StdEncoding.EncodeToString(csrPEM),
	})

	req := httptest.NewRequest("POST", "/submit-csr", bytes.NewReader(body))
	req = withForWhom(req, "alice")
	rec := httptest.NewRecorder()
	srv.handleSubmitCSR(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusAccepted, rec.Body.String())
	}

	var resp submitCSROut
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp.Hostname != "test.example.com" {
		t.Errorf("hostname = %q, want %q", resp.Hostname, "test.example.com")
	}
	if resp.SubmittedBy != "alice" {
		t.Errorf("submitted_by = %q, want %q", resp.SubmittedBy, "alice")
	}
	if resp.Status != "submitted" {
		t.Errorf("status = %q, want %q", resp.Status, "submitted")
	}

	// Check CSR was saved to disk
	csrPath := filepath.Join(srv.csrsDir, "alice", "test.example.com.csr")
	if _, err := os.Stat(csrPath); os.IsNotExist(err) {
		t.Errorf("CSR file not created at %s", csrPath)
	}

	// Check DB record
	cr, _ := st.GetLatestByHostname("test.example.com")
	if cr == nil {
		t.Fatal("expected DB record")
	}
	if cr.SubmittedBy != "alice" {
		t.Errorf("db submitted_by = %q", cr.SubmittedBy)
	}
}

func TestHandleSubmitCSR_InvalidBase64(t *testing.T) {
	srv, _ := newTestServer(t)

	body, _ := json.Marshal(submitCSRIn{
		Hostname: "test.example.com",
		B64CSR:   "not-valid-base64!!!",
	})

	req := httptest.NewRequest("POST", "/submit-csr", bytes.NewReader(body))
	req = withForWhom(req, "alice")
	rec := httptest.NewRecorder()
	srv.handleSubmitCSR(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestHandleSubmitCSR_InvalidCSR(t *testing.T) {
	srv, _ := newTestServer(t)

	body, _ := json.Marshal(submitCSRIn{
		Hostname: "test.example.com",
		B64CSR:   base64.StdEncoding.EncodeToString([]byte("not a real CSR")),
	})

	req := httptest.NewRequest("POST", "/submit-csr", bytes.NewReader(body))
	req = withForWhom(req, "alice")
	rec := httptest.NewRecorder()
	srv.handleSubmitCSR(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestHandleSubmitCSR_MissingHostname(t *testing.T) {
	srv, _ := newTestServer(t)

	csrPEM := makeCSRPEM(t, "test.example.com")
	body, _ := json.Marshal(submitCSRIn{
		B64CSR: base64.StdEncoding.EncodeToString(csrPEM),
	})

	req := httptest.NewRequest("POST", "/submit-csr", bytes.NewReader(body))
	req = withForWhom(req, "alice")
	rec := httptest.NewRecorder()
	srv.handleSubmitCSR(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestHandleGetStatus_Found(t *testing.T) {
	srv, st := newTestServer(t)

	st.InsertCertRequest(&store.CertRequest{
		Hostname:    "test.example.com",
		CSRPEM:      "fake",
		CSRPath:     "data/csrs/alice/test.example.com.csr",
		SubmittedBy: "alice",
		Status:      "submitted",
		CreatedAt:   "2026-03-18T10:00:00Z",
	})

	req := httptest.NewRequest("GET", "/status/test.example.com", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("hostname", "test.example.com")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rec := httptest.NewRecorder()
	srv.handleGetStatus(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var resp statusOut
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp.Hostname != "test.example.com" {
		t.Errorf("hostname = %q", resp.Hostname)
	}
	if resp.Status != "submitted" {
		t.Errorf("status = %q", resp.Status)
	}
	if resp.SubmittedBy != "alice" {
		t.Errorf("submitted_by = %q", resp.SubmittedBy)
	}
}

func TestHandleGetStatus_NotFound(t *testing.T) {
	srv, _ := newTestServer(t)

	req := httptest.NewRequest("GET", "/status/nonexistent.example.com", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("hostname", "nonexistent.example.com")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rec := httptest.NewRecorder()
	srv.handleGetStatus(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}
