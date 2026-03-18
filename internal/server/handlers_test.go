package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/billyraycyrus/csr-api/internal/acme"
	"github.com/billyraycyrus/csr-api/internal/store"
	"github.com/go-chi/chi/v5"
)

type mockObtainer struct {
	challengeData *acme.ChallengeData
	err           error
}

func (m *mockObtainer) ObtainCert(_ context.Context, _ []byte, _ string) (*acme.ChallengeData, error) {
	return m.challengeData, m.err
}

func newTestServer(t *testing.T, obtainer acme.CertObtainer) (*Server, *store.Store) {
	t.Helper()
	st, err := store.New(":memory:")
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	srv := &Server{
		obtainer: obtainer,
		store:    st,
		logger:   slog.Default(),
	}
	return srv, st
}

func TestHandleRequestCert_Success(t *testing.T) {
	mock := &mockObtainer{
		challengeData: &acme.ChallengeData{
			FQDN:  "_acme-challenge.test.example.com.",
			Value: "abc123",
		},
	}
	srv, _ := newTestServer(t, mock)

	csrPEM := "-----BEGIN CERTIFICATE REQUEST-----\nfake\n-----END CERTIFICATE REQUEST-----"
	body, _ := json.Marshal(certRequestIn{
		Hostname: "test.example.com",
		B64CSR:   base64.StdEncoding.EncodeToString([]byte(csrPEM)),
	})

	req := httptest.NewRequest("POST", "/request-cert", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	srv.handleRequestCert(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var resp certRequestOut
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp.Hostname != "test.example.com" {
		t.Errorf("hostname = %q, want %q", resp.Hostname, "test.example.com")
	}
	if resp.TXTRecordName != "_acme-challenge.test.example.com." {
		t.Errorf("txt_record_name = %q", resp.TXTRecordName)
	}
	if resp.TXTRecordValue != "abc123" {
		t.Errorf("txt_record_value = %q", resp.TXTRecordValue)
	}
}

func TestHandleRequestCert_InvalidBase64(t *testing.T) {
	srv, _ := newTestServer(t, &mockObtainer{})

	body, _ := json.Marshal(certRequestIn{
		Hostname: "test.example.com",
		B64CSR:   "not-valid-base64!!!",
	})

	req := httptest.NewRequest("POST", "/request-cert", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	srv.handleRequestCert(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestHandleRequestCert_ObtainError(t *testing.T) {
	mock := &mockObtainer{
		err: context.DeadlineExceeded,
	}
	srv, _ := newTestServer(t, mock)

	csrPEM := "-----BEGIN CERTIFICATE REQUEST-----\nfake\n-----END CERTIFICATE REQUEST-----"
	body, _ := json.Marshal(certRequestIn{
		Hostname: "test.example.com",
		B64CSR:   base64.StdEncoding.EncodeToString([]byte(csrPEM)),
	})

	req := httptest.NewRequest("POST", "/request-cert", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	srv.handleRequestCert(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}

func TestHandleGetStatus_Found(t *testing.T) {
	srv, st := newTestServer(t, &mockObtainer{})

	st.InsertCertRequest(&store.CertRequest{
		Hostname:  "test.example.com",
		CSRPEM:    "fake",
		TXTFQDN:   "_acme-challenge.test.example.com.",
		TXTValue:  "abc123",
		Status:    "pending_dns",
		CreatedAt: "2026-03-18T10:00:00Z",
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
	if resp.Status != "pending_dns" {
		t.Errorf("status = %q", resp.Status)
	}
}

func TestHandleGetStatus_NotFound(t *testing.T) {
	srv, _ := newTestServer(t, &mockObtainer{})

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
