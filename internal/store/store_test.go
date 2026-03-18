package store

import (
	"testing"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := New(":memory:")
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestInsertAndGetCertRequest(t *testing.T) {
	s := newTestStore(t)

	id, err := s.InsertCertRequest(&CertRequest{
		Hostname:  "test.example.com",
		CSRPEM:    "-----BEGIN CERTIFICATE REQUEST-----\nfake\n-----END CERTIFICATE REQUEST-----",
		TXTFQDN:   "_acme-challenge.test.example.com.",
		TXTValue:  "abc123",
		Status:    "pending_dns",
		CreatedAt: "2026-03-18T10:00:00Z",
	})
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	if id < 1 {
		t.Fatalf("expected positive id, got %d", id)
	}

	got, err := s.GetLatestByHostname("test.example.com")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got == nil {
		t.Fatal("expected record, got nil")
	}
	if got.Hostname != "test.example.com" {
		t.Errorf("hostname = %q, want %q", got.Hostname, "test.example.com")
	}
	if got.TXTValue != "abc123" {
		t.Errorf("txt_value = %q, want %q", got.TXTValue, "abc123")
	}
	if got.Status != "pending_dns" {
		t.Errorf("status = %q, want %q", got.Status, "pending_dns")
	}
}

func TestUpdateStatus(t *testing.T) {
	s := newTestStore(t)

	id, _ := s.InsertCertRequest(&CertRequest{
		Hostname:  "test.example.com",
		CSRPEM:    "fake",
		TXTFQDN:   "_acme-challenge.test.example.com.",
		TXTValue:  "abc123",
		Status:    "pending_dns",
		CreatedAt: "2026-03-18T10:00:00Z",
	})

	errMsg := "something went wrong"
	if err := s.UpdateStatus(id, "failed", &errMsg); err != nil {
		t.Fatalf("update: %v", err)
	}

	got, _ := s.GetLatestByHostname("test.example.com")
	if got.Status != "failed" {
		t.Errorf("status = %q, want %q", got.Status, "failed")
	}
	if got.ErrorMsg == nil || *got.ErrorMsg != errMsg {
		t.Errorf("error_msg = %v, want %q", got.ErrorMsg, errMsg)
	}
}

func TestUpdateChallengeData(t *testing.T) {
	s := newTestStore(t)

	id, _ := s.InsertCertRequest(&CertRequest{
		Hostname:  "test.example.com",
		CSRPEM:    "fake",
		TXTFQDN:   "",
		TXTValue:  "",
		Status:    "pending_dns",
		CreatedAt: "2026-03-18T10:00:00Z",
	})

	if err := s.UpdateChallengeData(id, "_acme-challenge.test.example.com.", "xyz789"); err != nil {
		t.Fatalf("update challenge data: %v", err)
	}

	got, _ := s.GetLatestByHostname("test.example.com")
	if got.TXTFQDN != "_acme-challenge.test.example.com." {
		t.Errorf("txt_fqdn = %q, want %q", got.TXTFQDN, "_acme-challenge.test.example.com.")
	}
	if got.TXTValue != "xyz789" {
		t.Errorf("txt_value = %q, want %q", got.TXTValue, "xyz789")
	}
}

func TestMarkCompleted(t *testing.T) {
	s := newTestStore(t)

	id, _ := s.InsertCertRequest(&CertRequest{
		Hostname:  "test.example.com",
		CSRPEM:    "fake",
		TXTFQDN:   "_acme-challenge.test.example.com.",
		TXTValue:  "abc123",
		Status:    "pending_dns",
		CreatedAt: "2026-03-18T10:00:00Z",
	})

	if err := s.MarkCompleted(id); err != nil {
		t.Fatalf("mark completed: %v", err)
	}

	got, _ := s.GetLatestByHostname("test.example.com")
	if got.Status != "issued" {
		t.Errorf("status = %q, want %q", got.Status, "issued")
	}
	if got.CompletedAt == nil {
		t.Error("completed_at should not be nil")
	}
}

func TestGetLatestByHostname_NotFound(t *testing.T) {
	s := newTestStore(t)

	got, err := s.GetLatestByHostname("nonexistent.example.com")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil, got %v", got)
	}
}

func TestInsertAndGetToken(t *testing.T) {
	s := newTestStore(t)

	err := s.InsertToken(&AuthToken{
		TokenHash:   "abc123hash",
		TokenPrefix: "abc12345",
		ForWhom:     "test-user",
		CreatedAt:   "2026-03-18T10:00:00Z",
	})
	if err != nil {
		t.Fatalf("insert: %v", err)
	}

	got, err := s.GetTokenByHash("abc123hash")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got == nil {
		t.Fatal("expected token, got nil")
	}
	if got.ForWhom != "test-user" {
		t.Errorf("for_whom = %q, want %q", got.ForWhom, "test-user")
	}
	if got.Revoked {
		t.Error("expected not revoked")
	}
}

func TestRevokeTokenByPrefix(t *testing.T) {
	s := newTestStore(t)

	s.InsertToken(&AuthToken{
		TokenHash:   "abc123hash",
		TokenPrefix: "abc12345",
		ForWhom:     "test-user",
		CreatedAt:   "2026-03-18T10:00:00Z",
	})

	found, err := s.RevokeTokenByPrefix("abc12345")
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if !found {
		t.Error("expected found=true")
	}

	got, _ := s.GetTokenByHash("abc123hash")
	if !got.Revoked {
		t.Error("expected revoked=true")
	}
}

func TestRevokeTokenByPrefix_NotFound(t *testing.T) {
	s := newTestStore(t)

	found, err := s.RevokeTokenByPrefix("nonexist")
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if found {
		t.Error("expected found=false")
	}
}

func TestTouchTokenLastUsed(t *testing.T) {
	s := newTestStore(t)

	s.InsertToken(&AuthToken{
		TokenHash:   "abc123hash",
		TokenPrefix: "abc12345",
		ForWhom:     "test-user",
		CreatedAt:   "2026-03-18T10:00:00Z",
	})

	got, _ := s.GetTokenByHash("abc123hash")
	if got.LastUsed != nil {
		t.Error("expected last_used to be nil initially")
	}

	if err := s.TouchTokenLastUsed(got.ID); err != nil {
		t.Fatalf("touch: %v", err)
	}

	got, _ = s.GetTokenByHash("abc123hash")
	if got.LastUsed == nil {
		t.Error("expected last_used to be set")
	}
}
