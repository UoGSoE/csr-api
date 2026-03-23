package store

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

type CertRequest struct {
	ID          int64
	Hostname    string
	CSRPEM      string
	CSRPath     string
	SubmittedBy string
	Status      string
	ErrorMsg    *string
	CreatedAt   string
	CompletedAt *string
}

type AuthToken struct {
	ID          int64
	TokenHash   string
	TokenPrefix string
	ForWhom     string
	CreatedAt   string
	LastUsed    *string
	Revoked     bool
}

func New(dbPath string) (*Store, error) {
	db, err := sql.Open("sqlite", dbPath+"?_pragma=journal_mode(WAL)")
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping db: %w", err)
	}

	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}

	return &Store{db: db}, nil
}

func migrate(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS cert_requests (
			id           INTEGER PRIMARY KEY,
			hostname     TEXT NOT NULL,
			csr_pem      TEXT NOT NULL,
			csr_path     TEXT NOT NULL,
			submitted_by TEXT NOT NULL,
			status       TEXT NOT NULL DEFAULT 'submitted',
			error_msg    TEXT,
			created_at   TEXT NOT NULL,
			completed_at TEXT
		);

		CREATE TABLE IF NOT EXISTS auth_tokens (
			id           INTEGER PRIMARY KEY,
			token_hash   TEXT NOT NULL UNIQUE,
			token_prefix TEXT NOT NULL,
			for_whom     TEXT NOT NULL,
			created_at   TEXT NOT NULL,
			last_used    TEXT,
			revoked      INTEGER NOT NULL DEFAULT 0
		);
	`)
	return err
}

func (s *Store) Close() error {
	return s.db.Close()
}

// CertRequest methods

func (s *Store) InsertCertRequest(r *CertRequest) (int64, error) {
	res, err := s.db.Exec(
		`INSERT INTO cert_requests (hostname, csr_pem, csr_path, submitted_by, status, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		r.Hostname, r.CSRPEM, r.CSRPath, r.SubmittedBy, r.Status, r.CreatedAt,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) GetLatestByHostname(hostname string) (*CertRequest, error) {
	row := s.db.QueryRow(
		`SELECT id, hostname, csr_pem, csr_path, submitted_by, status, error_msg, created_at, completed_at
		 FROM cert_requests WHERE hostname = ? ORDER BY id DESC LIMIT 1`,
		hostname,
	)
	r := &CertRequest{}
	err := row.Scan(&r.ID, &r.Hostname, &r.CSRPEM, &r.CSRPath, &r.SubmittedBy, &r.Status, &r.ErrorMsg, &r.CreatedAt, &r.CompletedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return r, nil
}

func (s *Store) GetLatestByHostnameAndOwner(hostname, owner string) (*CertRequest, error) {
	row := s.db.QueryRow(
		`SELECT id, hostname, csr_pem, csr_path, submitted_by, status, error_msg, created_at, completed_at
		 FROM cert_requests WHERE hostname = ? AND submitted_by = ? ORDER BY id DESC LIMIT 1`,
		hostname, owner,
	)
	r := &CertRequest{}
	err := row.Scan(&r.ID, &r.Hostname, &r.CSRPEM, &r.CSRPath, &r.SubmittedBy, &r.Status, &r.ErrorMsg, &r.CreatedAt, &r.CompletedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return r, nil
}

func (s *Store) UpdateStatus(id int64, status string, errorMsg *string) error {
	_, err := s.db.Exec(
		`UPDATE cert_requests SET status = ?, error_msg = ? WHERE id = ?`,
		status, errorMsg, id,
	)
	return err
}

func (s *Store) MarkComplete(id int64) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.db.Exec(
		`UPDATE cert_requests SET status = 'complete', completed_at = ? WHERE id = ?`,
		now, id,
	)
	return err
}

// AuthToken methods

func (s *Store) InsertToken(t *AuthToken) error {
	_, err := s.db.Exec(
		`INSERT INTO auth_tokens (token_hash, token_prefix, for_whom, created_at)
		 VALUES (?, ?, ?, ?)`,
		t.TokenHash, t.TokenPrefix, t.ForWhom, t.CreatedAt,
	)
	return err
}

func (s *Store) GetTokenByHash(hash string) (*AuthToken, error) {
	row := s.db.QueryRow(
		`SELECT id, token_hash, token_prefix, for_whom, created_at, last_used, revoked
		 FROM auth_tokens WHERE token_hash = ?`,
		hash,
	)
	t := &AuthToken{}
	var revoked int
	err := row.Scan(&t.ID, &t.TokenHash, &t.TokenPrefix, &t.ForWhom, &t.CreatedAt, &t.LastUsed, &revoked)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	t.Revoked = revoked != 0
	return t, nil
}

func (s *Store) FindActiveTokensByPrefix(prefix string) ([]AuthToken, error) {
	rows, err := s.db.Query(
		`SELECT id, token_hash, token_prefix, for_whom, created_at, last_used, revoked
		 FROM auth_tokens WHERE token_prefix = ? AND revoked = 0`,
		prefix,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tokens []AuthToken
	for rows.Next() {
		var t AuthToken
		var revoked int
		if err := rows.Scan(&t.ID, &t.TokenHash, &t.TokenPrefix, &t.ForWhom, &t.CreatedAt, &t.LastUsed, &revoked); err != nil {
			return nil, err
		}
		t.Revoked = revoked != 0
		tokens = append(tokens, t)
	}
	return tokens, rows.Err()
}

func (s *Store) RevokeTokenByID(id int64) error {
	_, err := s.db.Exec(`UPDATE auth_tokens SET revoked = 1 WHERE id = ?`, id)
	return err
}

func (s *Store) ListTokens() ([]AuthToken, error) {
	rows, err := s.db.Query(
		`SELECT id, token_hash, token_prefix, for_whom, created_at, last_used, revoked
		 FROM auth_tokens ORDER BY id`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tokens []AuthToken
	for rows.Next() {
		var t AuthToken
		var revoked int
		if err := rows.Scan(&t.ID, &t.TokenHash, &t.TokenPrefix, &t.ForWhom, &t.CreatedAt, &t.LastUsed, &revoked); err != nil {
			return nil, err
		}
		t.Revoked = revoked != 0
		tokens = append(tokens, t)
	}
	return tokens, rows.Err()
}

func (s *Store) TouchTokenLastUsed(id int64) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.db.Exec(
		`UPDATE auth_tokens SET last_used = ? WHERE id = ?`,
		now, id,
	)
	return err
}
