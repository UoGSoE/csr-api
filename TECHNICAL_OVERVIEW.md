# Technical overview

Last updated: 2026-03-19

## What this is

A self-service HTTP API for submitting Certificate Signing Requests (CSRs). Users submit a CSR via a bearer-token-authed endpoint. The API validates it, saves it to disk, and records the submission in SQLite. This removes the human bottleneck from the certificate request process -- no more chasing people on Teams or raising helpdesk tickets.

Certificate issuance and renewals are handled by central IT's existing tooling on `acme.cent.gla.ac.uk` (using `newcert`, `acme.sh`, and CNAME delegation to an `acme-dns` stub zone). This API is the self-service front door that feeds CSRs into that process.

## Stack

- Go 1.22+
- [chi v5](https://github.com/go-chi/chi) for HTTP routing
- [kong](https://github.com/alecthomas/kong) for CLI parsing
- [modernc.org/sqlite](https://pkg.go.dev/modernc.org/sqlite) for pure-Go SQLite (no CGo)

## Directory structure

```
cmd/csr-api/main.go        # CLI entry point, kong subcommands, serve wiring
internal/
  store/store.go            # SQLite schema, all CRUD methods
  auth/
    auth.go                 # Token generation (crypto/rand), SHA-256 hashing
    middleware.go           # Bearer token chi middleware, injects ForWhom into context
  server/
    server.go               # Server struct, http.Handler
    routes.go               # Chi router with auth middleware
    handlers.go             # POST /submit-csr, GET /status/{hostname}
```

## How it works

```
User generates CSR (openssl)
  |
  +-- POST /submit-csr with bearer token
  |     |
  |     +-- Validate CSR (real PEM, has CN or SANs)
  |     +-- Save to disk: {csrs-dir}/{token-owner}/{hostname}.csr
  |     +-- Record in SQLite (status: submitted)
  |     +-- Return 202 Accepted
  |
  +-- GET /status/{hostname} to check progress
```

The CSR is saved to disk organised by token owner (e.g. `data/csrs/alice/app.example.ac.uk.csr`), giving a clear audit trail of who requested what.

## Database schema

Two tables in SQLite with WAL mode enabled:

**cert_requests** tracks the lifecycle of each CSR submission:
- `hostname`, `csr_pem`, `csr_path`, `submitted_by`
- `status`: `submitted` -> `processing` -> `complete` | `failed`
- `error_msg`: populated on failure
- `created_at`, `completed_at`

**auth_tokens** stores bearer tokens:
- `token_hash` (SHA-256, unique), `token_prefix` (first 8 chars, for revocation lookup)
- `for_whom`: human-readable description (also used as the disk directory name)
- `revoked`: 0 or 1
- `last_used`: updated on each authenticated request

## API endpoints

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| POST | `/submit-csr` | Bearer token | Submit `{hostname, b64_csr}`, CSR saved to disk and recorded in DB |
| GET | `/status/{hostname}` | Bearer token | Check current submission state |

Both endpoints require bearer token auth. The middleware extracts the token's `for_whom` field and injects it into the request context, so the handler knows who submitted the CSR and can organise files accordingly.

## CLI subcommands

| Command | Purpose |
|---------|---------|
| `serve` | Start the API server |
| `create-token <for-whom>` | Generate a new bearer token, print it once |
| `revoke-token <prefix>` | Revoke by 8-char prefix |
| `list-tokens` | CSV dump of all tokens |

All commands share a `--db-path` flag (default `data/certs.db`, env `CSR_API_DB_PATH`).

## Authentication

Bearer tokens, hashed with SHA-256 before storage. The middleware (`internal/auth/middleware.go`) extracts the token from the `Authorization` header, hashes it, looks it up in the DB, checks the `revoked` flag, updates `last_used`, and injects `for_whom` into the request context.

No roles or permissions beyond "has a valid token".

## Testing

- Framework: `testing` (stdlib)
- Pattern: table-driven where appropriate, `:memory:` SQLite for store/auth tests, real CSR generation (`makeCSRPEM` helper) for handler tests
- Run: `go test ./...`

## Releases

GitHub Actions workflow (`.github/workflows/release.yml`) builds a matrix of 6 binaries on tag push (`v*`): linux/darwin/windows x amd64/arm64. Binaries are stripped (`-s -w`) and have the version baked in via ldflags.

## Local development

```bash
go build ./cmd/csr-api
./csr-api create-token "dev"
./csr-api serve
```

Data goes into `data/`. CSRs are saved under `data/csrs/`.
