# Technical overview

Last updated: 2026-03-18

## What this is

An HTTP API that automates Let's Encrypt certificate issuance via DNS-01 challenges, with bearer token auth and a SQLite backend.

## Stack

- Go 1.22+
- [lego v4](https://github.com/go-acme/lego) for the ACME protocol
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
    middleware.go           # Bearer token chi middleware
  acme/
    provider.go             # Custom DNS-01 provider (channel-based)
    account.go              # ECDSA P-256 key management, registration.User impl
    client.go               # ObtainCert orchestrator, CertObtainer interface
  server/
    server.go               # Server struct, http.Handler
    routes.go               # Chi router with auth middleware
    handlers.go             # POST /request-cert, GET /status/{hostname}
```

## How the ACME flow works

This is the non-obvious part. Lego's `ObtainForCSR()` is a blocking call that handles the entire ACME lifecycle internally. The trick is a custom DNS-01 provider that uses a Go channel to extract the challenge data mid-flow:

```
HTTP handler
  |
  +-- creates per-request Provider (buffered chan, size 1)
  +-- starts goroutine: lego.ObtainForCSR()
  |       |
  |       +-- lego calls Provider.Present()
  |       |       |
  |       |       +-- sends ChallengeData on channel
  |       |
  |   <-- reads from channel (30s timeout)
  |   returns TXT details to caller
  |
  |       +-- lego polls DNS for propagation
  |       +-- lego finalises with CA
  |       +-- goroutine saves cert, updates DB
```

Each request gets its own Provider instance. No shared mutable state between requests.

## Database schema

Two tables in SQLite with WAL mode enabled:

**cert_requests** tracks the lifecycle of each certificate order:
- `hostname`, `csr_pem`, `txt_fqdn`, `txt_value`
- `status`: `pending_dns` -> `issued` | `failed` | `timed_out`
- `error_msg`: populated on failure
- `created_at`, `completed_at`

**auth_tokens** stores bearer tokens:
- `token_hash` (SHA-256, unique), `token_prefix` (first 8 chars, for revocation lookup)
- `for_whom`: human-readable description
- `revoked`: 0 or 1
- `last_used`: updated on each authenticated request

## API endpoints

Both require `Authorization: Bearer <token>`.

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/request-cert` | Submit `{hostname, b64_csr}`, get back TXT record details |
| GET | `/status/{hostname}` | Poll for current request state |

## CLI subcommands

| Command | Purpose |
|---------|---------|
| `serve --acme-email <email>` | Start the API server |
| `create-token <for-whom>` | Generate a new bearer token, print it once |
| `revoke-token <prefix>` | Revoke by 8-char prefix |
| `list-tokens` | CSV dump of all tokens |

All commands share a `--db-path` flag (default `data/certs.db`, env `CSR_API_DB_PATH`).

## Interfaces

`CertObtainer` in `internal/acme/client.go` is the main seam for testing:

```go
type CertObtainer interface {
    ObtainCert(ctx context.Context, csrPEM []byte, hostname string) (*ChallengeData, error)
}
```

The server package depends on this interface, not the concrete `Client`. Handler tests use a `mockObtainer`.

## Authentication

Bearer tokens, hashed with SHA-256 before storage. The middleware (`internal/auth/middleware.go`) extracts the token from the `Authorization` header, hashes it, looks it up in the DB, checks the `revoked` flag, and updates `last_used`.

No roles or permissions beyond "has a valid token".

## Testing

- Framework: `testing` (stdlib)
- Pattern: table-driven where appropriate, `:memory:` SQLite for store/auth tests, mock `CertObtainer` for handler tests
- Run: `go test ./...`

## Releases

GitHub Actions workflow (`.github/workflows/release.yml`) builds a matrix of 6 binaries on tag push (`v*`): linux/darwin/windows x amd64/arm64. Binaries are stripped (`-s -w`) and have the version baked in via ldflags.

## Local development

```bash
go build ./cmd/csr-api
./csr-api create-token "dev"
./csr-api serve --acme-email test@example.com
```

The default ACME directory is Let's Encrypt staging. Data goes into `data/`.
