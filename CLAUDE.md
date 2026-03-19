# CLAUDE.md

## What this is

Go HTTP API that automates Let's Encrypt certificate issuance via DNS-01 challenges. Single static binary, SQLite backend, bearer token auth for admin endpoints, public cert downloads.

## Stack

Go 1.22+, lego v4 (ACME), chi v5 (routing), kong (CLI), modernc.org/sqlite (pure-Go, no CGo).

## Layout

```
cmd/csr-api/main.go          # CLI entry point, kong subcommands, server wiring
internal/
  acme/client.go              # ObtainCert orchestrator, CertObtainer interface
  acme/provider.go            # Custom DNS-01 provider (channel-based)
  acme/account.go             # ECDSA P-256 key management
  auth/auth.go                # Token generation, SHA-256 hashing
  auth/middleware.go           # Bearer token chi middleware
  server/server.go            # Server struct, Config, http.Handler
  server/routes.go            # Chi router setup
  server/handlers.go          # All HTTP handlers
  store/store.go              # SQLite schema, all CRUD methods
```

## Key design decisions

- The ACME flow uses a Go channel to extract challenge data mid-flow from lego's blocking `ObtainForCSR()` call. Each request gets its own Provider instance.
- `POST /request-cert` and `GET /status/{hostname}` require bearer tokens (IT staff).
- `GET /cert/{hostname}/fullchain.crt` is deliberately public -- the people downloading certs (students, researchers) shouldn't need API credentials. Optional `--allowed-domain` flag restricts by hostname suffix.
- Certs are saved to disk as `{CertsDir}/{hostname}.pem` (full chain PEM from lego).

## Build and test

```bash
go build ./cmd/csr-api
go test ./...
go vet ./...
```

## Test patterns

stdlib `testing`, table-driven where appropriate, `:memory:` SQLite for store/auth tests, mock `CertObtainer` for handler tests. Handler tests use `newTestServer()` / `newTestServerWithOpts()` helpers.
