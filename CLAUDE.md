# CLAUDE.md

## What this is

Go HTTP API for self-service CSR (Certificate Signing Request) submission. Users POST a CSR via bearer-token-authed endpoint, the API validates it, saves it to disk organised by token owner, and records the submission in SQLite. Designed to eliminate the human bottleneck of chasing someone on Teams or raising a helpdesk ticket to get a certificate issued.

Central IT's existing tooling (`newcert` on `acme.cent.gla.ac.uk`) handles actual certificate issuance and automatic renewals via CNAME delegation to their `acme-dns` stub zone. This app is the self-service front door that feeds into that process.

## Stack

Go 1.22+, chi v5 (routing), kong (CLI), modernc.org/sqlite (pure-Go, no CGo).

## Layout

```
cmd/csr-api/main.go          # CLI entry point, kong subcommands, server wiring
internal/
  auth/auth.go                # Token generation, SHA-256 hashing
  auth/middleware.go           # Bearer token chi middleware, puts ForWhom in context
  server/server.go            # Server struct, Config, http.Handler
  server/routes.go            # Chi router setup
  server/handlers.go          # POST /submit-csr, GET /status/{hostname}
  store/store.go              # SQLite schema, all CRUD methods
```

## Key design decisions

- `POST /submit-csr` validates the CSR (real PEM, has CN or SANs), saves to `{csrs-dir}/{token-owner}/{hostname}.csr`, records in DB.
- `GET /status/{hostname}` returns the current state of a submission (`submitted`, `processing`, `complete`, `failed`).
- Both endpoints require bearer token auth. The middleware puts the token's `for_whom` into the request context so the handler knows who submitted.
- CSRs are organised on disk by token owner for auditability.
- No ACME/Let's Encrypt code -- central IT handle issuance and renewals.

## Build and test

```bash
go build ./cmd/csr-api
go test ./...
go vet ./...
```

## Test patterns

stdlib `testing`, table-driven where appropriate, `:memory:` SQLite for store/auth tests. Handler tests generate real CSRs with `makeCSRPEM()` helper and use `newTestServer()`.
