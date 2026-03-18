# csr-api

An HTTP API that automates ACME certificate issuance using DNS-01 challenges. You submit a CSR, the API hands back a TXT record to create, then polls DNS and finalises the certificate with Let's Encrypt once the record appears.

## What it does

You POST a hostname and a base64-encoded CSR. The API starts an ACME order against Let's Encrypt (or any ACME-compatible CA) and returns the DNS-01 challenge details. You create the TXT record in your own DNS. The API watches for the record and, once it propagates, completes the ACME flow and saves the issued certificate to disk.

Authentication is via bearer tokens. Tokens are SHA-256 hashed before storage, so the raw token only appears once at creation time.

Compiles to a single static binary with an embedded SQLite database -- nothing else to install or run.

## Prerequisites

- Go 1.22 or later

## Getting started

Clone the repo and build:

```bash
git clone git@github.com:UoGSoE/csr-api.git
cd csr-api
go build ./cmd/csr-api
```

Create a token for API access:

```bash
./csr-api create-token "my-service"
```

This prints the raw token (save it, you won't see it again) and an 8-character prefix you can use to revoke it later.

Start the server:

```bash
./csr-api serve --acme-email certs@example.com
```

By default this listens on `:8443` and uses the Let's Encrypt staging directory. For production, pass the production URL:

```bash
./csr-api serve \
  --acme-email certs@example.com \
  --acme-directory https://acme-v02.api.letsencrypt.org/directory
```

All flags have environment variable equivalents prefixed with `CSR_API_`, e.g. `CSR_API_ADDR`, `CSR_API_ACME_EMAIL`.

## Usage

### Request a certificate

```bash
curl -X POST http://localhost:8443/request-cert \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"hostname": "app.example.com", "b64_csr": "<base64-encoded PEM CSR>"}'
```

The response includes the TXT record to create:

```json
{
  "hostname": "app.example.com",
  "txt_record_name": "_acme-challenge.app.example.com.",
  "txt_record_value": "abc123...",
  "message": "Create this TXT record in DNS. We will poll and finalise automatically."
}
```

### Check status

```bash
curl http://localhost:8443/status/app.example.com \
  -H "Authorization: Bearer <token>"
```

Returns the current state of the request (`pending_dns`, `issued`, `failed`, or `timed_out`).

### Token management

```bash
./csr-api create-token "alice"       # generate a new token
./csr-api list-tokens                # show all tokens as CSV
./csr-api revoke-token <prefix>      # revoke by 8-char prefix
```

## Configuration

| Flag | Env var | Default | Description |
|------|---------|---------|-------------|
| `--addr` | `CSR_API_ADDR` | `:8443` | Listen address |
| `--acme-directory` | `CSR_API_ACME_DIRECTORY` | LE staging URL | ACME directory URL |
| `--acme-email` | `CSR_API_ACME_EMAIL` | (required) | ACME account email |
| `--certs-dir` | `CSR_API_CERTS_DIR` | `data/certs` | Where issued certs are saved |
| `--db-path` | `CSR_API_DB_PATH` | `data/certs.db` | SQLite database path |
| `--dns-servers` | `CSR_API_DNS_SERVERS` | system resolvers | DNS servers for propagation checks |
| `--poll-timeout` | `CSR_API_POLL_TIMEOUT` | `2h` | Give up after this long |
| `--poll-interval` | `CSR_API_POLL_INTERVAL` | `2m` | Time between DNS checks |

## Logging

The API uses Go's structured logging (slog). Every log line is machine-parseable with `level`, `msg`, and contextual fields. The three levels mean:

- **INFO** -- normal operations (startup, certs issued, shutdown)
- **WARN** -- expected but notable events (rejected auth, minor failures)
- **ERROR** -- something is actually broken (ACME failures, DB errors)

Example output:

```
time=2026-03-18T20:00:00.000Z level=INFO  msg="starting server" addr=:8443
time=2026-03-18T20:01:30.000Z level=INFO  msg="cert issued" hostname=app.example.com path=data/certs/app.example.com.pem
time=2026-03-18T20:02:00.000Z level=WARN  msg="auth rejected" prefix=8a5a0868
time=2026-03-18T20:03:00.000Z level=ERROR msg="obtain cert failed" hostname=app.example.com err="acme: error 400 - urn:ietf:params:acme:error:rejectedIdentifier"
time=2026-03-18T20:05:00.000Z level=INFO  msg="shutting down..."
```

If you're feeding logs into a central system, grep for `level=ERROR` to catch things that need attention. `level=WARN` with `msg="auth rejected"` is worth monitoring if you want to spot brute-force attempts -- the `prefix` field identifies which token was tried without leaking the secret.

## Running tests

```bash
go test ./...
```

## Releases

Pre-built binaries for Linux, macOS, and Windows (amd64 and arm64) get published when you push a version tag:

```bash
git tag v0.1.0
git push origin v0.1.0
```

Binaries and SHA-256 checksums get attached to the GitHub release.

## Contributing

Fork the repo and clone it:

```bash
git clone git@github.com:<you>/csr-api.git
cd csr-api
go mod download
```

Make your changes, run `go test ./...` and `go vet ./...`, then open a pull request.

## Licence

MIT. See [LICENSE](LICENSE) for details.
