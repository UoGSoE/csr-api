# csr-api

A self-service HTTP API for submitting Certificate Signing Requests. You POST a CSR, the API validates it, saves it to disk, and records the submission. No more chasing someone on Teams or raising a helpdesk ticket to get a certificate.

## What it does

You POST a hostname and a base64-encoded CSR. The API validates the CSR (checks it's valid PEM with a CN or SANs), saves it to disk organised by token owner, and records the submission in SQLite. The actual certificate issuance is handled downstream by central IT's existing tooling.

Authentication is via bearer tokens. Tokens are SHA-256 hashed before storage, so the raw token only appears once at creation time. The token's owner label is used to organise CSRs on disk -- each owner gets their own directory.

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
./csr-api create-token "alice"
```

This prints the raw token (save it, you won't see it again) and an 8-character prefix you can use to revoke it later.

Start the server:

```bash
./csr-api serve
```

By default this listens on `:8443`. CSRs are saved to `data/csrs/`.

## Usage

### Submit a CSR

```bash
curl -X POST http://localhost:8443/submit-csr \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"hostname": "app.example.ac.uk", "b64_csr": "<base64-encoded PEM CSR>"}'
```

The response confirms the submission:

```json
{
  "hostname": "app.example.ac.uk",
  "submitted_by": "alice",
  "status": "submitted",
  "message": "CSR received and saved. It will be processed shortly."
}
```

The CSR is saved to disk at `data/csrs/alice/app.example.ac.uk.csr`.

### Check status

```bash
curl http://localhost:8443/status/app.example.ac.uk \
  -H "Authorization: Bearer <token>"
```

Returns the current state of the submission (`submitted`, `processing`, `complete`, or `failed`).

### Token management

```bash
./csr-api create-token "alice"       # generate a new token
./csr-api list-tokens                # show all tokens as CSV
./csr-api revoke-token <prefix>      # revoke by 8-char prefix
```

## Example script

This script generates a private key and CSR with `openssl`, then submits it to the API.

```bash
#!/usr/bin/env bash
set -euo pipefail

# --- Configuration ---
API_URL="https://csr-api.example.ac.uk"
API_TOKEN="your-bearer-token-here"
HOSTNAME="app.example.ac.uk"
KEY_FILE="${HOSTNAME}.key"
CSR_FILE="${HOSTNAME}.csr"

# --- Generate a private key and CSR ---
openssl ecparam -genkey -name prime256v1 -noout -out "$KEY_FILE"
openssl req -new -key "$KEY_FILE" -out "$CSR_FILE" -subj "/CN=${HOSTNAME}"

echo "Generated key: ${KEY_FILE}"
echo "Generated CSR: ${CSR_FILE}"

# --- Base64-encode the CSR and submit ---
# -w0 avoids line wrapping (Linux). On macOS, base64 doesn't wrap by default.
B64_CSR=$(base64 -w0 < "$CSR_FILE" 2>/dev/null || base64 < "$CSR_FILE" | tr -d '\n')

RESPONSE=$(curl -s -X POST "${API_URL}/submit-csr" \
  -H "Authorization: Bearer ${API_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{\"hostname\": \"${HOSTNAME}\", \"b64_csr\": \"${B64_CSR}\"}")

echo "$RESPONSE" | python3 -m json.tool

echo ""
echo "CSR submitted. Check status with:"
echo "  curl ${API_URL}/status/${HOSTNAME} -H 'Authorization: Bearer ${API_TOKEN}'"
```

## Configuration

| Flag | Env var | Default | Description |
|------|---------|---------|-------------|
| `--addr` | `CSR_API_ADDR` | `:8443` | Listen address |
| `--csrs-dir` | `CSR_API_CSRS_DIR` | `data/csrs` | Where submitted CSRs are saved |
| `--db-path` | `CSR_API_DB_PATH` | `data/certs.db` | SQLite database path |

## Logging

The API uses Go's structured logging (slog). Every log line is machine-parseable with `level`, `msg`, and contextual fields. The three levels mean:

- **INFO** -- normal operations (startup, CSR submissions, shutdown)
- **WARN** -- expected but notable events (rejected auth, minor failures)
- **ERROR** -- something is actually broken (DB errors, file write failures)

Example output:

```
time=2026-03-19T20:00:00.000Z level=INFO  msg="starting server" addr=:8443
time=2026-03-19T20:01:30.000Z level=INFO  msg="csr submitted" hostname=app.example.ac.uk submitted_by=alice path=data/csrs/alice/app.example.ac.uk.csr
time=2026-03-19T20:02:00.000Z level=WARN  msg="auth rejected" prefix=8a5a0868
time=2026-03-19T20:05:00.000Z level=INFO  msg="shutting down..."
```

If you're feeding logs into a central system, grep for `level=ERROR` to catch things that need attention. `level=WARN` with `msg="auth rejected"` is worth monitoring if you want to spot brute-force attempts -- the `prefix` field identifies which token was tried without leaking the secret.

## Running tests

```bash
go test ./...
```

## Releases

Pre-built binaries for Linux, macOS, and Windows (amd64 and arm64) get published when you push a version tag:

```bash
git tag v0.2.0
git push origin v0.2.0
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
