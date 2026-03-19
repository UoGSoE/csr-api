# csr-api

An HTTP API that automates ACME certificate issuance using DNS-01 challenges. You submit a CSR, the API hands back a TXT record to create, then polls DNS and finalises the certificate with Let's Encrypt once the record appears.

## What it does

You POST a hostname and a base64-encoded CSR. The API starts an ACME order against Let's Encrypt (or any ACME-compatible CA) and returns the DNS-01 challenge details. You create the TXT record in your own DNS. The API watches for the record and, once it propagates, completes the ACME flow and saves the issued certificate to disk.

Once a certificate is issued, anyone can download it from a public endpoint -- no token needed. The IT team (who hold the bearer tokens) handle the CSR submission, but the person actually setting up the web server might be a student or a research group who shouldn't need API credentials just to grab a cert. Certificates are public data anyway. If you'd rather limit which hostnames can be downloaded, there's an `--allowed-domain` flag that filters by suffix (e.g. `.ourplace.ac.uk`).

Authentication for certificate requests and status checks is via bearer tokens. Tokens are SHA-256 hashed before storage, so the raw token only appears once at creation time.

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

### Download a certificate

Once the status shows `issued`, grab the full chain -- no token needed:

```bash
curl http://localhost:8443/cert/app.example.com/fullchain.crt -o fullchain.crt
```

If the cert isn't ready yet you'll get the current status back instead.

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

## Example scripts

### Requesting a certificate

This script generates a private key and CSR with `openssl`, then submits it to the API. It prints the TXT record you need to create in DNS.

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

RESPONSE=$(curl -s -X POST "${API_URL}/request-cert" \
  -H "Authorization: Bearer ${API_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{\"hostname\": \"${HOSTNAME}\", \"b64_csr\": \"${B64_CSR}\"}")

echo "$RESPONSE" | python3 -m json.tool

# --- Show what to do next ---
TXT_NAME=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['txt_record_name'])")
TXT_VALUE=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['txt_record_value'])")

echo ""
echo "Create this DNS TXT record:"
echo "  ${TXT_NAME}  TXT  \"${TXT_VALUE}\""
echo ""
echo "Once the record is in place, the API will detect it and finalise the certificate."
echo "Run the download script to poll for completion and fetch the cert."
```

### Downloading the certificate

This script polls the status endpoint until the certificate is issued, then downloads it. Uncomment the block at the end to install it for nginx.

```bash
#!/usr/bin/env bash
set -euo pipefail

# --- Configuration ---
API_URL="https://csr-api.example.ac.uk"
API_TOKEN="your-bearer-token-here"
HOSTNAME="app.example.ac.uk"
POLL_INTERVAL=30   # seconds between checks
MAX_ATTEMPTS=120   # give up after this many attempts (~1 hour at 30s)

# --- Poll until issued ---
echo "Waiting for certificate to be issued for ${HOSTNAME}..."

for (( i=1; i<=MAX_ATTEMPTS; i++ )); do
  STATUS=$(curl -s "${API_URL}/status/${HOSTNAME}" \
    -H "Authorization: Bearer ${API_TOKEN}" \
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('status','unknown'))")

  case "$STATUS" in
    issued)
      echo "Certificate issued!"
      break
      ;;
    pending_dns)
      echo "  [${i}/${MAX_ATTEMPTS}] Status: ${STATUS} — waiting ${POLL_INTERVAL}s..."
      sleep "$POLL_INTERVAL"
      ;;
    failed|timed_out)
      echo "  Certificate request ${STATUS}. Check the API logs for details."
      exit 1
      ;;
    *)
      echo "  Unexpected status: ${STATUS}"
      exit 1
      ;;
  esac
done

if [ "$STATUS" != "issued" ]; then
  echo "Timed out waiting for certificate."
  exit 1
fi

# --- Download the full chain ---
curl -s "${API_URL}/cert/${HOSTNAME}/fullchain.crt" -o "${HOSTNAME}.fullchain.crt"
echo "Saved to ${HOSTNAME}.fullchain.crt"

# --- Optional: install for nginx ---
# sudo cp "${HOSTNAME}.fullchain.crt" /etc/ssl/certs/${HOSTNAME}.crt
# sudo cp "${HOSTNAME}.key" /etc/ssl/private/${HOSTNAME}.key
# sudo systemctl reload nginx
# echo "Installed and nginx reloaded."
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
| `--allowed-domain` | `CSR_API_ALLOWED_DOMAIN` | (none) | Only allow cert downloads for hostnames ending in this suffix |

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
