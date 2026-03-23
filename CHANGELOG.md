# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-03-23
### Added
- Self-service CSR submission via `POST /submit-csr` with bearer token authentication
- Status tracking via `GET /status/{hostname}` returning submission state
- CSR validation (PEM format, requires CN or SANs)
- CSRs saved to disk organised by token owner for auditability
- SQLite-backed submission tracking with status lifecycle
- CLI token management: `create-token`, `revoke-token`, `list-tokens` subcommands
- Graceful server shutdown on SIGTERM/SIGINT

## [0.0.6] - 2026-03-23

## [0.0.5] - 2026-03-19

## [0.0.4] - 2026-03-19

## [0.0.3] - 2026-03-19

## [0.0.2] - 2026-03-18

## [0.0.1] - 2026-03-18

[Unreleased]: https://github.com/UoGSoE/csr-api/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/UoGSoE/csr-api/compare/v0.0.6...v1.0.0
[0.0.6]: https://github.com/UoGSoE/csr-api/compare/v0.0.5...v0.0.6
[0.0.5]: https://github.com/UoGSoE/csr-api/compare/v0.0.4...v0.0.5
[0.0.4]: https://github.com/UoGSoE/csr-api/compare/v0.0.3...v0.0.4
[0.0.3]: https://github.com/UoGSoE/csr-api/compare/v0.0.2...v0.0.3
[0.0.2]: https://github.com/UoGSoE/csr-api/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/UoGSoE/csr-api/releases/tag/v0.0.1
