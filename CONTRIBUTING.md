# Contributing to lh-secure-ota-daemon

Thank you for your interest in contributing to `lh-secure-ota-daemon` (`lh-ota`). This repository is part of the Logihertz 60-Tool Open-Source Ecosystem, providing an atomic dual A/B partition OTA firmware updater, Ed25519 M-of-N multi-signature verifier, boot-trial watchdog state machine, and embedded OTA posture auditor.

## Core Architectural Mandates

1. **Zero External Runtime Dependencies**:
   `go.mod` must contain zero external `require` directives. All cryptography (`crypto/ed25519`, `crypto/sha256`, `crypto/subtle`, `crypto/rand`), JSON parsing, SARIF generation, and state machine logic must strictly utilize the Go 1.22+ standard library.
2. **Cryptographic Rigor**:
   All signature verification operations must use constant-time comparisons (`crypto/subtle`) where applicable, prevent signature malleability, reject duplicate signer key IDs, and enforce domain separation pre-images (`LH_OTA_BUNDLE_V1:`).
3. **Fail-Safe A/B Partitioning**:
   State transitions must never leave both partitions active or unbootable. The hardware anti-rollback Security Version Number (SVN) ratchet must strictly remain deferred until post-boot healthchecks succeed (`MarkBootSuccessful`).

## Development Workflow

### Prerequisites
- Go 1.22 or later
- Git

### Building from Source
```bash
git clone https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-secure-ota-daemon.git
cd lh-secure-ota-daemon
go build -v -ldflags="-s -w" -o bin/lh-ota ./cmd/lh-ota
```

### Running Tests and Linting
All pull requests must pass formatting, static analysis, and the race-detector test suite without any warnings:
```bash
# Check formatting
test -z "$(gofmt -s -l .)"

# Static analysis
go vet ./...

# Unit and integration test suite with data race detection
go test -v -race -cover ./...
```

## Pull Request Guidelines
- Ensure all new features or bug fixes include deterministic unit tests in `pkg/ota/ota_test.go`.
- Run `gofmt -s -w .` before committing changes.
- Maintain comprehensive documentation and inline comments explaining state machine transitions and cryptographic verification invariants.
- Adhere to the code of conduct and sign commits where appropriate.
