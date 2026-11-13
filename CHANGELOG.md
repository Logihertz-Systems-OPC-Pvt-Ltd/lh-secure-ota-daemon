# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-13

### Added
- **RFC 8032 Ed25519 M-of-N Multi-Signature Verification**:
  - Implemented cryptographic bundle verification requiring $M$-of-$N$ valid signatures from authorized root-of-trust public keys.
  - Enforced domain-separated pre-image hashing (`LH_OTA_BUNDLE_V1:`) to prevent cross-protocol signature replay.
  - Pinned key ID tracking with duplicate-key rejection.
- **Streaming Integrity & Anti-Rollback Safeguards**:
  - Per-chunk streaming SHA-256 verification before flash write, bounding memory footprint during staging.
  - Full-image SHA-256 payload validation and dm-verity root hash binding support.
  - TUF-inspired anti-rollback check rejecting bundles with Security Version Numbers below the current device monotonic fuse (`SVN_bundle < SVN_current`).
  - Freeze-attack protection validating bundle expiration timestamps against authenticated device time (`T_now < T_expires`).
  - Hardware platform compatibility verification against target device hardware IDs.
- **Atomic Dual A/B Partition State Machine**:
  - Complete state management for `SLOT_A` and `SLOT_B` across states: `ACTIVE_GOOD`, `STANDBY_INACTIVE`, `STAGED_PENDING_BOOT`, `BOOT_TRIAL`, and `UNBOOTABLE_ROLLED_BACK`.
  - Configurable watchdog boot-trial attempt counter ($N_{\text{max\_tries}} = 3$).
  - Automatic fallback rollback to the active slot upon trial boot failure or healthcheck timeout.
  - Deferred anti-rollback SVN ratchet strictly executed post-boot upon verification of self-test healthchecks (`MarkBootSuccessful`).
- **10-Rule Embedded OTA Posture Auditor**:
  - Automated compliance scanner covering `LH-OTA-001` through `LH-OTA-010`.
  - Severity scoring ($S_{\text{posture}} = \max(0, 100 - \sum \text{Deductions})$) categorizing systems into `HARDENED`, `ACCEPTABLE`, `DEGRADED`, or `NON-COMPLIANT`.
  - Multi-format reporting supporting ANSI terminal tables, Canonical JSON, and OASIS SARIF v2.1.0 schemas.
- **Production CLI Tooling (`lh-ota`)**:
  - `scan`: Evaluates OTA configuration and security posture against the 10 audit rules.
  - `keygen`: Generates RFC 8032 Ed25519 signing key pairs with hexadecimal encoding.
  - `sign-bundle`: Creates canonical domain-separated multi-signature bundle manifests.
  - `verify-bundle`: Cryptographically validates bundle signatures, chunk hashes, SVN, and expiration.
  - `simulate-ab`: Simulates the complete dual A/B update, staging, boot-trial, and rollback lifecycle.
- **Zero External Dependencies**:
  - Built exclusively using the Go 1.22+ standard library (`crypto/ed25519`, `crypto/sha256`, `crypto/subtle`, etc.) with zero external Go module requirements.
