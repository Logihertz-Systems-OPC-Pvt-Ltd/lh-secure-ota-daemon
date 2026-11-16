# Engineering & Technical Architecture Specification

**Specification ID**: `LH-SPEC-2026-046`  
**Repository**: `lh-secure-ota-daemon`  
**CLI Executable**: `lh-ota`  
**Standard Release Version**: `0.1.0`  
**Standard License**: `Apache-2.0`  
**Classification**: `Industrial Sovereign Cybersecurity & Critical Infrastructure Telemetry`

---

## Section 1: Document Control & Specification Metadata

| Metadata Attribute | Value |
| :--- | :--- |
| **Document Identification** | `LH-SPEC-2026-046` |
| **System Name** | `Logihertz Systems Sovereign Ecosystem` |
| **Target Component** | `lh-secure-ota-daemon` (`lh-ota`) |
| **Target Language / Platform** | `Go` |
| **Legal Entity** | Logihertz Systems (OPC) Private Limited |
| **Corporate Identity (CIN)** | `U72100MH2025OPC463857` |
| **GSTIN Registration** | `27AAGCL6394P1ZL` |
| **Principal Architect** | Sameer Tawade (`ops@logihertz.com` / `security@logihertz.com`) |
| **Headquarters & Registered Office** | Mumbai, Maharashtra, Republic of India |
| **Official Portal** | [https://www.logihertz.com](https://www.logihertz.com) |
| **Repository URL** | [https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-secure-ota-daemon](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-secure-ota-daemon) |
| **Document Status** | `APPROVED FOR PRODUCTION & INDUSTRIAL CERTIFICATION` |
| **Effective Release Date** | `2026-11-16` |

---

## Section 2: Normative RFC 2119 Requirements & System Invariants

This technical architecture specification enforces strict deterministic execution invariants in accordance with **RFC 2119** (`MUST`, `MUST NOT`, `REQUIRED`, `SHALL`, `SHALL NOT`, `SHOULD`, `RECOMMENDED`, `MAY`).

1. **Zero-Daemon Execution Invariant**:
   - The CLI binary `lh-ota` `MUST` execute as a clean, self-contained, stateless, zero-daemon process.
   - It `MUST NOT` spawn background daemons, fork unmonitored worker processes, or establish persistent Unix domain socket listeners unless explicitly invoked in daemon mode.
   - All state transitions `MUST` be deterministic, ephemeral, and strictly bounded by the execution lifecycle.

2. **Zero External Runtime Dependency Mandate**:
   - The software `MUST NOT` load, link, or depend upon third-party runtime package registries (e.g. PyPI, npm, Packagist, crates.io, Maven) at runtime.
   - For `Go`, all cryptographic, mathematical, serialization, and networking primitives `MUST` be implemented exclusively via language standard libraries or clean-room internal zero-dependency modules.

3. **Deterministic Air-Gapped Operation**:
   - The system `MUST` function with 100% feature parity in air-gapped, isolated, and offline enclaves.
   - The software `MUST NOT` initiate unsolicited network calls, telemetry telemetry pings, phone-home beacons, or external CDN queries.
   - All verification baselines, heuristics, and schemas `MUST` be packaged locally within the distribution.

4. **Constant-Time Cryptographic Comparison**:
   - All cryptographic comparison routines (hashes, HMAC tags, signatures, secret tokens, and commitments) `MUST` execute in constant time (`subtle.ConstantTimeCompare`, `CRYPTO_memcmp`, or equivalent).
   - The implementation `MUST NOT` short-circuit string comparisons when evaluating sensitive keys, thereby mitigating timing side-channel attacks.

5. **Memory Safety & Explicit Zeroization**:
   - All transient buffers containing sensitive key material, decrypted plaintexts, seeds, and cryptographic nonces `MUST` be explicitly overwritten with zeroes immediately following completion of the cryptographic operation.
   - For C/C++ implementations, bounds checks and safe buffer wrappers `MUST` prevent stack/heap overflows. For Rust implementations, `#![forbid(unsafe_code)]` `MUST` be enforced.

6. **Standardized Telemetry Interoperability**:
   - All security assessment outputs `MUST` support machine-readable ingestion via OASIS SARIF v2.1.0 JSON and Canonical Indented JSON schemas, alongside ANSI console tables.

---

## Section 3: Core Mathematical & Algorithmic Specification

### 3.1 Domain Engine Mathematical Foundation: Threshold Ed25519 Quorum & Monotonic SVN Anti-Rollback

The underlying computational core of `lh-secure-ota-daemon` is formally governed by the following mathematical and algorithmic formulations:

$$\sum_{i=1}^{N} \text{Verify}_{\text{Ed25519}}(\sigma_i, M, PK_i) \ge M, \quad \text{SVN}_{\text{new}} \ge \text{SVN}_{\text{current}}$$

### 3.2 Standardized Logihertz Security Posture Score Formulation

To achieve absolute cross-tool normalization across all 60 repositories in the Logihertz Systems Ecosystem, the security posture score $S_{\text{posture}}$ is evaluated on a standardized continuous integer scale $[0, 100]$:

$$S_{\text{posture}} = \max\left(0, \; 100 - \left(25 \cdot c_{\text{CRITICAL}} + 10 \cdot c_{\text{HIGH}} + 4 \cdot c_{\text{MEDIUM}} + 1 \cdot c_{\text{LOW}}\right)\right)$$

Where:
- $c_{\text{CRITICAL}}$ represents the total count of triggered Critical-severity normative rules (deduction: $-25$ per finding).
- $c_{\text{HIGH}}$ represents the total count of triggered High-severity normative rules (deduction: $-10$ per finding).
- $c_{\text{MEDIUM}}$ represents the total count of triggered Medium-severity normative rules (deduction: $-4$ per finding).
- $c_{\text{LOW}}$ represents the total count of triggered Low-severity normative rules (deduction: $-1$ per finding).

The final compliance verdict is strictly bifurcated:
$$\text{Verdict} = \begin{cases} \text{PASS} & \text{if } S_{\text{posture}} = 100 \land \sum c_i = 0 \\ \text{FAIL} & \text{otherwise} \end{cases}$$

---

## Section 4: Normative 10-Rule Detection Matrix

The detection engine evaluates configurations, manifests, firmware, protocols, and streams against the following 10 deterministic security rules:

| Rule ID | Severity | Weight | CWE ID | Trigger Predicate / Condition | Remediation Guideline |
| :--- | :--- | :---: | :---: | :--- | :--- |
| `LH-OTA-001` | `CRITICAL` | `25` | `CWE-347` | signature_verification_enabled == true && signature_algorithm == "Ed25519" | Enable bundle authentication and enforce RFC 8032 Ed25519. |
| `LH-OTA-002` | `CRITICAL` | `25` | `CWE-494` | dual_ab_partition_scheme == true && allow_active_slot_overwrite == false | Enforce atomic dual A/B partitioning; disallow active slot writes. |
| `LH-OTA-003` | `CRITICAL` | `25` | `CWE-319` | require_tls_1_3 == true && mtls_client_auth_enabled == true && !allow_insecure_http_fallback | Enforce TLS 1.3 with mTLS; forbid unencrypted HTTP fallback. |
| `LH-OTA-004` | `HIGH` | `10` | `CWE-693` | anti_rollback_svn_enforced == true && ratchet_svn_only_after_good_boot == true | Enforce monotonic SVN anti-rollback and defer ratchet to post-boot. |
| `LH-OTA-005` | `HIGH` | `10` | `CWE-755` | $1 \le \text{boot\_trial\_max\_attempts} \le 5$ && auto_rollback_on_healthcheck_fail == true | Configure watchdog boot-trial counter and enable automatic rollback. |
| `LH-OTA-006` | `HIGH` | `10` | `CWE-345` | min_signature_quorum >= 2 && enforce_manifest_expiration == true | Require at least 2 root signatures and enforce freeze-attack expiration. |
| `LH-OTA-007` | `HIGH` | `10` | `CWE-353` | verify_chunk_hashes_before_write == true && bind_dm_verity_roothash == true | Enable streaming 4 KiB chunk verification and dm-verity binding. |
| `LH-OTA-008` | `MEDIUM` | `4` | `CWE-20` | verify_hardware_compat_id == true | Enable cryptographic hardware compatibility ID validation. |
| `LH-OTA-009` | `MEDIUM` | `4` | `CWE-400` | $\text{max\_bundle\_size\_mb} \le 2048$ && $\text{min\_battery\_soc\_percent} \ge 30$ | Bound bundle memory size and gate updates on battery threshold. |
| `LH-OTA-010` | `LOW` | `1` | `CWE-778` | poll_jitter_enabled == true && signed_ota_audit_receipt == true | Enable randomized poll jitter and signed update audit receipts. |

---

## Section 5: CLI Contract, Exit Codes & OASIS SARIF v2.1.0 Specification

### 5.1 Command-Line Interface Syntax

The primary entrypoint `lh-ota` conforms to standard POSIX argument conventions:

```text
USAGE:
  lh-ota <command> [flags] [arguments]

CORE COMMANDS:
  scan <target> [--format table|json|sarif] [--output <file>]
      Execute deterministic security evaluation against target manifest or telemetry stream.
  verify <target>
      Validate operational parameters, cryptographic checksums, and structural invariants.
  --version, version
      Output release version, architecture, and legal attribution.
  --help, help
      Display comprehensive operational usage and command reference.
```

### 5.2 Deterministic Exit Code Protocol

| Exit Code | Classification | Operational Semantics |
| :---: | :--- | :--- |
| `0` | **SUCCESS / PASS** | Target passed all checks; zero Critical/High violations detected; $S_{\text{posture}} = 100$. |
| `1` | **FINDINGS / FAIL** | Target triggered one or more security rule violations; policy threshold breached. |
| `2` | **ERROR / USAGE** | Invalid CLI invocation, syntax error, missing input file, or fatal I/O failure. |

### 5.3 OASIS SARIF v2.1.0 Schema Compliance

Exported SARIF documents validate against the official OASIS schema (`sarif-schema-2.1.0.json`). Each result object maps:
- `ruleId`: Standardized identifier (`LH-OTA-001` .. `LH-OTA-010`).
- `level`: SARIF severity levels (`error` for Critical/High, `warning` for Medium, `note` for Low).
- `message.text`: Comprehensive explanation, CWE mapping, and actionable remediation steps.
- `locations[].physicalLocation.artifactLocation.uri`: Absolute or normalized relative path of target artifact.

---

## Section 6: Future Development Roadmap & Extension Architecture

### Milestone v0.2.0: Modular Extensions & Telemetry Streaming
- **Policy Pack Plugin Hooks**: Enable external declarative YAML/JSON rule-pack loading without source modification.
- **Hardware Telemetry Streaming**: Real-time integration with SPI, I2C, UART, CAN, and eBPF kernel event rings.
- **Configurable Severity Weights**: Support custom industrial profiles (e.g. Nuclear/Medical safety vs. Commercial IoT).

### Milestone v0.5.0: Native STRUCT OS Integration & Daemonless IPC
- **STRUCT OS Security Bus**: Native zero-copy shared memory integration with the STRUCT OS Security Command Center.
- **Automated Remediation Synthesis**: Direct IPC bridge with `lh-auto-remediation` for automatic synthesizing of verified unified diffs.
- **Hardware Root-of-Trust Attestation**: Cryptographic sealing of telemetry reports via TPM 2.0 PCR-bound quotes.

### Milestone v1.0.0: High-Assurance Certification & Hardening
- **FIPS 140-3 Validation**: Cryptographic module boundary verification and NIST CAVP compliance testing.
- **Common Criteria EAL4+ Alignment**: Formal verification of deterministic security targets and functional invariants.
- **Automotive & Industrial Compliance**: Formal baseline compliance with ISO 21434 (Automotive Cybersecurity) and IEC 62443 (Industrial Automation & Control Systems).
- **Signed Binary Attestation**: In-toto attestation and Cosign cryptographic signing across all release artifacts.

---

## Section 7: Verification, Quality Assurance & Legal Attribution

### 7.1 Automated Verification Protocol

Prior to distribution, all builds must execute the standardized Logihertz test suite:
- Unit and mathematical property tests verifying all equations and edge cases.
- Static analysis with zero warnings under standard strict linters.
- Subprocess CLI verification covering exit codes `0`, `1`, and `2`.

### 7.2 Copyright & Governance Notice

```text
Copyright 2025-2026 Logihertz Systems (OPC) Private Limited.
Creator, Founder, Director & Sole Developer: Sameer Tawade <ops@logihertz.com> / <security@logihertz.com>
Official Corporate Portal: https://www.logihertz.com
```

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this software except in compliance with the License. You may obtain a copy of the License at `http://www.apache.org/licenses/LICENSE-2.0`.
