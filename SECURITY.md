# Security Policy: lh-secure-ota-daemon

## Threat Model & Embedded OTA Firmware Guarantees

`lh-secure-ota-daemon` enforces cryptographically authenticated Over-The-Air firmware updates for embedded edge appliances and autonomous robotics.

The security architecture mitigates the following threat classes:
1. **Malicious / Forged Firmware Updates**: Enforces RFC 8032 Ed25519 M-of-N multi-signature threshold verification across pinned hardware root-of-trust signing keys before any data is staged.
2. **Rollback & Downgrade Attacks**: Rejects bundles with Security Version Numbers (`SVN`) lower than the hardware monotonic fuse ratchet (`SVN_bundle < SVN_current`).
3. **Freeze Attacks**: Enforces TUF-inspired manifest expiration timestamps (`T_now >= T_expires`).
4. **Transport Tampering & Incomplete Downloads**: Enforces per-chunk SHA-256 streaming verification and full-image SHA-256 validation.
5. **Bricking on Failed Update**: Implements an atomic dual A/B partition state machine (`SLOT_A` and `SLOT_B`) with a hardware watchdog boot-trial attempt counter and automatic fallback to the known-good partition if healthchecks fail. The permanent hardware `SVN` fuse is ratcheted only after a successful post-boot self-test.

## Reporting a Vulnerability

Please report security issues or bypass discoveries to `security@logihertz.com` with a copy to `ops@logihertz.com`. We coordinate disclosure and issue patches promptly.
