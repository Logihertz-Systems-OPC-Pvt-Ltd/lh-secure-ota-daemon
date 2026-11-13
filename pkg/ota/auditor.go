package ota

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// RuleSeverity represents the risk level of an auditor finding
type RuleSeverity string

const (
	SeverityCritical RuleSeverity = "CRITICAL"
	SeverityHigh     RuleSeverity = "HIGH"
	SeverityMedium   RuleSeverity = "MEDIUM"
	SeverityLow      RuleSeverity = "LOW"
)

// PostureStatus classifies the overall security health of the OTA policy
type PostureStatus string

const (
	StatusHardened     PostureStatus = "HARDENED"
	StatusAcceptable   PostureStatus = "ACCEPTABLE"
	StatusDegraded     PostureStatus = "DEGRADED"
	StatusNonCompliant PostureStatus = "NON-COMPLIANT"
)

// OTAPostureConfig defines the security parameters of an embedded OTA subsystem
type OTAPostureConfig struct {
	SignatureVerificationEnabled  bool   `json:"signature_verification_enabled"`
	SignatureAlgorithm            string `json:"signature_algorithm"`
	DualABPartitionScheme         bool   `json:"dual_ab_partition_scheme"`
	AllowActiveSlotOverwrite      bool   `json:"allow_active_slot_overwrite"`
	RequireTLS13                  bool   `json:"require_tls_1_3"`
	MTLSClientAuthEnabled         bool   `json:"mtls_client_auth_enabled"`
	AllowInsecureHTTPFallback     bool   `json:"allow_insecure_http_fallback"`
	AntiRollbackSVNEnforced       bool   `json:"anti_rollback_svn_enforced"`
	RatchetSVNOnlyAfterGoodBoot   bool   `json:"ratchet_svn_only_after_good_boot"`
	BootTrialMaxAttempts          int    `json:"boot_trial_max_attempts"`
	AutoRollbackOnHealthcheckFail bool   `json:"auto_rollback_on_healthcheck_fail"`
	MinSignatureQuorum            int    `json:"min_signature_quorum"`
	EnforceManifestExpiration     bool   `json:"enforce_manifest_expiration"`
	VerifyChunkHashesBeforeWrite  bool   `json:"verify_chunk_hashes_before_write"`
	BindDmVerityRootHash          bool   `json:"bind_dm_verity_roothash"`
	VerifyHardwareCompatID        bool   `json:"verify_hardware_compat_id"`
	MaxBundleSizeMB               int    `json:"max_bundle_size_mb"`
	MinBatterySoCPercent          int    `json:"min_battery_soc_percent"`
	PollJitterEnabled             bool   `json:"poll_jitter_enabled"`
	SignedOTAAuditReceipt         bool   `json:"signed_ota_audit_receipt"`
}

// AuditFinding documents an evaluation outcome for a specific rule
type AuditFinding struct {
	RuleID      string       `json:"rule_id"`
	Title       string       `json:"title"`
	Severity    RuleSeverity `json:"severity"`
	Deduction   int          `json:"deduction"`
	CWENumber   string       `json:"cwe_number"`
	Passed      bool         `json:"passed"`
	Description string       `json:"description"`
	Remediation string       `json:"remediation"`
}

// AuditReport summarizes the complete evaluation of the 10-rule posture
type AuditReport struct {
	TimestampUTC    string           `json:"timestamp_utc"`
	Score           int              `json:"score"`
	Status          PostureStatus    `json:"status"`
	TotalRules      int              `json:"total_rules"`
	PassedRules     int              `json:"passed_rules"`
	FailedRules     int              `json:"failed_rules"`
	Findings        []AuditFinding   `json:"findings"`
	PolicyEvaluated OTAPostureConfig `json:"policy_evaluated"`
}

// AuditRule defines the specification and evaluation function for a single rule
type AuditRule struct {
	ID          string
	Title       string
	Severity    RuleSeverity
	Deduction   int
	CWENumber   string
	Description string
	Remediation string
	Evaluate    func(cfg *OTAPostureConfig) (bool, string)
}

// GetStandardAuditRules returns the canonical 10-rule OTA posture checklist
func GetStandardAuditRules() []AuditRule {
	return []AuditRule{
		{
			ID:          "LH-OTA-001",
			Title:       "Ed25519 Cryptographic Bundle Authentication",
			Severity:    SeverityCritical,
			Deduction:   25,
			CWENumber:   "CWE-347",
			Description: "Firmware bundle manifest verification must be enforced using modern RFC 8032 Ed25519 signatures.",
			Remediation: "Set signature_verification_enabled: true and signature_algorithm: \"Ed25519\".",
			Evaluate: func(cfg *OTAPostureConfig) (bool, string) {
				if !cfg.SignatureVerificationEnabled {
					return false, "Firmware signature verification is disabled."
				}
				if cfg.SignatureAlgorithm != "Ed25519" {
					return false, fmt.Sprintf("Weak or insecure signature algorithm: %q (expected Ed25519).", cfg.SignatureAlgorithm)
				}
				return true, "Ed25519 bundle authentication enforced."
			},
		},
		{
			ID:          "LH-OTA-002",
			Title:       "Atomic Dual A/B Partition Isolation",
			Severity:    SeverityCritical,
			Deduction:   25,
			CWENumber:   "CWE-494",
			Description: "Firmware flashing must target an inactive standby slot in a dual A/B scheme, preventing in-place active slot corruption.",
			Remediation: "Set dual_ab_partition_scheme: true and allow_active_slot_overwrite: false.",
			Evaluate: func(cfg *OTAPostureConfig) (bool, string) {
				if !cfg.DualABPartitionScheme {
					return false, "Dual A/B partitioning scheme is disabled; system is vulnerable to bricking."
				}
				if cfg.AllowActiveSlotOverwrite {
					return false, "Active slot overwrite is permitted, risking bricking during live execution."
				}
				return true, "Atomic dual A/B partition isolation enforced."
			},
		},
		{
			ID:          "LH-OTA-003",
			Title:       "Mutual TLS 1.3 Transport Encryption",
			Severity:    SeverityCritical,
			Deduction:   25,
			CWENumber:   "CWE-319",
			Description: "OTA download channels must require modern TLS 1.3 with mutual client certificate authentication (mTLS) and disallow cleartext HTTP fallback.",
			Remediation: "Set require_tls_1_3: true, mtls_client_auth_enabled: true, and allow_insecure_http_fallback: false.",
			Evaluate: func(cfg *OTAPostureConfig) (bool, string) {
				if !cfg.RequireTLS13 {
					return false, "TLS 1.3 transport security is not strictly required."
				}
				if !cfg.MTLSClientAuthEnabled {
					return false, "Mutual TLS (mTLS) client certificate authentication is disabled."
				}
				if cfg.AllowInsecureHTTPFallback {
					return false, "Insecure HTTP transport fallback is permitted."
				}
				return true, "Mutual TLS 1.3 transport security enforced."
			},
		},
		{
			ID:          "LH-OTA-004",
			Title:       "Monotonic Anti-Rollback SVN Ratchet",
			Severity:    SeverityHigh,
			Deduction:   10,
			CWENumber:   "CWE-693",
			Description: "Monotonic hardware Security Version Number (SVN) must reject older firmware and ratchet only after successful post-boot healthchecks.",
			Remediation: "Set anti_rollback_svn_enforced: true and ratchet_svn_only_after_good_boot: true.",
			Evaluate: func(cfg *OTAPostureConfig) (bool, string) {
				if !cfg.AntiRollbackSVNEnforced {
					return false, "Anti-rollback SVN checks are not enforced."
				}
				if !cfg.RatchetSVNOnlyAfterGoodBoot {
					return false, "Premature SVN ratchet detected; ratchet occurs before verifying post-boot healthchecks."
				}
				return true, "Anti-rollback SVN ratchet strictly deferred to post-boot verification."
			},
		},
		{
			ID:          "LH-OTA-005",
			Title:       "Watchdog Boot-Trial & Automatic Rollback",
			Severity:    SeverityHigh,
			Deduction:   10,
			CWENumber:   "CWE-755",
			Description: "A hardware watchdog boot-trial attempt counter (1-5 attempts) must automatically roll back to the good slot upon failure.",
			Remediation: "Set boot_trial_max_attempts between 1 and 5, and auto_rollback_on_healthcheck_fail: true.",
			Evaluate: func(cfg *OTAPostureConfig) (bool, string) {
				if cfg.BootTrialMaxAttempts < 1 || cfg.BootTrialMaxAttempts > 5 {
					return false, fmt.Sprintf("Invalid boot trial attempts: %d (must be between 1 and 5).", cfg.BootTrialMaxAttempts)
				}
				if !cfg.AutoRollbackOnHealthcheckFail {
					return false, "Automatic fallback rollback on failed boot trial healthcheck is disabled."
				}
				return true, fmt.Sprintf("Watchdog boot-trial active with max %d attempts and auto-rollback.", cfg.BootTrialMaxAttempts)
			},
		},
		{
			ID:          "LH-OTA-006",
			Title:       "Multi-Signature Quorum & Freeze-Attack Guard",
			Severity:    SeverityHigh,
			Deduction:   10,
			CWENumber:   "CWE-345",
			Description: "Manifest must require an M-of-N threshold of at least 2 independent root signatures and enforce valid non-expired timestamps.",
			Remediation: "Set min_signature_quorum >= 2 and enforce_manifest_expiration: true.",
			Evaluate: func(cfg *OTAPostureConfig) (bool, string) {
				if cfg.MinSignatureQuorum < 2 {
					return false, fmt.Sprintf("Single point of signing failure: min quorum is %d (must be >= 2).", cfg.MinSignatureQuorum)
				}
				if !cfg.EnforceManifestExpiration {
					return false, "Manifest expiration timestamp enforcement is disabled (vulnerable to freeze attack)."
				}
				return true, fmt.Sprintf("Multi-signature quorum (>=%d) and freeze-attack guards enforced.", cfg.MinSignatureQuorum)
			},
		},
		{
			ID:          "LH-OTA-007",
			Title:       "Streaming Chunk Hash & dm-verity Binding",
			Severity:    SeverityHigh,
			Deduction:   10,
			CWENumber:   "CWE-353",
			Description: "Streaming chunk hashes must be verified prior to flash writes, and dm-verity root hash must be bound in the manifest.",
			Remediation: "Set verify_chunk_hashes_before_write: true and bind_dm_verity_roothash: true.",
			Evaluate: func(cfg *OTAPostureConfig) (bool, string) {
				if !cfg.VerifyChunkHashesBeforeWrite {
					return false, "Streaming chunk SHA-256 verification before flash write is disabled."
				}
				if !cfg.BindDmVerityRootHash {
					return false, "Manifest does not bind and verify dm-verity root tree hashes."
				}
				return true, "Streaming chunk hashes and dm-verity root binding active."
			},
		},
		{
			ID:          "LH-OTA-008",
			Title:       "Hardware Compatibility ID Validation",
			Severity:    SeverityMedium,
			Deduction:   4,
			CWENumber:   "CWE-20",
			Description: "Manifest must cryptographically attest and validate the target hardware board/SoC platform ID.",
			Remediation: "Set verify_hardware_compat_id: true.",
			Evaluate: func(cfg *OTAPostureConfig) (bool, string) {
				if !cfg.VerifyHardwareCompatID {
					return false, "Hardware compatibility ID validation is disabled; risk of cross-flashing incompatible hardware."
				}
				return true, "Hardware compatibility ID strictly validated."
			},
		},
		{
			ID:          "LH-OTA-009",
			Title:       "Bundle Size Bounds & Brownout Protection",
			Severity:    SeverityMedium,
			Deduction:   4,
			CWENumber:   "CWE-400",
			Description: "Firmware bundle size must be capped (<= 2048 MB) and installation gated on minimum battery state-of-charge (>= 30%).",
			Remediation: "Set max_bundle_size_mb <= 2048 and min_battery_soc_percent >= 30.",
			Evaluate: func(cfg *OTAPostureConfig) (bool, string) {
				if cfg.MaxBundleSizeMB <= 0 || cfg.MaxBundleSizeMB > 2048 {
					return false, fmt.Sprintf("Bundle size bound invalid or excessive: %d MB (must be <= 2048 MB).", cfg.MaxBundleSizeMB)
				}
				if cfg.MinBatterySoCPercent < 30 {
					return false, fmt.Sprintf("Insufficient battery threshold: %d%% (must be >= 30%% to prevent brownouts).", cfg.MinBatterySoCPercent)
				}
				return true, fmt.Sprintf("Bundle bounds (<=%d MB) and SoC threshold (>=%d%%) verified.", cfg.MaxBundleSizeMB, cfg.MinBatterySoCPercent)
			},
		},
		{
			ID:          "LH-OTA-010",
			Title:       "Telemetry Poll Jitter & Signed Audit Receipts",
			Severity:    SeverityLow,
			Deduction:   1,
			CWENumber:   "CWE-778",
			Description: "Client polling must include randomized backoff jitter to prevent Thundering Herd, and publish signed installation receipts.",
			Remediation: "Set poll_jitter_enabled: true and signed_ota_audit_receipt: true.",
			Evaluate: func(cfg *OTAPostureConfig) (bool, string) {
				if !cfg.PollJitterEnabled {
					return false, "Poll jitter randomized backoff is disabled."
				}
				if !cfg.SignedOTAAuditReceipt {
					return false, "Cryptographically signed OTA audit receipts are disabled."
				}
				return true, "Poll jitter and signed audit receipts active."
			},
		},
	}
}

// EvaluatePolicy runs all 10 rules against the provided policy configuration
func EvaluatePolicy(cfg *OTAPostureConfig) *AuditReport {
	rules := GetStandardAuditRules()
	findings := make([]AuditFinding, 0, len(rules))

	totalDeductions := 0
	passedCount := 0
	failedCount := 0

	for _, r := range rules {
		passed, reason := r.Evaluate(cfg)
		finding := AuditFinding{
			RuleID:      r.ID,
			Title:       r.Title,
			Severity:    r.Severity,
			Deduction:   r.Deduction,
			CWENumber:   r.CWENumber,
			Passed:      passed,
			Description: reason,
			Remediation: r.Remediation,
		}

		if passed {
			passedCount++
		} else {
			failedCount++
			totalDeductions += r.Deduction
		}
		findings = append(findings, finding)
	}

	score := 100 - totalDeductions
	if score < 0 {
		score = 0
	}

	var status PostureStatus
	switch {
	case score >= 90:
		status = StatusHardened
	case score >= 70:
		status = StatusAcceptable
	case score >= 50:
		status = StatusDegraded
	default:
		status = StatusNonCompliant
	}

	return &AuditReport{
		TimestampUTC:    time.Now().UTC().Format(time.RFC3339),
		Score:           score,
		Status:          status,
		TotalRules:      len(rules),
		PassedRules:     passedCount,
		FailedRules:     failedCount,
		Findings:        findings,
		PolicyEvaluated: *cfg,
	}
}

// LoadPolicyFromFile parses an OTAPostureConfig JSON file from disk
func LoadPolicyFromFile(path string) (*OTAPostureConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy file: %w", err)
	}
	var cfg OTAPostureConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse policy JSON: %w", err)
	}
	return &cfg, nil
}
