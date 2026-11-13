package ota_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-secure-ota-daemon/pkg/ota"
)

// Helper to create deterministic test key pairs
func makeTestKeyPair(t *testing.T, keyID string, seedByte byte) *ota.KeyPair {
	t.Helper()
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = seedByte
	}
	privKey := ed25519.NewKeyFromSeed(seed)
	pubKey := privKey.Public().(ed25519.PublicKey)

	return &ota.KeyPair{
		KeyID:         keyID,
		PublicKeyHex:  hex.EncodeToString(pubKey),
		PrivateKeyHex: hex.EncodeToString(privKey),
	}
}

// Helper to create deterministic test firmware payload
func makeTestPayload(size int) []byte {
	payload := make([]byte, size)
	for i := 0; i < size; i++ {
		payload[i] = byte((i*31 + 17) & 0xFF)
	}
	return payload
}

// -----------------------------------------------------------------------
// Test Group 1: Key Generation and Cryptographic Primitives
// -----------------------------------------------------------------------

func TestGenerateKeyPair(t *testing.T) {
	kp, err := ota.GenerateKeyPair("test-key-01")
	if err != nil {
		t.Fatalf("unexpected error generating key pair: %v", err)
	}
	if kp.KeyID != "test-key-01" {
		t.Errorf("expected KeyID test-key-01, got %s", kp.KeyID)
	}

	pubBytes, err := hex.DecodeString(kp.PublicKeyHex)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		t.Errorf("expected %d public key bytes, got %d (err: %v)", ed25519.PublicKeySize, len(pubBytes), err)
	}

	privBytes, err := hex.DecodeString(kp.PrivateKeyHex)
	if err != nil || len(privBytes) != ed25519.PrivateKeySize {
		t.Errorf("expected %d private key bytes, got %d (err: %v)", ed25519.PrivateKeySize, len(privBytes), err)
	}
}

func TestCanonicalPreImageDomainSeparation(t *testing.T) {
	meta := &ota.CanonicalMetadata{
		BundleVersion:         "1.0.0",
		SecurityVersionNumber: 1,
		HardwareCompatID:      "TEST-BOARD-01",
		IssuedAtUnix:          1000,
		ExpiresAtUnix:         2000,
		PayloadSizeBytes:      1024,
		PayloadSHA256Hex:      "abcdef",
	}

	preImage, err := ota.ComputeCanonicalPreImage(meta)
	if err != nil {
		t.Fatalf("failed to compute pre-image: %v", err)
	}

	if !strings.HasPrefix(string(preImage), ota.DomainSeparatorPreImage) {
		t.Errorf("pre-image missing mandatory domain separation prefix %q", ota.DomainSeparatorPreImage)
	}
}

// -----------------------------------------------------------------------
// Test Group 2: Bundle Creation, Signing, and Multi-Sig Quorum
// -----------------------------------------------------------------------

func TestBuildBundleFromBytes(t *testing.T) {
	payload := makeTestPayload(10000)
	manifest, err := ota.BuildBundleFromBytes(
		payload,
		"2.0.0",
		5,
		"ROBOT-CHASSIS-V3",
		24*time.Hour,
		4096,
		"root_tree_hash_1234",
	)
	if err != nil {
		t.Fatalf("failed to build bundle: %v", err)
	}

	if manifest.BundleVersion != "2.0.0" {
		t.Errorf("expected version 2.0.0, got %s", manifest.BundleVersion)
	}
	if manifest.SecurityVersionNumber != 5 {
		t.Errorf("expected SVN 5, got %d", manifest.SecurityVersionNumber)
	}
	if manifest.HardwareCompatID != "ROBOT-CHASSIS-V3" {
		t.Errorf("expected HW ID ROBOT-CHASSIS-V3, got %s", manifest.HardwareCompatID)
	}
	if manifest.PayloadSizeBytes != 10000 {
		t.Errorf("expected 10000 bytes, got %d", manifest.PayloadSizeBytes)
	}

	// 10000 bytes with 4096 chunk size -> 3 chunks (4096, 4096, 1808)
	if len(manifest.ChunkSHA256List) != 3 {
		t.Errorf("expected 3 chunks, got %d", len(manifest.ChunkSHA256List))
	}
}

func TestSingleSignatureSignAndVerify(t *testing.T) {
	payload := makeTestPayload(4096)
	kp := makeTestKeyPair(t, "root-01", 0x42)

	manifest, err := ota.BuildBundleFromBytes(payload, "1.0.0", 1, "HW-A", time.Hour, 1024, "")
	if err != nil {
		t.Fatalf("build error: %v", err)
	}

	if err := manifest.SignBundle(kp); err != nil {
		t.Fatalf("sign error: %v", err)
	}

	keyring := map[string]string{
		kp.KeyID: kp.PublicKeyHex,
	}

	res, err := manifest.VerifyBundle(keyring, 1, 1, "HW-A", time.Now().Unix())
	if err != nil {
		t.Fatalf("verify error: %v", err)
	}
	if !res.IsAuthentic {
		t.Errorf("expected bundle to be authentic")
	}
	if res.ValidSignaturesCount != 1 {
		t.Errorf("expected 1 valid signature, got %d", res.ValidSignaturesCount)
	}
}

func TestMOfNMultiSignatureQuorum(t *testing.T) {
	payload := makeTestPayload(8192)
	kp1 := makeTestKeyPair(t, "key-01", 0x11)
	kp2 := makeTestKeyPair(t, "key-02", 0x22)
	kp3 := makeTestKeyPair(t, "key-03", 0x33)

	manifest, err := ota.BuildBundleFromBytes(payload, "1.5.0", 3, "ROBOT-01", 2*time.Hour, 4096, "")
	if err != nil {
		t.Fatalf("build error: %v", err)
	}

	// Sign with 2 of 3 keys
	if err := manifest.SignBundle(kp1); err != nil {
		t.Fatal(err)
	}
	if err := manifest.SignBundle(kp2); err != nil {
		t.Fatal(err)
	}

	keyring := map[string]string{
		kp1.KeyID: kp1.PublicKeyHex,
		kp2.KeyID: kp2.PublicKeyHex,
		kp3.KeyID: kp3.PublicKeyHex,
	}

	now := time.Now().Unix()

	// Quorum 2-of-3 satisfied
	res, err := manifest.VerifyBundle(keyring, 2, 3, "ROBOT-01", now)
	if err != nil {
		t.Fatalf("expected 2-of-3 quorum to succeed, got %v", err)
	}
	if res.ValidSignaturesCount != 2 {
		t.Errorf("expected 2 valid signatures, got %d", res.ValidSignaturesCount)
	}

	// Quorum 3-of-3 should fail
	_, err = manifest.VerifyBundle(keyring, 3, 3, "ROBOT-01", now)
	if err == nil {
		t.Errorf("expected 3-of-3 quorum to fail with insufficient signatures")
	}
}

func TestDuplicateKeyIDRejection(t *testing.T) {
	payload := makeTestPayload(2048)
	kp := makeTestKeyPair(t, "key-dup", 0x55)

	manifest, _ := ota.BuildBundleFromBytes(payload, "1.0.0", 1, "HW-A", time.Hour, 1024, "")
	_ = manifest.SignBundle(kp)

	// Artificially duplicate the signature in manifest
	manifest.Signatures = append(manifest.Signatures, manifest.Signatures[0])

	keyring := map[string]string{kp.KeyID: kp.PublicKeyHex}
	_, err := manifest.VerifyBundle(keyring, 1, 1, "HW-A", time.Now().Unix())
	if err == nil {
		t.Errorf("expected duplicate key ID rejection")
	}
}

func TestCorruptedSignatureRejection(t *testing.T) {
	payload := makeTestPayload(2048)
	kp := makeTestKeyPair(t, "key-tamper", 0x77)

	manifest, _ := ota.BuildBundleFromBytes(payload, "1.0.0", 1, "HW-A", time.Hour, 1024, "")
	_ = manifest.SignBundle(kp)

	// Tamper with signature hex byte
	sigBytes, _ := hex.DecodeString(manifest.Signatures[0].SignatureHex)
	sigBytes[0] ^= 0xFF
	manifest.Signatures[0].SignatureHex = hex.EncodeToString(sigBytes)

	keyring := map[string]string{kp.KeyID: kp.PublicKeyHex}
	_, err := manifest.VerifyBundle(keyring, 1, 1, "HW-A", time.Now().Unix())
	if err == nil {
		t.Errorf("expected verification to fail for corrupted signature")
	}
}

// -----------------------------------------------------------------------
// Test Group 3: Anti-Rollback SVN and Freeze-Attack Expiration
// -----------------------------------------------------------------------

func TestSVNAntiRollbackEnforcement(t *testing.T) {
	payload := makeTestPayload(1024)
	kp := makeTestKeyPair(t, "key-svn", 0x88)
	keyring := map[string]string{kp.KeyID: kp.PublicKeyHex}
	now := time.Now().Unix()

	// Device fuse is SVN=5
	currentDeviceFuse := uint32(5)

	// Case A: Bundle has SVN=4 (Downgrade) -> Must Fail
	manifestOld, _ := ota.BuildBundleFromBytes(payload, "0.9.0", 4, "HW-1", time.Hour, 512, "")
	_ = manifestOld.SignBundle(kp)
	_, err := manifestOld.VerifyBundle(keyring, 1, currentDeviceFuse, "HW-1", now)
	if err == nil {
		t.Errorf("expected anti-rollback rejection for SVN 4 < device fuse 5")
	}

	// Case B: Bundle has SVN=5 (Same) -> Must Pass
	manifestSame, _ := ota.BuildBundleFromBytes(payload, "1.0.0", 5, "HW-1", time.Hour, 512, "")
	_ = manifestSame.SignBundle(kp)
	_, err = manifestSame.VerifyBundle(keyring, 1, currentDeviceFuse, "HW-1", now)
	if err != nil {
		t.Errorf("expected SVN=5 to pass device fuse 5: %v", err)
	}

	// Case C: Bundle has SVN=6 (Upgrade) -> Must Pass
	manifestNew, _ := ota.BuildBundleFromBytes(payload, "1.1.0", 6, "HW-1", time.Hour, 512, "")
	_ = manifestNew.SignBundle(kp)
	_, err = manifestNew.VerifyBundle(keyring, 1, currentDeviceFuse, "HW-1", now)
	if err != nil {
		t.Errorf("expected SVN=6 to pass device fuse 5: %v", err)
	}
}

func TestFreezeAttackExpiration(t *testing.T) {
	payload := makeTestPayload(1024)
	kp := makeTestKeyPair(t, "key-freeze", 0x99)
	keyring := map[string]string{kp.KeyID: kp.PublicKeyHex}

	// Manifest expired 1 hour ago
	manifest, _ := ota.BuildBundleFromBytes(payload, "1.0.0", 1, "HW-1", time.Hour, 512, "")
	manifest.IssuedAtUnix = time.Now().Add(-2 * time.Hour).Unix()
	manifest.ExpiresAtUnix = time.Now().Add(-1 * time.Hour).Unix()
	_ = manifest.SignBundle(kp)

	_, err := manifest.VerifyBundle(keyring, 1, 1, "HW-1", time.Now().Unix())
	if err == nil {
		t.Errorf("expected freeze-attack expiration rejection")
	}
}

func TestHardwareMismatchRejection(t *testing.T) {
	payload := makeTestPayload(1024)
	kp := makeTestKeyPair(t, "key-hw", 0xAA)
	keyring := map[string]string{kp.KeyID: kp.PublicKeyHex}

	manifest, _ := ota.BuildBundleFromBytes(payload, "1.0.0", 1, "BOARD-REV-A", time.Hour, 512, "")
	_ = manifest.SignBundle(kp)

	_, err := manifest.VerifyBundle(keyring, 1, 1, "BOARD-REV-B", time.Now().Unix())
	if err == nil {
		t.Errorf("expected hardware ID mismatch rejection")
	}
}

// -----------------------------------------------------------------------
// Test Group 4: Streaming Payload Integrity and Chunk Verification
// -----------------------------------------------------------------------

func TestStreamingPayloadVerificationSuccess(t *testing.T) {
	payload := makeTestPayload(16384)
	manifest, err := ota.BuildBundleFromBytes(payload, "1.0.0", 1, "HW-1", time.Hour, 4096, "")
	if err != nil {
		t.Fatal(err)
	}

	reader := bytes.NewReader(payload)
	if err := manifest.VerifyStreamingPayload(reader); err != nil {
		t.Fatalf("unexpected streaming verification error: %v", err)
	}
}

func TestStreamingPayloadCorruptedChunk(t *testing.T) {
	payload := makeTestPayload(16384)
	manifest, _ := ota.BuildBundleFromBytes(payload, "1.0.0", 1, "HW-1", time.Hour, 4096, "")

	// Corrupt a byte in the 2nd chunk
	corrupted := make([]byte, len(payload))
	copy(corrupted, payload)
	corrupted[5000] ^= 0x55

	reader := bytes.NewReader(corrupted)
	err := manifest.VerifyStreamingPayload(reader)
	if err == nil {
		t.Errorf("expected error for corrupted chunk in streaming payload")
	}
}

func TestStreamingPayloadTruncated(t *testing.T) {
	payload := makeTestPayload(8192)
	manifest, _ := ota.BuildBundleFromBytes(payload, "1.0.0", 1, "HW-1", time.Hour, 4096, "")

	// Truncate last 100 bytes
	reader := bytes.NewReader(payload[:8092])
	err := manifest.VerifyStreamingPayload(reader)
	if err == nil {
		t.Errorf("expected error for truncated payload")
	}
}

func TestStreamingPayloadAppendedBytes(t *testing.T) {
	payload := makeTestPayload(4096)
	manifest, _ := ota.BuildBundleFromBytes(payload, "1.0.0", 1, "HW-1", time.Hour, 4096, "")

	appended := append(payload, 0x99)
	reader := bytes.NewReader(appended)
	err := manifest.VerifyStreamingPayload(reader)
	if err == nil {
		t.Errorf("expected error for appended payload bytes")
	}
}

// -----------------------------------------------------------------------
// Test Group 5: Dual A/B Partition State Machine & Watchdog Rollbacks
// -----------------------------------------------------------------------

func TestABStateMachineInitialization(t *testing.T) {
	sm := ota.NewABStateMachine(ota.SlotA, "1.0.0", 1, 3)
	status := sm.GetStatus()

	if status.ActiveSlot != ota.SlotA {
		t.Errorf("expected active slot %s, got %s", ota.SlotA, status.ActiveSlot)
	}
	if status.StandbySlot != ota.SlotB {
		t.Errorf("expected standby slot %s, got %s", ota.SlotB, status.StandbySlot)
	}
	if status.HardwareSVNFuse != 1 {
		t.Errorf("expected hardware fuse 1, got %d", status.HardwareSVNFuse)
	}
	if status.SlotA.State != ota.StateActiveGood {
		t.Errorf("expected slot A state %s, got %s", ota.StateActiveGood, status.SlotA.State)
	}
	if status.SlotB.State != ota.StateStandbyInactive {
		t.Errorf("expected slot B state %s, got %s", ota.StateStandbyInactive, status.SlotB.State)
	}
}

func TestABStateMachineHappyPathPromotion(t *testing.T) {
	sm := ota.NewABStateMachine(ota.SlotA, "1.0.0", 1, 3)

	manifest := &ota.BundleManifest{
		CanonicalMetadata: ota.CanonicalMetadata{
			BundleVersion:         "1.1.0",
			SecurityVersionNumber: 2,
			PayloadSHA256Hex:      "dummy_sha256",
		},
	}

	// 1. Stage update on Standby (Slot B)
	if err := sm.StageUpdate(manifest); err != nil {
		t.Fatalf("stage failed: %v", err)
	}
	st := sm.GetStatus()
	if st.SlotB.State != ota.StateStagedPendingBoot {
		t.Errorf("expected slot B staged, got %s", st.SlotB.State)
	}
	// Hardware fuse must NOT ratchet yet
	if st.HardwareSVNFuse != 1 {
		t.Errorf("premature ratchet: hardware fuse ratcheted to %d", st.HardwareSVNFuse)
	}

	// 2. Initiate reboot into trial mode
	if err := sm.InitiateRebootToStaged(); err != nil {
		t.Fatalf("reboot failed: %v", err)
	}
	st = sm.GetStatus()
	if st.SlotB.State != ota.StateBootTrial {
		t.Errorf("expected slot B in boot trial, got %s", st.SlotB.State)
	}

	// 3. Healthcheck passes!
	success, rollback, err := sm.RecordBootTrialResult(true)
	if err != nil {
		t.Fatalf("trial result recording failed: %v", err)
	}
	if !success || rollback {
		t.Errorf("expected success=true, rollback=false")
	}

	st = sm.GetStatus()
	if st.ActiveSlot != ota.SlotB {
		t.Errorf("expected active slot %s, got %s", ota.SlotB, st.ActiveSlot)
	}
	if st.StandbySlot != ota.SlotA {
		t.Errorf("expected standby slot %s, got %s", ota.SlotA, st.StandbySlot)
	}
	if st.SlotB.State != ota.StateActiveGood {
		t.Errorf("expected slot B active good, got %s", st.SlotB.State)
	}
	if st.SlotA.State != ota.StateStandbyInactive {
		t.Errorf("expected slot A standby inactive, got %s", st.SlotA.State)
	}

	// DEFERRED RATCHET: hardware fuse should now be ratcheted to 2
	if st.HardwareSVNFuse != 2 {
		t.Errorf("expected hardware fuse ratcheted to 2, got %d", st.HardwareSVNFuse)
	}
}

func TestABStateMachineWatchdogRollbackOnFailure(t *testing.T) {
	sm := ota.NewABStateMachine(ota.SlotA, "1.0.0", 1, 3)

	manifest := &ota.BundleManifest{
		CanonicalMetadata: ota.CanonicalMetadata{
			BundleVersion:         "1.1.0",
			SecurityVersionNumber: 2,
		},
	}

	_ = sm.StageUpdate(manifest)
	_ = sm.InitiateRebootToStaged()

	// Trial attempt 1 fails
	success, rollback, _ := sm.RecordBootTrialResult(false)
	if success || rollback {
		t.Errorf("attempt 1 should not succeed or trigger rollback yet")
	}
	if sm.GetStatus().SlotB.BootAttemptsRemaining != 2 {
		t.Errorf("expected 2 attempts remaining")
	}

	// Trial attempt 2 fails
	success, rollback, _ = sm.RecordBootTrialResult(false)
	if success || rollback {
		t.Errorf("attempt 2 should not succeed or trigger rollback yet")
	}
	if sm.GetStatus().SlotB.BootAttemptsRemaining != 1 {
		t.Errorf("expected 1 attempt remaining")
	}

	// Trial attempt 3 fails -> Watchdog triggers rollback!
	success, rollback, err := sm.RecordBootTrialResult(false)
	if err != nil {
		t.Fatal(err)
	}
	if success || !rollback {
		t.Errorf("expected success=false, rollback=true on final attempt exhaustion")
	}

	st := sm.GetStatus()
	if st.ActiveSlot != ota.SlotA {
		t.Errorf("expected active slot to remain %s, got %s", ota.SlotA, st.ActiveSlot)
	}
	if st.SlotA.State != ota.StateActiveGood {
		t.Errorf("expected slot A to remain %s, got %s", ota.StateActiveGood, st.SlotA.State)
	}
	if st.SlotB.State != ota.StateUnbootableRolledBack {
		t.Errorf("expected slot B marked %s, got %s", ota.StateUnbootableRolledBack, st.SlotB.State)
	}

	// CRITICAL: Hardware fuse must NEVER have ratcheted to 2!
	if st.HardwareSVNFuse != 1 {
		t.Errorf("hardware fuse improperly ratcheted to %d despite rollback!", st.HardwareSVNFuse)
	}

	// Slot B can now be reset to standby inactive
	if err := sm.ResetUnbootableSlot(); err != nil {
		t.Fatalf("reset failed: %v", err)
	}
	if sm.GetStatus().SlotB.State != ota.StateStandbyInactive {
		t.Errorf("expected slot B to be reset to %s", ota.StateStandbyInactive)
	}
}

func TestABStateMachinePreventActiveSlotOverwrite(t *testing.T) {
	sm := ota.NewABStateMachine(ota.SlotA, "1.0.0", 1, 3)

	// Attempting to stage with SVN downgrade
	manifest := &ota.BundleManifest{
		CanonicalMetadata: ota.CanonicalMetadata{
			BundleVersion:         "0.9.0",
			SecurityVersionNumber: 0,
		},
	}
	err := sm.StageUpdate(manifest)
	if err == nil {
		t.Errorf("expected error staging bundle with SVN lower than hardware fuse")
	}
}

// -----------------------------------------------------------------------
// Test Group 6: 10-Rule Embedded OTA Posture Auditor
// -----------------------------------------------------------------------

func getHardenedConfig() *ota.OTAPostureConfig {
	return &ota.OTAPostureConfig{
		SignatureVerificationEnabled:  true,
		SignatureAlgorithm:            "Ed25519",
		DualABPartitionScheme:         true,
		AllowActiveSlotOverwrite:      false,
		RequireTLS13:                  true,
		MTLSClientAuthEnabled:         true,
		AllowInsecureHTTPFallback:     false,
		AntiRollbackSVNEnforced:       true,
		RatchetSVNOnlyAfterGoodBoot:   true,
		BootTrialMaxAttempts:          3,
		AutoRollbackOnHealthcheckFail: true,
		MinSignatureQuorum:            2,
		EnforceManifestExpiration:     true,
		VerifyChunkHashesBeforeWrite:  true,
		BindDmVerityRootHash:          true,
		VerifyHardwareCompatID:        true,
		MaxBundleSizeMB:               512,
		MinBatterySoCPercent:          50,
		PollJitterEnabled:             true,
		SignedOTAAuditReceipt:         true,
	}
}

func TestAuditorHardenedPolicy100Score(t *testing.T) {
	cfg := getHardenedConfig()
	report := ota.EvaluatePolicy(cfg)

	if report.Score != 100 {
		t.Errorf("expected hardened policy score 100, got %d", report.Score)
	}
	if report.Status != ota.StatusHardened {
		t.Errorf("expected status %s, got %s", ota.StatusHardened, report.Status)
	}
	if report.PassedRules != 10 || report.FailedRules != 0 {
		t.Errorf("expected 10 passed, 0 failed; got %d passed, %d failed", report.PassedRules, report.FailedRules)
	}
}

func TestAuditorVulnerablePolicyZeroScore(t *testing.T) {
	cfg := &ota.OTAPostureConfig{
		SignatureVerificationEnabled:  false,
		SignatureAlgorithm:            "RSA-1024",
		DualABPartitionScheme:         false,
		AllowActiveSlotOverwrite:      true,
		RequireTLS13:                  false,
		MTLSClientAuthEnabled:         false,
		AllowInsecureHTTPFallback:     true,
		AntiRollbackSVNEnforced:       false,
		RatchetSVNOnlyAfterGoodBoot:   false,
		BootTrialMaxAttempts:          0,
		AutoRollbackOnHealthcheckFail: false,
		MinSignatureQuorum:            1,
		EnforceManifestExpiration:     false,
		VerifyChunkHashesBeforeWrite:  false,
		BindDmVerityRootHash:          false,
		VerifyHardwareCompatID:        false,
		MaxBundleSizeMB:               4096,
		MinBatterySoCPercent:          10,
		PollJitterEnabled:             false,
		SignedOTAAuditReceipt:         false,
	}

	report := ota.EvaluatePolicy(cfg)
	if report.Score != 0 {
		t.Errorf("expected score 0 for vulnerable policy, got %d", report.Score)
	}
	if report.Status != ota.StatusNonCompliant {
		t.Errorf("expected status %s, got %s", ota.StatusNonCompliant, report.Status)
	}
	if report.FailedRules != 10 {
		t.Errorf("expected all 10 rules to fail, got %d failures", report.FailedRules)
	}
}

// Individual Rule Tests
func TestAuditorRule001(t *testing.T) {
	cfg := getHardenedConfig()
	cfg.SignatureVerificationEnabled = false
	report := ota.EvaluatePolicy(cfg)
	if report.Findings[0].Passed {
		t.Errorf("expected LH-OTA-001 to fail when signature verification disabled")
	}

	cfg = getHardenedConfig()
	cfg.SignatureAlgorithm = "ECDSA-P256"
	report = ota.EvaluatePolicy(cfg)
	if report.Findings[0].Passed {
		t.Errorf("expected LH-OTA-001 to fail when signature alg != Ed25519")
	}
}

func TestAuditorRule002(t *testing.T) {
	cfg := getHardenedConfig()
	cfg.DualABPartitionScheme = false
	report := ota.EvaluatePolicy(cfg)
	if report.Findings[1].Passed {
		t.Errorf("expected LH-OTA-002 to fail when dual A/B disabled")
	}

	cfg = getHardenedConfig()
	cfg.AllowActiveSlotOverwrite = true
	report = ota.EvaluatePolicy(cfg)
	if report.Findings[1].Passed {
		t.Errorf("expected LH-OTA-002 to fail when active slot overwrite allowed")
	}
}

func TestAuditorRule003(t *testing.T) {
	cfg := getHardenedConfig()
	cfg.RequireTLS13 = false
	report := ota.EvaluatePolicy(cfg)
	if report.Findings[2].Passed {
		t.Errorf("expected LH-OTA-003 to fail when TLS 1.3 not required")
	}

	cfg = getHardenedConfig()
	cfg.AllowInsecureHTTPFallback = true
	report = ota.EvaluatePolicy(cfg)
	if report.Findings[2].Passed {
		t.Errorf("expected LH-OTA-003 to fail when insecure HTTP fallback allowed")
	}
}

func TestAuditorRule004(t *testing.T) {
	cfg := getHardenedConfig()
	cfg.AntiRollbackSVNEnforced = false
	report := ota.EvaluatePolicy(cfg)
	if report.Findings[3].Passed {
		t.Errorf("expected LH-OTA-004 to fail when anti-rollback SVN disabled")
	}

	cfg = getHardenedConfig()
	cfg.RatchetSVNOnlyAfterGoodBoot = false
	report = ota.EvaluatePolicy(cfg)
	if report.Findings[3].Passed {
		t.Errorf("expected LH-OTA-004 to fail when premature SVN ratchet permitted")
	}
}

func TestAuditorRule005(t *testing.T) {
	cfg := getHardenedConfig()
	cfg.BootTrialMaxAttempts = 6
	report := ota.EvaluatePolicy(cfg)
	if report.Findings[4].Passed {
		t.Errorf("expected LH-OTA-005 to fail when boot trial attempts > 5")
	}

	cfg = getHardenedConfig()
	cfg.AutoRollbackOnHealthcheckFail = false
	report = ota.EvaluatePolicy(cfg)
	if report.Findings[4].Passed {
		t.Errorf("expected LH-OTA-005 to fail when auto rollback disabled")
	}
}

func TestAuditorRule006(t *testing.T) {
	cfg := getHardenedConfig()
	cfg.MinSignatureQuorum = 1
	report := ota.EvaluatePolicy(cfg)
	if report.Findings[5].Passed {
		t.Errorf("expected LH-OTA-006 to fail when min quorum < 2")
	}

	cfg = getHardenedConfig()
	cfg.EnforceManifestExpiration = false
	report = ota.EvaluatePolicy(cfg)
	if report.Findings[5].Passed {
		t.Errorf("expected LH-OTA-006 to fail when manifest expiration disabled")
	}
}

func TestAuditorRule007(t *testing.T) {
	cfg := getHardenedConfig()
	cfg.VerifyChunkHashesBeforeWrite = false
	report := ota.EvaluatePolicy(cfg)
	if report.Findings[6].Passed {
		t.Errorf("expected LH-OTA-007 to fail when chunk verify disabled")
	}

	cfg = getHardenedConfig()
	cfg.BindDmVerityRootHash = false
	report = ota.EvaluatePolicy(cfg)
	if report.Findings[6].Passed {
		t.Errorf("expected LH-OTA-007 to fail when dm-verity binding disabled")
	}
}

func TestAuditorRule008(t *testing.T) {
	cfg := getHardenedConfig()
	cfg.VerifyHardwareCompatID = false
	report := ota.EvaluatePolicy(cfg)
	if report.Findings[7].Passed {
		t.Errorf("expected LH-OTA-008 to fail when HW ID validation disabled")
	}
}

func TestAuditorRule009(t *testing.T) {
	cfg := getHardenedConfig()
	cfg.MaxBundleSizeMB = 3000
	report := ota.EvaluatePolicy(cfg)
	if report.Findings[8].Passed {
		t.Errorf("expected LH-OTA-009 to fail when bundle size > 2048 MB")
	}

	cfg = getHardenedConfig()
	cfg.MinBatterySoCPercent = 20
	report = ota.EvaluatePolicy(cfg)
	if report.Findings[8].Passed {
		t.Errorf("expected LH-OTA-009 to fail when battery threshold < 30%%")
	}
}

func TestAuditorRule010(t *testing.T) {
	cfg := getHardenedConfig()
	cfg.PollJitterEnabled = false
	report := ota.EvaluatePolicy(cfg)
	if report.Findings[9].Passed {
		t.Errorf("expected LH-OTA-010 to fail when poll jitter disabled")
	}

	cfg = getHardenedConfig()
	cfg.SignedOTAAuditReceipt = false
	report = ota.EvaluatePolicy(cfg)
	if report.Findings[9].Passed {
		t.Errorf("expected LH-OTA-010 to fail when signed audit receipt disabled")
	}
}

// -----------------------------------------------------------------------
// Test Group 7: Output Exporters (Table, JSON, SARIF)
// -----------------------------------------------------------------------

func TestTerminalTableExporter(t *testing.T) {
	report := ota.EvaluatePolicy(getHardenedConfig())
	table := ota.FormatTerminalTable(report)

	if !strings.Contains(table, "LOGIHERTZ SECURE OTA DAEMON") {
		t.Errorf("table missing expected header")
	}
	if !strings.Contains(table, "LH-OTA-001") || !strings.Contains(table, "LH-OTA-010") {
		t.Errorf("table missing rule identifiers")
	}
	if !strings.Contains(table, "HARDENED") {
		t.Errorf("table missing HARDENED status")
	}
}

func TestCanonicalJSONExporter(t *testing.T) {
	report := ota.EvaluatePolicy(getHardenedConfig())
	jsonStr, err := ota.FormatCanonicalJSON(report)
	if err != nil {
		t.Fatalf("json format error: %v", err)
	}

	var parsed ota.AuditReport
	if err := json.Unmarshal([]byte(jsonStr), &parsed); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if parsed.Score != 100 {
		t.Errorf("expected parsed score 100, got %d", parsed.Score)
	}
}

func TestSARIFExporter(t *testing.T) {
	cfg := getHardenedConfig()
	cfg.SignatureVerificationEnabled = false // generate 1 violation
	report := ota.EvaluatePolicy(cfg)

	sarifStr, err := ota.FormatSARIF(report)
	if err != nil {
		t.Fatalf("sarif format error: %v", err)
	}

	var log ota.SarifLog
	if err := json.Unmarshal([]byte(sarifStr), &log); err != nil {
		t.Fatalf("failed to parse generated SARIF: %v", err)
	}

	if log.Version != "2.1.0" {
		t.Errorf("expected SARIF version 2.1.0, got %s", log.Version)
	}
	if len(log.Runs) == 0 {
		t.Fatalf("expected runs in SARIF")
	}
	if len(log.Runs[0].Results) != 1 {
		t.Errorf("expected 1 result, got %d", len(log.Runs[0].Results))
	}
	if log.Runs[0].Results[0].RuleID != "LH-OTA-001" {
		t.Errorf("expected result rule ID LH-OTA-001, got %s", log.Runs[0].Results[0].RuleID)
	}
}

// -----------------------------------------------------------------------
// Test Group 8: File IO & Serialization
// -----------------------------------------------------------------------

func TestManifestSaveAndLoad(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "test_manifest.json")

	payload := makeTestPayload(1024)
	manifest, _ := ota.BuildBundleFromBytes(payload, "3.0.0", 10, "BOARD-Z", time.Hour, 512, "abc")

	if err := ota.SaveManifestToFile(path, manifest); err != nil {
		t.Fatalf("save error: %v", err)
	}

	loaded, err := ota.LoadManifestFromFile(path)
	if err != nil {
		t.Fatalf("load error: %v", err)
	}

	if loaded.BundleVersion != manifest.BundleVersion {
		t.Errorf("expected version %s, got %s", manifest.BundleVersion, loaded.BundleVersion)
	}
	if loaded.SecurityVersionNumber != manifest.SecurityVersionNumber {
		t.Errorf("expected SVN %d, got %d", manifest.SecurityVersionNumber, loaded.SecurityVersionNumber)
	}
	if loaded.PayloadSHA256Hex != manifest.PayloadSHA256Hex {
		t.Errorf("expected payload hash %s, got %s", manifest.PayloadSHA256Hex, loaded.PayloadSHA256Hex)
	}
}

func TestLoadPolicyFromFile(t *testing.T) {
	policyPath := "../../fixtures/hardened_ota_policy.json"
	if _, err := os.Stat(policyPath); os.IsNotExist(err) {
		policyPath = "../fixtures/hardened_ota_policy.json"
	}
	if _, err := os.Stat(policyPath); os.IsNotExist(err) {
		policyPath = "fixtures/hardened_ota_policy.json"
	}

	cfg, err := ota.LoadPolicyFromFile(policyPath)
	if err != nil {
		t.Fatalf("failed to load fixture policy: %v", err)
	}
	if !cfg.SignatureVerificationEnabled {
		t.Errorf("expected signature verification enabled in hardened fixture")
	}
}
