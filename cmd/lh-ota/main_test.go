package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func getRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	// If currently in cmd/lh-ota, parent is cmd, grandparent is repo root
	if filepath.Base(dir) == "lh-ota" {
		return filepath.Clean(filepath.Join(dir, "../.."))
	}
	return dir
}

func runCommandInRepo(t *testing.T, args ...string) (string, error) {
	t.Helper()
	repoRoot := getRepoRoot(t)
	cmdArgs := append([]string{"run", "./cmd/lh-ota"}, args...)
	cmd := exec.Command("go", cmdArgs...)
	cmd.Dir = repoRoot
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestCLIVersion(t *testing.T) {
	out, err := runCommandInRepo(t, "--version")
	if err != nil {
		t.Fatalf("command failed: %v, output: %s", err, out)
	}
	if !strings.Contains(out, "lh-ota v0.1.0") {
		t.Errorf("expected version output, got %s", out)
	}
}

func TestCLIHelp(t *testing.T) {
	out, err := runCommandInRepo(t, "--help")
	if err != nil {
		t.Fatalf("command failed: %v, output: %s", err, out)
	}
	if !strings.Contains(out, "Zero-Dependency Atomic Dual A/B OTA Daemon") {
		t.Errorf("expected help output, got %s", out)
	}
}

func TestCLIScanSubcommand(t *testing.T) {
	// 1. Scan hardened policy
	outHardened, err := runCommandInRepo(t, "scan", "fixtures/hardened_ota_policy.json", "--format=table")
	if err != nil {
		t.Fatalf("scan hardened failed: %v, output: %s", err, outHardened)
	}
	if !strings.Contains(outHardened, "HARDENED") || !strings.Contains(outHardened, "100 / 100") {
		t.Errorf("unexpected output for hardened scan: %s", outHardened)
	}

	// 2. Scan JSON format
	outJSON, err := runCommandInRepo(t, "scan", "fixtures/hardened_ota_policy.json", "--format=json")
	if err != nil {
		t.Fatalf("scan json failed: %v, output: %s", err, outJSON)
	}
	if !strings.Contains(outJSON, `"score": 100`) {
		t.Errorf("unexpected JSON output: %s", outJSON)
	}

	// 3. Scan SARIF format
	outSARIF, err := runCommandInRepo(t, "scan", "fixtures/hardened_ota_policy.json", "--format=sarif")
	if err != nil {
		t.Fatalf("scan sarif failed: %v, output: %s", err, outSARIF)
	}
	if !strings.Contains(outSARIF, `"version": "2.1.0"`) {
		t.Errorf("unexpected SARIF output: %s", outSARIF)
	}

	// 4. Scan vulnerable policy (should return non-zero exit code)
	outVuln, err := runCommandInRepo(t, "scan", "fixtures/vulnerable_ota_policy.json")
	if err == nil {
		t.Errorf("expected non-zero exit code for vulnerable policy scan, got output: %s", outVuln)
	}
	if !strings.Contains(outVuln, "NON-COMPLIANT") || !strings.Contains(outVuln, "0 / 100") {
		t.Errorf("unexpected output for vulnerable scan: %s", outVuln)
	}
}

func TestCLIKeygenAndSigningFlow(t *testing.T) {
	tmpDir := t.TempDir()
	pubPath := filepath.Join(tmpDir, "root.pub")
	privPath := filepath.Join(tmpDir, "root.priv")
	payloadPath := filepath.Join(tmpDir, "firmware.bin")
	manifestPath := filepath.Join(tmpDir, "manifest.json")

	// 1. Generate key pair
	_, err := runCommandInRepo(t, "keygen",
		"--id=signer-alpha",
		"--out-pub="+pubPath,
		"--out-priv="+privPath,
	)
	if err != nil {
		t.Fatalf("keygen failed: %v", err)
	}

	pubBytes, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatal(err)
	}
	privBytes, err := os.ReadFile(privPath)
	if err != nil {
		t.Fatal(err)
	}
	pubHex := strings.TrimSpace(string(pubBytes))
	privHex := strings.TrimSpace(string(privBytes))

	// 2. Write test payload (8 KiB)
	testPayload := bytes.Repeat([]byte{0xA5, 0x5A}, 4096)
	if err := os.WriteFile(payloadPath, testPayload, 0644); err != nil {
		t.Fatal(err)
	}

	// 3. Sign bundle
	_, err = runCommandInRepo(t, "sign-bundle",
		"--payload="+payloadPath,
		"--version=2.1.0",
		"--svn=3",
		"--hw-id=LH-AGX-01",
		"--priv-key="+privHex,
		"--key-id=signer-alpha",
		"--pub-key="+pubHex,
		"--out="+manifestPath,
	)
	if err != nil {
		t.Fatalf("sign-bundle failed: %v", err)
	}

	// 4. Verify bundle
	outVerify, err := runCommandInRepo(t, "verify-bundle",
		"--manifest="+manifestPath,
		"--payload="+payloadPath,
		"--pub-keys=signer-alpha:"+pubHex,
		"--min-quorum=1",
		"--current-svn=2",
		"--hw-id=LH-AGX-01",
	)
	if err != nil {
		t.Fatalf("verify-bundle failed: %v, out: %s", err, outVerify)
	}
	if !strings.Contains(outVerify, "FIRMWARE BUNDLE VERIFICATION SUCCESSFUL") {
		t.Errorf("unexpected verify output: %s", outVerify)
	}
}

func TestCLISimulateAB(t *testing.T) {
	// Happy path
	outSuccess, err := runCommandInRepo(t, "simulate-ab",
		"--initial-slot=SLOT_A",
		"--initial-version=1.0.0",
		"--initial-svn=1",
		"--new-version=1.1.0",
		"--new-svn=2",
	)
	if err != nil {
		t.Fatalf("simulate-ab happy path failed: %v, out: %s", err, outSuccess)
	}
	if !strings.Contains(outSuccess, "Promotion Success     : true") {
		t.Errorf("expected Promotion Success : true, got: %s", outSuccess)
	}

	// Rollback path
	outRollback, err := runCommandInRepo(t, "simulate-ab",
		"--initial-slot=SLOT_A",
		"--initial-version=1.0.0",
		"--initial-svn=1",
		"--new-version=1.1.0",
		"--new-svn=2",
		"--fail-healthcheck",
	)
	if err != nil {
		t.Fatalf("simulate-ab rollback path failed: %v, out: %s", err, outRollback)
	}
	if !strings.Contains(outRollback, "WATCHDOG ROLLBACK ACTIVATED") {
		t.Errorf("expected WATCHDOG ROLLBACK ACTIVATED, got: %s", outRollback)
	}
	if !strings.Contains(outRollback, "Rollback Triggered    : true") {
		t.Errorf("expected Rollback Triggered : true, got: %s", outRollback)
	}
}
