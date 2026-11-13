package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-secure-ota-daemon/pkg/ota"
)

const (
	Version   = "0.1.0"
	ToolName  = "lh-ota"
	Copyright = "Copyright (C) 2026 Logihertz Systems (OPC) Private Limited"
)

func printUsage() {
	fmt.Printf("%s v%s - Zero-Dependency Atomic Dual A/B OTA Daemon & Posture Auditor\n", ToolName, Version)
	fmt.Println(Copyright)
	fmt.Println("\nUSAGE:")
	fmt.Printf("  %s <command> [arguments...]\n", ToolName)
	fmt.Println("\nCOMMANDS:")
	fmt.Println("  scan           Audit an embedded OTA security policy against 10 posture rules")
	fmt.Println("  keygen         Generate a cryptographic RFC 8032 Ed25519 key pair")
	fmt.Println("  sign-bundle    Create and sign a firmware update bundle manifest")
	fmt.Println("  verify-bundle  Verify cryptographic signatures, chunk hashes, and anti-rollback SVN")
	fmt.Println("  simulate-ab    Simulate atomic dual A/B staging, boot-trials, and watchdog rollbacks")
	fmt.Println("  version        Display version and license information")
	fmt.Println("\nGLOBAL OPTIONS:")
	fmt.Println("  -h, --help     Show this help message")
	fmt.Println("  -v, --version  Show application version")
	fmt.Println("\nRun 'lh-ota <command> --help' for details on each subcommand.")
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(0)
	}

	arg1 := os.Args[1]
	if arg1 == "--help" || arg1 == "-h" || arg1 == "help" {
		printUsage()
		os.Exit(0)
	}
	if arg1 == "--version" || arg1 == "-v" || arg1 == "version" {
		fmt.Printf("%s v%s\n%s\n", ToolName, Version, Copyright)
		os.Exit(0)
	}

	switch arg1 {
	case "scan":
		runScan(os.Args[2:])
	case "keygen":
		runKeygen(os.Args[2:])
	case "sign-bundle":
		runSignBundle(os.Args[2:])
	case "verify-bundle":
		runVerifyBundle(os.Args[2:])
	case "simulate-ab":
		runSimulateAB(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "Error: unknown command %q. Run '%s --help' for available commands.\n", arg1, ToolName)
		os.Exit(1)
	}
}

func runScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	format := fs.String("format", "table", "Output format: table, json, sarif")
	outputPath := fs.String("output", "", "Optional path to write output report")
	fs.Usage = func() {
		fmt.Println("Usage: lh-ota scan <policy.json> [options]")
		fmt.Println("\nOptions:")
		fs.PrintDefaults()
	}

	var policyPath string
	var flagArgs []string
	for _, a := range args {
		if !strings.HasPrefix(a, "-") && policyPath == "" {
			policyPath = a
		} else {
			flagArgs = append(flagArgs, a)
		}
	}

	if err := fs.Parse(flagArgs); err != nil {
		os.Exit(1)
	}

	if policyPath == "" {
		if len(fs.Args()) > 0 {
			policyPath = fs.Args()[0]
		} else {
			fmt.Fprintln(os.Stderr, "Error: policy file path required. Example: lh-ota scan fixtures/hardened_ota_policy.json")
			os.Exit(1)
		}
	}
	cfg, err := ota.LoadPolicyFromFile(policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading policy file: %v\n", err)
		os.Exit(1)
	}

	report := ota.EvaluatePolicy(cfg)

	var outputText string
	switch strings.ToLower(*format) {
	case "json":
		jsonStr, err := ota.FormatCanonicalJSON(report)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error formatting JSON: %v\n", err)
			os.Exit(1)
		}
		outputText = jsonStr
	case "sarif":
		sarifStr, err := ota.FormatSARIF(report)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error formatting SARIF: %v\n", err)
			os.Exit(1)
		}
		outputText = sarifStr
	default:
		outputText = ota.FormatTerminalTable(report)
	}

	if *outputPath != "" {
		if err := os.WriteFile(*outputPath, []byte(outputText), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing report to %s: %v\n", *outputPath, err)
			os.Exit(1)
		}
		fmt.Printf("Report successfully written to %s\n", *outputPath)
	} else {
		fmt.Println(outputText)
	}

	if report.Score < 50 {
		os.Exit(1)
	}
}

func runKeygen(args []string) {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	keyID := fs.String("id", "root-signer-01", "Identifier for the key pair")
	outPub := fs.String("out-pub", "", "Optional file path to write public key hex")
	outPriv := fs.String("out-priv", "", "Optional file path to write private key hex")
	fs.Usage = func() {
		fmt.Println("Usage: lh-ota keygen [options]")
		fmt.Println("\nOptions:")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	kp, err := ota.GenerateKeyPair(*keyID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate key pair: %v\n", err)
		os.Exit(1)
	}

	if *outPub != "" {
		if err := os.WriteFile(*outPub, []byte(kp.PublicKeyHex+"\n"), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to write public key: %v\n", err)
			os.Exit(1)
		}
	}
	if *outPriv != "" {
		if err := os.WriteFile(*outPriv, []byte(kp.PrivateKeyHex+"\n"), 0600); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to write private key: %v\n", err)
			os.Exit(1)
		}
	}

	fmt.Println("Generated RFC 8032 Ed25519 Key Pair:")
	fmt.Printf("  Key ID          : %s\n", kp.KeyID)
	fmt.Printf("  Public Key (hex): %s\n", kp.PublicKeyHex)
	fmt.Printf("  Private Key(hex): %s\n", kp.PrivateKeyHex)
}

func runSignBundle(args []string) {
	fs := flag.NewFlagSet("sign-bundle", flag.ExitOnError)
	payloadPath := fs.String("payload", "", "Path to raw binary firmware image (required)")
	version := fs.String("version", "1.0.0", "Firmware semantic bundle version")
	svn := fs.Uint("svn", 1, "Security Version Number (monotonic fuse SVN)")
	hwID := fs.String("hw-id", "LH-EDGE-ROBOT-01", "Hardware platform compatibility ID")
	privKeyHex := fs.String("priv-key", "", "Hex-encoded 64-byte Ed25519 private key (required)")
	keyID := fs.String("key-id", "root-signer-01", "Signer Key ID")
	pubKeyHex := fs.String("pub-key", "", "Hex-encoded 32-byte Ed25519 public key (optional, derived if empty)")
	ttlHours := fs.Int("ttl-hours", 168, "Manifest valid lifetime in hours (freeze-attack guard)")
	chunkSize := fs.Int("chunk-size", 4096, "Streaming chunk block size in bytes")
	dmVerityRoot := fs.String("dm-verity", "", "Optional hex dm-verity root tree hash")
	outManifest := fs.String("out", "", "Path to write output signed manifest JSON")

	fs.Usage = func() {
		fmt.Println("Usage: lh-ota sign-bundle [options]")
		fmt.Println("\nOptions:")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	if *payloadPath == "" || *privKeyHex == "" {
		fmt.Fprintln(os.Stderr, "Error: --payload and --priv-key are required.")
		fs.Usage()
		os.Exit(1)
	}

	payloadBytes, err := os.ReadFile(*payloadPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading payload %s: %v\n", *payloadPath, err)
		os.Exit(1)
	}

	validDuration := time.Duration(*ttlHours) * time.Hour
	manifest, err := ota.BuildBundleFromBytes(
		payloadBytes,
		*version,
		uint32(*svn),
		*hwID,
		validDuration,
		*chunkSize,
		*dmVerityRoot,
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error building bundle manifest: %v\n", err)
		os.Exit(1)
	}

	// Compute public key from private key if not explicitly provided
	if *pubKeyHex == "" {
		privBytes, err := hex.DecodeString(*privKeyHex)
		if err == nil && len(privBytes) == 64 {
			*pubKeyHex = hex.EncodeToString(privBytes[32:])
		}
	}

	kp := &ota.KeyPair{
		KeyID:         *keyID,
		PublicKeyHex:  *pubKeyHex,
		PrivateKeyHex: *privKeyHex,
	}

	if err := manifest.SignBundle(kp); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to cryptographically sign bundle: %v\n", err)
		os.Exit(1)
	}

	if *outManifest != "" {
		if err := ota.SaveManifestToFile(*outManifest, manifest); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to save manifest to %s: %v\n", *outManifest, err)
			os.Exit(1)
		}
		fmt.Printf("Successfully generated and signed manifest: %s\n", *outManifest)
	} else {
		jsonBytes, _ := json.MarshalIndent(manifest, "", "  ")
		fmt.Println(string(jsonBytes))
	}
}

func runVerifyBundle(args []string) {
	fs := flag.NewFlagSet("verify-bundle", flag.ExitOnError)
	manifestPath := fs.String("manifest", "", "Path to bundle manifest JSON (required)")
	payloadPath := fs.String("payload", "", "Path to firmware payload binary (required)")
	pubKeysRaw := fs.String("pub-keys", "", "Trusted key list: file or comma-separated key_id:pub_hex (required)")
	minQuorum := fs.Int("min-quorum", 1, "Minimum required valid signatures (M-of-N quorum)")
	currentSVN := fs.Uint("current-svn", 0, "Current device hardware SVN fuse value")
	hwID := fs.String("hw-id", "", "Expected hardware compatibility ID")

	fs.Usage = func() {
		fmt.Println("Usage: lh-ota verify-bundle [options]")
		fmt.Println("\nOptions:")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	if *manifestPath == "" || *payloadPath == "" || *pubKeysRaw == "" {
		fmt.Fprintln(os.Stderr, "Error: --manifest, --payload, and --pub-keys are required.")
		fs.Usage()
		os.Exit(1)
	}

	manifest, err := ota.LoadManifestFromFile(*manifestPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading manifest: %v\n", err)
		os.Exit(1)
	}

	// Parse trusted keyring
	keyring := make(map[string]string)
	if _, err := os.Stat(*pubKeysRaw); err == nil {
		// Keyring file in JSON format
		keyData, err := os.ReadFile(*pubKeysRaw)
		if err == nil {
			_ = json.Unmarshal(keyData, &keyring)
		}
	}
	if len(keyring) == 0 {
		// Comma-separated pairs: id1:hex1,id2:hex2
		pairs := strings.Split(*pubKeysRaw, ",")
		for _, pair := range pairs {
			parts := strings.SplitN(strings.TrimSpace(pair), ":", 2)
			if len(parts) == 2 {
				keyring[parts[0]] = parts[1]
			}
		}
	}

	now := time.Now().Unix()
	res, err := manifest.VerifyBundle(keyring, *minQuorum, uint32(*currentSVN), *hwID, now)
	if err != nil {
		fmt.Fprintf(os.Stderr, "BUNDLE VERIFICATION FAILED: %v\n", err)
		os.Exit(1)
	}

	// Verify streaming payload chunk hashes and overall SHA-256
	payloadFile, err := os.Open(*payloadPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open payload file %s: %v\n", *payloadPath, err)
		os.Exit(1)
	}
	defer payloadFile.Close()

	if err := manifest.VerifyStreamingPayload(payloadFile); err != nil {
		fmt.Fprintf(os.Stderr, "STREAMING INTEGRITY VERIFICATION FAILED: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("===================================================================")
	fmt.Println("            FIRMWARE BUNDLE VERIFICATION SUCCESSFUL                ")
	fmt.Println("===================================================================")
	fmt.Printf(" Bundle Version      : %s\n", manifest.BundleVersion)
	fmt.Printf(" Security Version    : %d (Device Fuse: %d)\n", manifest.SecurityVersionNumber, *currentSVN)
	fmt.Printf(" Hardware ID         : %s\n", manifest.HardwareCompatID)
	fmt.Printf(" Signatures Verified : %d / %d (Required Quorum: %d)\n",
		res.ValidSignaturesCount, res.TotalSignaturesCount, res.RequiredQuorum)
	fmt.Printf(" Verified Key IDs    : %s\n", strings.Join(res.VerifiedKeyIDs, ", "))
	fmt.Printf(" Payload Size        : %d bytes\n", manifest.PayloadSizeBytes)
	fmt.Printf(" Payload SHA-256     : %s\n", manifest.PayloadSHA256Hex)
	fmt.Printf(" Streaming Chunks    : %d verified chunks (%d bytes/chunk)\n",
		len(manifest.ChunkSHA256List), manifest.ChunkSizeBytes)
	fmt.Println(" Cryptographic Status: AUTHENTIC, VALID, AND SAFE TO FLASH")
	fmt.Println("===================================================================")
}

func runSimulateAB(args []string) {
	fs := flag.NewFlagSet("simulate-ab", flag.ExitOnError)
	initialSlot := fs.String("initial-slot", "SLOT_A", "Initial active partition slot (SLOT_A or SLOT_B)")
	initialVer := fs.String("initial-version", "1.0.0", "Current production firmware version")
	initialSVN := fs.Uint("initial-svn", 1, "Current hardware monotonic SVN fuse")
	newVer := fs.String("new-version", "1.1.0", "New firmware version to stage")
	newSVN := fs.Uint("new-svn", 2, "New firmware SVN")
	maxAttempts := fs.Int("max-attempts", 3, "Watchdog boot-trial attempts")
	failHealthcheck := fs.Bool("fail-healthcheck", false, "Force post-boot healthchecks to fail (triggers rollback)")

	fs.Usage = func() {
		fmt.Println("Usage: lh-ota simulate-ab [options]")
		fmt.Println("\nOptions:")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	fmt.Println("===================================================================")
	fmt.Println("      LOGIHERTZ DUAL A/B PARTITION FAIL-SAFE OTA SIMULATION        ")
	fmt.Println("===================================================================")

	sm := ota.NewABStateMachine(*initialSlot, *initialVer, uint32(*initialSVN), *maxAttempts)
	status := sm.GetStatus()
	fmt.Printf("[STEP 1: INITIAL STATE]\n")
	fmt.Printf("  Active Slot      : %s (v%s, SVN=%d)\n", status.ActiveSlot, status.SlotA.FirmwareVersion, status.HardwareSVNFuse)
	fmt.Printf("  Standby Slot     : %s (State=%s)\n", status.StandbySlot, status.SlotB.State)
	fmt.Printf("  Hardware SVN Fuse: %d\n\n", status.HardwareSVNFuse)

	// Build dummy manifest for staging
	dummyHash := sha256.Sum256([]byte("dummy_firmware_bytes_for_simulation"))
	manifest := &ota.BundleManifest{
		CanonicalMetadata: ota.CanonicalMetadata{
			BundleVersion:         *newVer,
			SecurityVersionNumber: uint32(*newSVN),
			HardwareCompatID:      "LH-TEST-TARGET",
			PayloadSHA256Hex:      hex.EncodeToString(dummyHash[:]),
		},
	}

	fmt.Printf("[STEP 2: STAGING FIRMWARE]\n")
	if err := sm.StageUpdate(manifest); err != nil {
		fmt.Fprintf(os.Stderr, "Staging failed: %v\n", err)
		os.Exit(1)
	}
	status = sm.GetStatus()
	targetSlotCfg := status.SlotB
	if status.StandbySlot == ota.SlotA {
		targetSlotCfg = status.SlotA
	}
	fmt.Printf("  Staged on Target Slot : %s\n", status.StandbySlot)
	fmt.Printf("  Target Slot State     : %s\n", targetSlotCfg.State)
	fmt.Printf("  Target Version / SVN  : v%s / SVN=%d\n", targetSlotCfg.FirmwareVersion, targetSlotCfg.SecurityVersionNumber)
	fmt.Printf("  Hardware Fuse (Held)  : %d (Ratchet strictly deferred!)\n\n", status.HardwareSVNFuse)

	fmt.Printf("[STEP 3: INITIATING REBOOT INTO TRIAL MODE]\n")
	if err := sm.InitiateRebootToStaged(); err != nil {
		fmt.Fprintf(os.Stderr, "Reboot initiation failed: %v\n", err)
		os.Exit(1)
	}
	status = sm.GetStatus()
	targetSlotCfg = status.SlotB
	if status.StandbySlot == ota.SlotA {
		targetSlotCfg = status.SlotA
	}
	fmt.Printf("  Target Slot State     : %s\n", targetSlotCfg.State)
	fmt.Printf("  Boot Counter Remaining: %d / %d\n\n", targetSlotCfg.BootAttemptsRemaining, targetSlotCfg.MaxBootAttempts)

	fmt.Printf("[STEP 4: WATCHDOG HEALTHCHECKS & BOOT RESOLUTION]\n")
	if !*failHealthcheck {
		// Scenario: Healthcheck PASSES
		success, rollback, err := sm.RecordBootTrialResult(true)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Trial recording error: %v\n", err)
			os.Exit(1)
		}
		status = sm.GetStatus()
		fmt.Printf("  Healthcheck Result    : PASSED\n")
		fmt.Printf("  Promotion Success     : %t\n", success)
		fmt.Printf("  Rollback Triggered    : %t\n", rollback)
		fmt.Printf("  New Active Slot       : %s (v%s, SVN=%d)\n", status.ActiveSlot, *newVer, *newSVN)
		fmt.Printf("  Standby Slot          : %s\n", status.StandbySlot)
		fmt.Printf("  Hardware Fuse Ratchet : %d (Successfully Ratcheted Post-Boot)\n", status.HardwareSVNFuse)
	} else {
		// Scenario: Healthcheck FAILS repeatedly until watchdog triggers rollback
		for attempt := 1; attempt <= *maxAttempts; attempt++ {
			success, rollback, err := sm.RecordBootTrialResult(false)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Trial recording error: %v\n", err)
				os.Exit(1)
			}
			status = sm.GetStatus()
			targetSlotCfg = status.SlotB
			if status.StandbySlot == ota.SlotA {
				targetSlotCfg = status.SlotA
			}
			fmt.Printf("  Healthcheck Attempt #%d : FAILED (Remaining: %d)\n", attempt, targetSlotCfg.BootAttemptsRemaining)
			if rollback {
				fmt.Printf("\n[WATCHDOG ROLLBACK ACTIVATED]\n")
				fmt.Printf("  Failed Slot State     : %s\n", targetSlotCfg.State)
				fmt.Printf("  Active Fallback Slot  : %s (v%s, SVN=%d)\n", status.ActiveSlot, *initialVer, *initialSVN)
				fmt.Printf("  Hardware Fuse Value   : %d (PROTECTED: No premature ratchet!)\n", status.HardwareSVNFuse)
				fmt.Printf("  Rollback Triggered    : %t\n", rollback)
				fmt.Printf("  Success               : %t\n", success)
				break
			}
		}
	}
	fmt.Println("===================================================================")
}
