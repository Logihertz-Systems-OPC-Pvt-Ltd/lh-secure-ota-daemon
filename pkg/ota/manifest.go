package ota

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"time"
)

const (
	// DomainSeparatorPreImage prevents cross-protocol signature forgery and replay
	DomainSeparatorPreImage = "LH_OTA_BUNDLE_V1:"
	// DefaultChunkSizeBytes defines standard 4 KiB streaming chunk blocks
	DefaultChunkSizeBytes = 4096
)

var (
	ErrSVNDowngrade        = errors.New("security version number downgrade rejected (anti-rollback violation)")
	ErrManifestExpired     = errors.New("firmware bundle manifest expired (freeze-attack protection)")
	ErrManifestNotYetValid = errors.New("firmware bundle issued timestamp is in the future")
	ErrHardwareMismatch    = errors.New("hardware compatibility ID does not match target platform")
	ErrQuorumNotMet        = errors.New("insufficient valid cryptographic signatures to satisfy M-of-N quorum")
	ErrDuplicateKeyID      = errors.New("duplicate key ID detected in bundle signatures")
	ErrChunkHashMismatch   = errors.New("streaming chunk SHA-256 hash does not match manifest commitment")
	ErrPayloadHashMismatch = errors.New("full payload SHA-256 hash does not match manifest commitment")
	ErrPayloadSizeMismatch = errors.New("payload size in bytes does not match manifest commitment")
	ErrInvalidSignature    = errors.New("cryptographic Ed25519 signature is invalid")
	ErrKeyNotFound         = errors.New("signing key ID is not present in trusted root-of-trust keyring")
)

// Signature represents an RFC 8032 Ed25519 cryptographic signature entry
type Signature struct {
	KeyID        string `json:"key_id"`
	PublicKeyHex string `json:"public_key_hex"`
	SignatureHex string `json:"signature_hex"`
}

// CanonicalMetadata contains the deterministic fields signed by root-of-trust keys
type CanonicalMetadata struct {
	BundleVersion         string   `json:"bundle_version"`
	SecurityVersionNumber uint32   `json:"security_version_number"`
	HardwareCompatID      string   `json:"hardware_compat_id"`
	IssuedAtUnix          int64    `json:"issued_at_unix"`
	ExpiresAtUnix         int64    `json:"expires_at_unix"`
	PayloadSizeBytes      int64    `json:"payload_size_bytes"`
	PayloadSHA256Hex      string   `json:"payload_sha256_hex"`
	DmVerityRootHashHex   string   `json:"dm_verity_root_hash_hex"`
	ChunkSizeBytes        int      `json:"chunk_size_bytes"`
	ChunkSHA256List       []string `json:"chunk_sha256_list"`
}

// BundleManifest encapsulates the entire OTA payload specification and signatures
type BundleManifest struct {
	CanonicalMetadata
	Signatures []Signature `json:"signatures"`
}

// KeyPair represents an Ed25519 key pair with hex-encoded keys
type KeyPair struct {
	KeyID         string `json:"key_id"`
	PublicKeyHex  string `json:"public_key_hex"`
	PrivateKeyHex string `json:"private_key_hex"`
}

// VerificationResult contains the detailed verification telemetry
type VerificationResult struct {
	ValidSignaturesCount int      `json:"valid_signatures_count"`
	TotalSignaturesCount int      `json:"total_signatures_count"`
	RequiredQuorum       int      `json:"required_quorum"`
	VerifiedKeyIDs       []string `json:"verified_key_ids"`
	SecurityVersion      uint32   `json:"security_version"`
	HardwareCompatID     string   `json:"hardware_compat_id"`
	PayloadSHA256        string   `json:"payload_sha256"`
	IsAuthentic          bool     `json:"is_authentic"`
}

// GenerateKeyPair generates a new RFC 8032 Ed25519 key pair
func GenerateKeyPair(keyID string) (*KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Ed25519 key: %w", err)
	}

	return &KeyPair{
		KeyID:         keyID,
		PublicKeyHex:  hex.EncodeToString(pub),
		PrivateKeyHex: hex.EncodeToString(priv),
	}, nil
}

// ComputeCanonicalPreImage returns the domain-separated bytes to be signed/verified
func ComputeCanonicalPreImage(meta *CanonicalMetadata) ([]byte, error) {
	rawJSON, err := json.Marshal(meta)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize canonical metadata: %w", err)
	}

	preImage := make([]byte, 0, len(DomainSeparatorPreImage)+len(rawJSON))
	preImage = append(preImage, []byte(DomainSeparatorPreImage)...)
	preImage = append(preImage, rawJSON...)
	return preImage, nil
}

// SignBundle signs a bundle manifest using the provided private key
func (m *BundleManifest) SignBundle(kp *KeyPair) error {
	privBytes, err := hex.DecodeString(kp.PrivateKeyHex)
	if err != nil || len(privBytes) != ed25519.PrivateKeySize {
		return fmt.Errorf("invalid private key hex encoding or length: %w", err)
	}

	preImage, err := ComputeCanonicalPreImage(&m.CanonicalMetadata)
	if err != nil {
		return err
	}

	sig := ed25519.Sign(ed25519.PrivateKey(privBytes), preImage)

	// Check if key already signed; if so, replace
	for i, existing := range m.Signatures {
		if existing.KeyID == kp.KeyID {
			m.Signatures[i] = Signature{
				KeyID:        kp.KeyID,
				PublicKeyHex: kp.PublicKeyHex,
				SignatureHex: hex.EncodeToString(sig),
			}
			return nil
		}
	}

	m.Signatures = append(m.Signatures, Signature{
		KeyID:        kp.KeyID,
		PublicKeyHex: kp.PublicKeyHex,
		SignatureHex: hex.EncodeToString(sig),
	})
	return nil
}

// VerifyBundle validates all signatures, anti-rollback SVN, freeze expiration, and HW ID
func (m *BundleManifest) VerifyBundle(
	trustedKeyring map[string]string,
	minQuorum int,
	currentHardwareSVN uint32,
	targetHardwareID string,
	currentTimeUnix int64,
) (*VerificationResult, error) {
	// 1. Anti-Rollback SVN check
	if m.SecurityVersionNumber < currentHardwareSVN {
		return nil, fmt.Errorf("%w: bundle SVN (%d) < current device SVN (%d)",
			ErrSVNDowngrade, m.SecurityVersionNumber, currentHardwareSVN)
	}

	// 2. Freeze attack expiration check
	if m.ExpiresAtUnix > 0 && currentTimeUnix > m.ExpiresAtUnix {
		return nil, fmt.Errorf("%w: current time (%d) > bundle expiry (%d)",
			ErrManifestExpired, currentTimeUnix, m.ExpiresAtUnix)
	}
	if m.IssuedAtUnix > 0 && currentTimeUnix < (m.IssuedAtUnix-300) { // allow 5m clock skew
		return nil, fmt.Errorf("%w: bundle issued time (%d) is in the future",
			ErrManifestNotYetValid, m.IssuedAtUnix)
	}

	// 3. Hardware compatibility ID validation
	if targetHardwareID != "" && m.HardwareCompatID != targetHardwareID {
		return nil, fmt.Errorf("%w: expected %q, got %q",
			ErrHardwareMismatch, targetHardwareID, m.HardwareCompatID)
	}

	// 4. Multi-signature quorum check
	if minQuorum < 1 {
		minQuorum = 1
	}

	preImage, err := ComputeCanonicalPreImage(&m.CanonicalMetadata)
	if err != nil {
		return nil, err
	}

	seenKeys := make(map[string]bool)
	var verifiedKeyIDs []string

	for _, sig := range m.Signatures {
		if seenKeys[sig.KeyID] {
			return nil, fmt.Errorf("%w: duplicate key ID %q", ErrDuplicateKeyID, sig.KeyID)
		}
		seenKeys[sig.KeyID] = true

		trustedPubHex, exists := trustedKeyring[sig.KeyID]
		if !exists {
			// Key not in trusted keyring; skip
			continue
		}

		trustedPubBytes, err := hex.DecodeString(trustedPubHex)
		if err != nil || len(trustedPubBytes) != ed25519.PublicKeySize {
			continue
		}

		sigBytes, err := hex.DecodeString(sig.SignatureHex)
		if err != nil || len(sigBytes) != ed25519.SignatureSize {
			continue
		}

		// Constant-time check that declared public key matches keyring
		declaredPubBytes, err := hex.DecodeString(sig.PublicKeyHex)
		if err == nil && len(declaredPubBytes) == ed25519.PublicKeySize {
			if subtle.ConstantTimeCompare(trustedPubBytes, declaredPubBytes) != 1 {
				continue
			}
		}

		if ed25519.Verify(ed25519.PublicKey(trustedPubBytes), preImage, sigBytes) {
			verifiedKeyIDs = append(verifiedKeyIDs, sig.KeyID)
		}
	}

	sort.Strings(verifiedKeyIDs)

	res := &VerificationResult{
		ValidSignaturesCount: len(verifiedKeyIDs),
		TotalSignaturesCount: len(m.Signatures),
		RequiredQuorum:       minQuorum,
		VerifiedKeyIDs:       verifiedKeyIDs,
		SecurityVersion:      m.SecurityVersionNumber,
		HardwareCompatID:     m.HardwareCompatID,
		PayloadSHA256:        m.PayloadSHA256Hex,
		IsAuthentic:          len(verifiedKeyIDs) >= minQuorum,
	}

	if len(verifiedKeyIDs) < minQuorum {
		return res, fmt.Errorf("%w: valid=%d, required=%d",
			ErrQuorumNotMet, len(verifiedKeyIDs), minQuorum)
	}

	return res, nil
}

// VerifyStreamingPayload streams a payload, computing chunk hashes and overall SHA-256
func (m *BundleManifest) VerifyStreamingPayload(reader io.Reader) error {
	chunkSize := m.ChunkSizeBytes
	if chunkSize <= 0 {
		chunkSize = DefaultChunkSizeBytes
	}

	buf := make([]byte, chunkSize)
	fullHasher := sha256.New()
	chunkIndex := 0
	var totalBytesRead int64

	for {
		n, readErr := io.ReadFull(reader, buf)
		if n > 0 {
			totalBytesRead += int64(n)
			fullHasher.Write(buf[:n])

			// Verify chunk hash
			if chunkIndex >= len(m.ChunkSHA256List) {
				return fmt.Errorf("%w: received more chunks than committed in manifest", ErrChunkHashMismatch)
			}

			chunkHash := sha256.Sum256(buf[:n])
			chunkHashHex := hex.EncodeToString(chunkHash[:])

			expectedChunkHash := m.ChunkSHA256List[chunkIndex]
			if subtle.ConstantTimeCompare([]byte(chunkHashHex), []byte(expectedChunkHash)) != 1 {
				return fmt.Errorf("%w at chunk index %d (expected %s, got %s)",
					ErrChunkHashMismatch, chunkIndex, expectedChunkHash, chunkHashHex)
			}
			chunkIndex++
		}

		if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
			break
		}
		if readErr != nil {
			return fmt.Errorf("error reading streaming payload: %w", readErr)
		}
	}

	// Verify total chunk count
	if chunkIndex != len(m.ChunkSHA256List) {
		return fmt.Errorf("%w: expected %d chunks, verified %d",
			ErrChunkHashMismatch, len(m.ChunkSHA256List), chunkIndex)
	}

	// Verify total size
	if totalBytesRead != m.PayloadSizeBytes {
		return fmt.Errorf("%w: expected %d bytes, got %d",
			ErrPayloadSizeMismatch, m.PayloadSizeBytes, totalBytesRead)
	}

	// Verify full payload SHA-256
	fullHash := hex.EncodeToString(fullHasher.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(fullHash), []byte(m.PayloadSHA256Hex)) != 1 {
		return fmt.Errorf("%w: expected %s, got %s",
			ErrPayloadHashMismatch, m.PayloadSHA256Hex, fullHash)
	}

	return nil
}

// BuildBundleFromBytes constructs a complete BundleManifest from in-memory firmware bytes
func BuildBundleFromBytes(
	payload []byte,
	version string,
	svn uint32,
	hwID string,
	validDuration time.Duration,
	chunkSize int,
	dmVerityRootHex string,
) (*BundleManifest, error) {
	if chunkSize <= 0 {
		chunkSize = DefaultChunkSizeBytes
	}

	now := time.Now().UTC()
	issuedAt := now.Unix()
	var expiresAt int64
	if validDuration > 0 {
		expiresAt = now.Add(validDuration).Unix()
	}

	fullHash := sha256.Sum256(payload)
	fullHashHex := hex.EncodeToString(fullHash[:])

	var chunkList []string
	for offset := 0; offset < len(payload); offset += chunkSize {
		end := offset + chunkSize
		if end > len(payload) {
			end = len(payload)
		}
		chunkSlice := payload[offset:end]
		cHash := sha256.Sum256(chunkSlice)
		chunkList = append(chunkList, hex.EncodeToString(cHash[:]))
	}

	return &BundleManifest{
		CanonicalMetadata: CanonicalMetadata{
			BundleVersion:         version,
			SecurityVersionNumber: svn,
			HardwareCompatID:      hwID,
			IssuedAtUnix:          issuedAt,
			ExpiresAtUnix:         expiresAt,
			PayloadSizeBytes:      int64(len(payload)),
			PayloadSHA256Hex:      fullHashHex,
			DmVerityRootHashHex:   dmVerityRootHex,
			ChunkSizeBytes:        chunkSize,
			ChunkSHA256List:       chunkList,
		},
		Signatures: []Signature{},
	}, nil
}

// LoadManifestFromFile reads and parses a JSON BundleManifest from disk
func LoadManifestFromFile(path string) (*BundleManifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest file: %w", err)
	}
	var manifest BundleManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("failed to parse manifest JSON: %w", err)
	}
	return &manifest, nil
}

// SaveManifestToFile serializes and writes a BundleManifest to disk
func SaveManifestToFile(path string, manifest *BundleManifest) error {
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal manifest: %w", err)
	}
	return os.WriteFile(path, append(data, '\n'), 0644)
}
