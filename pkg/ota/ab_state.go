package ota

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

const (
	SlotA = "SLOT_A"
	SlotB = "SLOT_B"

	StateActiveGood           = "ACTIVE_GOOD"
	StateStandbyInactive      = "STANDBY_INACTIVE"
	StateStagedPendingBoot    = "STAGED_PENDING_BOOT"
	StateBootTrial            = "BOOT_TRIAL"
	StateUnbootableRolledBack = "UNBOOTABLE_ROLLED_BACK"

	DefaultMaxBootAttempts = 3
)

var (
	ErrInvalidSlotTransition = errors.New("invalid partition slot state transition")
	ErrActiveSlotOverwrite   = errors.New("safety violation: attempting to write to currently active partition slot")
	ErrNoPendingTrial        = errors.New("no active partition slot is currently undergoing a boot trial")
	ErrSVNRatchetPremature   = errors.New("cannot ratchet hardware SVN fuse before post-boot healthchecks succeed")
)

// SlotConfig holds the operational status of an individual partition slot
type SlotConfig struct {
	SlotID                string `json:"slot_id"`
	State                 string `json:"state"`
	FirmwareVersion       string `json:"firmware_version"`
	SecurityVersionNumber uint32 `json:"security_version_number"`
	PayloadSHA256Hex      string `json:"payload_sha256_hex"`
	BootAttemptsRemaining int    `json:"boot_attempts_remaining"`
	MaxBootAttempts       int    `json:"max_boot_attempts"`
	LastUpdatedUnix       int64  `json:"last_updated_unix"`
}

// ABStateMachine coordinates atomic dual-slot failover, watchdog counters, and hardware SVN ratchets
type ABStateMachine struct {
	mu              sync.RWMutex
	ActiveSlot      string                 `json:"active_slot"`
	StandbySlot     string                 `json:"standby_slot"`
	HardwareSVNFuse uint32                 `json:"hardware_svn_fuse"`
	Slots           map[string]*SlotConfig `json:"slots"`
	History         []string               `json:"transition_history"`
}

// ABStatusReport contains an atomic snapshot of system partition status
type ABStatusReport struct {
	ActiveSlot      string     `json:"active_slot"`
	StandbySlot     string     `json:"standby_slot"`
	HardwareSVNFuse uint32     `json:"hardware_svn_fuse"`
	SlotA           SlotConfig `json:"slot_a"`
	SlotB           SlotConfig `json:"slot_b"`
	IsTrialPending  bool       `json:"is_trial_pending"`
	History         []string   `json:"transition_history"`
}

// NewABStateMachine initializes a resilient dual-slot state machine
func NewABStateMachine(initialActive string, version string, svn uint32, maxAttempts int) *ABStateMachine {
	if initialActive != SlotA && initialActive != SlotB {
		initialActive = SlotA
	}
	if maxAttempts <= 0 {
		maxAttempts = DefaultMaxBootAttempts
	}

	standby := SlotB
	if initialActive == SlotB {
		standby = SlotA
	}

	now := time.Now().Unix()

	sm := &ABStateMachine{
		ActiveSlot:      initialActive,
		StandbySlot:     standby,
		HardwareSVNFuse: svn,
		Slots: map[string]*SlotConfig{
			initialActive: {
				SlotID:                initialActive,
				State:                 StateActiveGood,
				FirmwareVersion:       version,
				SecurityVersionNumber: svn,
				PayloadSHA256Hex:      "initial_factory_payload",
				BootAttemptsRemaining: maxAttempts,
				MaxBootAttempts:       maxAttempts,
				LastUpdatedUnix:       now,
			},
			standby: {
				SlotID:                standby,
				State:                 StateStandbyInactive,
				FirmwareVersion:       "none",
				SecurityVersionNumber: 0,
				PayloadSHA256Hex:      "",
				BootAttemptsRemaining: 0,
				MaxBootAttempts:       maxAttempts,
				LastUpdatedUnix:       now,
			},
		},
		History: []string{
			fmt.Sprintf("Initialized: %s=ACTIVE_GOOD (v%s, SVN=%d), %s=STANDBY_INACTIVE",
				initialActive, version, svn, standby),
		},
	}
	return sm
}

// StageUpdate stages a verified payload into the standby slot
func (sm *ABStateMachine) StageUpdate(bundle *BundleManifest) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	standbyCfg, exists := sm.Slots[sm.StandbySlot]
	if !exists {
		return fmt.Errorf("standby slot %q not found", sm.StandbySlot)
	}

	// Verify we are not overwriting active slot
	if sm.StandbySlot == sm.ActiveSlot {
		return ErrActiveSlotOverwrite
	}

	// Permissible states for standby slot staging: STANDBY_INACTIVE, STAGED_PENDING_BOOT, UNBOOTABLE_ROLLED_BACK
	if standbyCfg.State != StateStandbyInactive &&
		standbyCfg.State != StateStagedPendingBoot &&
		standbyCfg.State != StateUnbootableRolledBack {
		return fmt.Errorf("%w: standby slot %s is in state %s",
			ErrInvalidSlotTransition, sm.StandbySlot, standbyCfg.State)
	}

	// Hardware SVN fuse check: bundle must not be lower than hardware fuse
	if bundle.SecurityVersionNumber < sm.HardwareSVNFuse {
		return fmt.Errorf("%w: bundle SVN (%d) < hardware fuse (%d)",
			ErrSVNDowngrade, bundle.SecurityVersionNumber, sm.HardwareSVNFuse)
	}

	now := time.Now().Unix()
	standbyCfg.State = StateStagedPendingBoot
	standbyCfg.FirmwareVersion = bundle.BundleVersion
	standbyCfg.SecurityVersionNumber = bundle.SecurityVersionNumber
	standbyCfg.PayloadSHA256Hex = bundle.PayloadSHA256Hex
	standbyCfg.BootAttemptsRemaining = standbyCfg.MaxBootAttempts
	standbyCfg.LastUpdatedUnix = now

	sm.recordTransition(fmt.Sprintf("Staged update on %s: v%s, SVN=%d (attempts=%d)",
		sm.StandbySlot, bundle.BundleVersion, bundle.SecurityVersionNumber, standbyCfg.MaxBootAttempts))

	return nil
}

// InitiateRebootToStaged sets up the system to boot into the staged slot in trial mode
func (sm *ABStateMachine) InitiateRebootToStaged() error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	standbyCfg := sm.Slots[sm.StandbySlot]
	if standbyCfg.State != StateStagedPendingBoot {
		return fmt.Errorf("%w: target slot %s is %s, expected %s",
			ErrInvalidSlotTransition, sm.StandbySlot, standbyCfg.State, StateStagedPendingBoot)
	}

	standbyCfg.State = StateBootTrial
	standbyCfg.LastUpdatedUnix = time.Now().Unix()

	sm.recordTransition(fmt.Sprintf("Initiated boot trial into %s (v%s, SVN=%d)",
		sm.StandbySlot, standbyCfg.FirmwareVersion, standbyCfg.SecurityVersionNumber))

	return nil
}

// RecordBootTrialResult processes the healthcheck status during a boot trial
func (sm *ABStateMachine) RecordBootTrialResult(healthcheckPass bool) (trialSuccess bool, rollbackTriggered bool, err error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	targetSlot := sm.StandbySlot
	targetCfg := sm.Slots[targetSlot]
	activeCfg := sm.Slots[sm.ActiveSlot]

	if targetCfg.State != StateBootTrial {
		return false, false, fmt.Errorf("%w: slot %s is %s",
			ErrNoPendingTrial, targetSlot, targetCfg.State)
	}

	now := time.Now().Unix()

	if healthcheckPass {
		// Post-boot healthcheck PASSED: promote standby to active
		prevActiveSlot := sm.ActiveSlot
		activeCfg.State = StateStandbyInactive
		activeCfg.BootAttemptsRemaining = 0
		activeCfg.LastUpdatedUnix = now

		targetCfg.State = StateActiveGood
		targetCfg.BootAttemptsRemaining = targetCfg.MaxBootAttempts
		targetCfg.LastUpdatedUnix = now

		sm.ActiveSlot = targetSlot
		sm.StandbySlot = prevActiveSlot

		// DEFERRED ANTI-ROLLBACK RATCHET: strictly ratchet hardware fuse now
		if targetCfg.SecurityVersionNumber > sm.HardwareSVNFuse {
			oldFuse := sm.HardwareSVNFuse
			sm.HardwareSVNFuse = targetCfg.SecurityVersionNumber
			sm.recordTransition(fmt.Sprintf("Hardware SVN fuse ratcheted: %d -> %d", oldFuse, sm.HardwareSVNFuse))
		}

		sm.recordTransition(fmt.Sprintf("Boot trial SUCCEEDED: promoted %s to ACTIVE_GOOD (v%s, SVN=%d); %s is now STANDBY_INACTIVE",
			targetSlot, targetCfg.FirmwareVersion, targetCfg.SecurityVersionNumber, prevActiveSlot))

		return true, false, nil
	}

	// Post-boot healthcheck FAILED
	targetCfg.BootAttemptsRemaining--
	targetCfg.LastUpdatedUnix = now

	sm.recordTransition(fmt.Sprintf("Boot trial healthcheck FAILED on %s: %d attempts remaining",
		targetSlot, targetCfg.BootAttemptsRemaining))

	if targetCfg.BootAttemptsRemaining <= 0 {
		// Exhausted trial attempts: trigger automatic rollback!
		targetCfg.State = StateUnbootableRolledBack
		// DO NOT ratchet hardware SVN fuse!
		// Current active slot remains unchanged and ACTIVE_GOOD
		activeCfg.State = StateActiveGood
		activeCfg.BootAttemptsRemaining = activeCfg.MaxBootAttempts
		activeCfg.LastUpdatedUnix = now

		sm.recordTransition(fmt.Sprintf("Automatic rollback triggered: %s marked UNBOOTABLE_ROLLED_BACK; falling back to %s (v%s, SVN=%d)",
			targetSlot, sm.ActiveSlot, activeCfg.FirmwareVersion, activeCfg.SecurityVersionNumber))

		return false, true, nil
	}

	return false, false, nil
}

// ResetUnbootableSlot allows clearing an unbootable slot back to standby inactive
func (sm *ABStateMachine) ResetUnbootableSlot() error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	standbyCfg := sm.Slots[sm.StandbySlot]
	if standbyCfg.State != StateUnbootableRolledBack {
		return fmt.Errorf("%w: slot %s is %s, not %s",
			ErrInvalidSlotTransition, sm.StandbySlot, standbyCfg.State, StateUnbootableRolledBack)
	}

	standbyCfg.State = StateStandbyInactive
	standbyCfg.BootAttemptsRemaining = 0
	standbyCfg.LastUpdatedUnix = time.Now().Unix()

	sm.recordTransition(fmt.Sprintf("Reset unbootable slot %s to STANDBY_INACTIVE", sm.StandbySlot))
	return nil
}

// GetStatus returns an atomic snapshot of the dual-slot status
func (sm *ABStateMachine) GetStatus() ABStatusReport {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	slotA := *sm.Slots[SlotA]
	slotB := *sm.Slots[SlotB]

	isTrial := sm.Slots[sm.StandbySlot].State == StateBootTrial

	histCopy := make([]string, len(sm.History))
	copy(histCopy, sm.History)

	return ABStatusReport{
		ActiveSlot:      sm.ActiveSlot,
		StandbySlot:     sm.StandbySlot,
		HardwareSVNFuse: sm.HardwareSVNFuse,
		SlotA:           slotA,
		SlotB:           slotB,
		IsTrialPending:  isTrial,
		History:         histCopy,
	}
}

func (sm *ABStateMachine) recordTransition(msg string) {
	entry := fmt.Sprintf("[%s] %s", time.Now().UTC().Format(time.RFC3339), msg)
	sm.History = append(sm.History, entry)
}
