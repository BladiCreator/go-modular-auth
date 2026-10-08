package memory_test

import (
	"context"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth-twofactor/store"
	"github.com/BladiCreator/go-modular-auth-twofactor/store/memory"
)

func TestMemoryStore_Factors(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	now := time.Now().UTC()

	f := &store.FactorRecord{
		ID:               "f1",
		UserID:           "u1",
		Type:             "totp",
		Label:            "Phone",
		EncryptedSecret:  "secret_enc",
		Confirmed:        false,
		LastUsedTimeStep: -1,
		CreatedAt:        now,
		UpdatedAt:        now,
	}

	// Save
	if err := s.SaveFactor(ctx, f); err != nil {
		t.Fatalf("SaveFactor failed: %v", err)
	}

	// Duplicate save returns ErrConflict
	if err := s.SaveFactor(ctx, f); err != store.ErrConflict {
		t.Fatalf("expected ErrConflict, got %v", err)
	}

	// Get
	got, err := s.GetFactor(ctx, "f1")
	if err != nil {
		t.Fatalf("GetFactor failed: %v", err)
	}
	if got.ID != "f1" || got.EncryptedSecret != "secret_enc" {
		t.Errorf("unexpected factor retrieved: %+v", got)
	}

	// List
	list, err := s.ListFactorsByUser(ctx, "u1")
	if err != nil || len(list) != 1 {
		t.Fatalf("ListFactorsByUser failed: %v, len=%d", err, len(list))
	}

	// Update
	got.Confirmed = true
	got.EncryptedSecret = "secret_updated"
	if err := s.UpdateFactor(ctx, got); err != nil {
		t.Fatalf("UpdateFactor failed: %v", err)
	}
	updated, _ := s.GetFactor(ctx, "f1")
	if !updated.Confirmed || updated.EncryptedSecret != "secret_updated" {
		t.Errorf("UpdateFactor did not persist updates: %+v", updated)
	}

	// Delete
	if err := s.DeleteFactor(ctx, "f1"); err != nil {
		t.Fatalf("DeleteFactor failed: %v", err)
	}
	if _, err := s.GetFactor(ctx, "f1"); err != store.ErrNotFound {
		t.Errorf("expected ErrNotFound after deletion, got %v", err)
	}

	// DeleteFactorsByUser
	_ = s.SaveFactor(ctx, &store.FactorRecord{ID: "f2", UserID: "u1"})
	_ = s.SaveFactor(ctx, &store.FactorRecord{ID: "f3", UserID: "u1"})
	_ = s.SaveFactor(ctx, &store.FactorRecord{ID: "f4", UserID: "u2"})
	if err := s.DeleteFactorsByUser(ctx, "u1"); err != nil {
		t.Fatalf("DeleteFactorsByUser failed: %v", err)
	}
	remainingU1, _ := s.ListFactorsByUser(ctx, "u1")
	if len(remainingU1) != 0 {
		t.Errorf("expected 0 factors for u1, got %d", len(remainingU1))
	}
	remainingU2, _ := s.ListFactorsByUser(ctx, "u2")
	if len(remainingU2) != 1 {
		t.Errorf("expected 1 factor for u2, got %d", len(remainingU2))
	}
}

func TestMemoryStore_RecoveryCodes(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	now := time.Now().UTC()

	codes := []*store.RecoveryCodeRecord{
		{ID: "rc1", UserID: "u1", CodeHash: "hash1", CreatedAt: now},
		{ID: "rc2", UserID: "u1", CodeHash: "hash2", CreatedAt: now},
	}

	if err := s.SaveRecoveryCodes(ctx, codes); err != nil {
		t.Fatalf("SaveRecoveryCodes failed: %v", err)
	}

	active, err := s.ListActiveRecoveryCodesByUser(ctx, "u1")
	if err != nil || len(active) != 2 {
		t.Fatalf("ListActiveRecoveryCodesByUser failed: %v, count=%d", err, len(active))
	}

	// Mark used
	if err := s.MarkRecoveryCodeUsed(ctx, "rc1", now); err != nil {
		t.Fatalf("MarkRecoveryCodeUsed failed: %v", err)
	}

	// Second mark used returns ErrConflict (single-use semantics)
	if err := s.MarkRecoveryCodeUsed(ctx, "rc1", now); err != store.ErrConflict {
		t.Fatalf("expected ErrConflict on double consumption, got %v", err)
	}

	activeAfter, _ := s.ListActiveRecoveryCodesByUser(ctx, "u1")
	if len(activeAfter) != 1 || activeAfter[0].ID != "rc2" {
		t.Errorf("expected only rc2 active, got %v", activeAfter)
	}

	// Delete by user
	if err := s.DeleteRecoveryCodesByUser(ctx, "u1"); err != nil {
		t.Fatalf("DeleteRecoveryCodesByUser failed: %v", err)
	}
	activeEnd, _ := s.ListActiveRecoveryCodesByUser(ctx, "u1")
	if len(activeEnd) != 0 {
		t.Errorf("expected 0 active codes after deletion, got %d", len(activeEnd))
	}
}

func TestMemoryStore_Challenges(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	now := time.Now().UTC()

	ch := &store.ChallengeRecord{
		ID:        "ch1",
		UserID:    "u1",
		ExpiresAt: now.Add(5 * time.Minute),
		CreatedAt: now,
	}

	if err := s.SaveChallenge(ctx, ch); err != nil {
		t.Fatalf("SaveChallenge failed: %v", err)
	}

	got, err := s.GetChallenge(ctx, "ch1")
	if err != nil || got.ID != "ch1" {
		t.Fatalf("GetChallenge failed: %v, got %+v", err, got)
	}

	if err := s.MarkChallengeUsed(ctx, "ch1", now); err != nil {
		t.Fatalf("MarkChallengeUsed failed: %v", err)
	}

	// Double use returns ErrConflict
	if err := s.MarkChallengeUsed(ctx, "ch1", now); err != store.ErrConflict {
		t.Fatalf("expected ErrConflict on double consumption, got %v", err)
	}
}
