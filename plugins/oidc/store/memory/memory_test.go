package memory_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth-oidc/store"
	"github.com/BladiCreator/go-modular-auth-oidc/store/memory"
)

func TestMemoryStore_Lifecycle(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	now := time.Now().UTC()

	sess := &store.StateSession{
		State:        "state-123",
		Provider:     "google",
		RedirectURI:  "https://app.example.com/cb",
		CodeVerifier: "verifier-xyz",
		Nonce:        "nonce-abc",
		Action:       store.ActionSignIn,
		ExpiresAt:    now.Add(10 * time.Minute),
		CreatedAt:    now,
	}

	// 1. SaveState
	if err := s.SaveState(ctx, sess); err != nil {
		t.Fatalf("SaveState failed: %v", err)
	}

	// 2. Duplicate SaveState
	if err := s.SaveState(ctx, sess); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("expected ErrConflict on duplicate, got %v", err)
	}

	// 3. GetState
	got, err := s.GetState(ctx, "state-123")
	if err != nil {
		t.Fatalf("GetState failed: %v", err)
	}
	if got.State != "state-123" || got.Provider != "google" {
		t.Errorf("unexpected retrieved state: %+v", got)
	}

	// 4. Non-existent Get
	_, err = s.GetState(ctx, "unknown-state")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}

	// 5. ConsumeState (Single-use)
	consumed, err := s.ConsumeState(ctx, "state-123", now)
	if err != nil {
		t.Fatalf("ConsumeState failed: %v", err)
	}
	if !consumed.IsConsumed() {
		t.Fatalf("expected state to be marked as consumed")
	}

	// 6. Re-consume (Double-spend prevention)
	_, err = s.ConsumeState(ctx, "state-123", now)
	if !errors.Is(err, store.ErrStateConsumed) {
		t.Fatalf("expected ErrStateConsumed on replay, got %v", err)
	}

	// 7. DeleteState
	if err := s.DeleteState(ctx, "state-123"); err != nil {
		t.Fatalf("DeleteState failed: %v", err)
	}
	_, err = s.GetState(ctx, "state-123")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound after deletion, got %v", err)
	}
}

func TestMemoryStore_PurgeExpired(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	now := time.Now().UTC()

	s1 := &store.StateSession{
		State:     "expired-1",
		Provider:  "okta",
		ExpiresAt: now.Add(-5 * time.Minute),
		CreatedAt: now.Add(-15 * time.Minute),
	}
	s2 := &store.StateSession{
		State:     "valid-1",
		Provider:  "okta",
		ExpiresAt: now.Add(15 * time.Minute),
		CreatedAt: now,
	}

	_ = s.SaveState(ctx, s1)
	_ = s.SaveState(ctx, s2)

	n, err := s.PurgeExpired(ctx, now)
	if err != nil {
		t.Fatalf("PurgeExpired failed: %v", err)
	}
	if n != 1 {
		t.Errorf("expected 1 purged record, got %d", n)
	}

	_, err = s.GetState(ctx, "expired-1")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected expired state to be deleted, got %v", err)
	}

	valid, err := s.GetState(ctx, "valid-1")
	if err != nil || valid == nil {
		t.Fatalf("expected valid state to remain, got %v", err)
	}
}
