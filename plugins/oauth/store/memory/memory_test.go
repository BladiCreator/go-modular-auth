package memory_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth-oauth/store"
	"github.com/BladiCreator/go-modular-auth-oauth/store/memory"
)

func TestMemoryStore_CRUDAndLifecycle(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	s := memory.New(memory.WithClock(func() time.Time {
		return now
	}))

	sess := &store.StateSession{
		State:        "state_abc_123",
		Provider:     "google",
		RedirectURI:  "https://example.com/callback",
		CodeVerifier: "verifier_secret_value",
		Action:       store.ActionSignIn,
		Metadata:     map[string]string{"return_to": "/dashboard"},
		ExpiresAt:    now.Add(10 * time.Minute),
		CreatedAt:    now,
	}

	// 1. Save state
	if err := s.SaveState(ctx, sess); err != nil {
		t.Fatalf("unexpected save error: %v", err)
	}

	// Duplicate save must return ErrConflict
	if err := s.SaveState(ctx, sess); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("expected ErrConflict on duplicate save, got %v", err)
	}

	// 2. Get state without consuming
	got, err := s.GetState(ctx, "state_abc_123")
	if err != nil {
		t.Fatalf("unexpected get error: %v", err)
	}
	if got.Provider != "google" || got.Consumed() {
		t.Fatalf("expected unconsumed google session, got %+v", got)
	}

	// Missing state
	if _, err := s.GetState(ctx, "nonexistent"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}

	// 3. Consume state atomically
	consumed, err := s.ConsumeState(ctx, "state_abc_123", now.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("unexpected consume error: %v", err)
	}
	if !consumed.Consumed() {
		t.Fatal("expected state to be marked consumed")
	}

	// 4. Anti-replay protection: consuming again must return ErrAlreadyConsumed
	if _, err := s.ConsumeState(ctx, "state_abc_123", now.Add(3*time.Minute)); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("expected ErrAlreadyConsumed on replay, got %v", err)
	}

	// 5. Expiration check
	expiredSess := &store.StateSession{
		State:       "state_expired",
		Provider:    "github",
		RedirectURI: "https://example.com/callback",
		Action:      store.ActionSignIn,
		ExpiresAt:   now.Add(5 * time.Minute),
		CreatedAt:   now,
	}
	if err := s.SaveState(ctx, expiredSess); err != nil {
		t.Fatalf("unexpected save error: %v", err)
	}

	// Consume after expiration
	if _, err := s.ConsumeState(ctx, "state_expired", now.Add(6*time.Minute)); !errors.Is(err, store.ErrExpired) {
		t.Fatalf("expected ErrExpired, got %v", err)
	}

	// 6. Delete state
	if err := s.DeleteState(ctx, "state_abc_123"); err != nil {
		t.Fatalf("unexpected delete error: %v", err)
	}
	if _, err := s.GetState(ctx, "state_abc_123"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound after deletion, got %v", err)
	}

	// 7. Delete expired states
	purged, err := s.DeleteExpiredStates(ctx, now.Add(10*time.Minute))
	if err != nil {
		t.Fatalf("unexpected purge error: %v", err)
	}
	if purged != 1 {
		t.Fatalf("expected 1 purged expired state, got %d", purged)
	}
}

func TestMemoryStore_ConcurrencySingleUse(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	s := memory.New()

	sess := &store.StateSession{
		State:       "race_state",
		Provider:    "google",
		RedirectURI: "https://example.com/callback",
		Action:      store.ActionSignIn,
		ExpiresAt:   now.Add(10 * time.Minute),
		CreatedAt:   now,
	}
	if err := s.SaveState(ctx, sess); err != nil {
		t.Fatalf("save error: %v", err)
	}

	workers := 25
	var wg sync.WaitGroup
	var mu sync.Mutex
	successCount := 0
	alreadyConsumedCount := 0

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.ConsumeState(ctx, "race_state", now)
			mu.Lock()
			if err == nil {
				successCount++
			} else if errors.Is(err, store.ErrAlreadyConsumed) {
				alreadyConsumedCount++
			}
			mu.Unlock()
		}()
	}

	wg.Wait()

	if successCount != 1 {
		t.Fatalf("expected exactly 1 worker to succeed in consuming state, got %d", successCount)
	}
	if alreadyConsumedCount != workers-1 {
		t.Fatalf("expected %d replays blocked with ErrAlreadyConsumed, got %d", workers-1, alreadyConsumedCount)
	}
}
