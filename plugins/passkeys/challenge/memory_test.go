package challenge_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth-passkeys/challenge"
	"github.com/go-webauthn/webauthn/webauthn"
)

func TestChallengeMemoryStore(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	cs := challenge.NewMemoryStore(challenge.WithClock(func() time.Time {
		return now
	}))

	sess := &challenge.Session{
		ID:        "session_xyz",
		Type:      challenge.CeremonyRegistration,
		UserID:    "user_456",
		Data:      webauthn.SessionData{Challenge: "random_challenge_bytes"},
		CreatedAt: now,
		ExpiresAt: now.Add(5 * time.Minute),
	}

	// 1. Save
	if err := cs.Save(ctx, sess); err != nil {
		t.Fatalf("unexpected save error: %v", err)
	}

	// 2. Get
	got, err := cs.Get(ctx, "session_xyz")
	if err != nil {
		t.Fatalf("unexpected get error: %v", err)
	}
	if got.UserID != "user_456" || got.Consumed() {
		t.Fatalf("expected unconsumed session, got %+v", got)
	}

	// 3. Consume
	consumed, err := cs.Consume(ctx, "session_xyz")
	if err != nil {
		t.Fatalf("unexpected consume error: %v", err)
	}
	if !consumed.Consumed() {
		t.Fatal("expected session to be marked consumed")
	}

	// 4. Replay prevention: Consume again must fail
	if _, err := cs.Consume(ctx, "session_xyz"); err != challenge.ErrAlreadyConsumed {
		t.Fatalf("expected ErrAlreadyConsumed on replay, got %v", err)
	}

	// 5. Expiration
	now = now.Add(10 * time.Minute)
	expiredSess := &challenge.Session{
		ID:        "session_expired",
		Type:      challenge.CeremonyAuthentication,
		CreatedAt: now.Add(-10 * time.Minute),
		ExpiresAt: now.Add(-5 * time.Minute),
	}
	_ = cs.Save(ctx, expiredSess)

	if _, err := cs.Consume(ctx, "session_expired"); err != challenge.ErrExpired {
		t.Fatalf("expected ErrExpired, got %v", err)
	}
}

func TestChallengeConcurrency(t *testing.T) {
	ctx := context.Background()
	cs := challenge.NewMemoryStore()

	sess := &challenge.Session{
		ID:        "race_session",
		Type:      challenge.CeremonyAuthentication,
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}
	_ = cs.Save(ctx, sess)

	var wg sync.WaitGroup
	workers := 10
	successCount := 0
	alreadyConsumedCount := 0
	var mu sync.Mutex

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := cs.Consume(ctx, "race_session")
			mu.Lock()
			if err == nil {
				successCount++
			} else if err == challenge.ErrAlreadyConsumed {
				alreadyConsumedCount++
			}
			mu.Unlock()
		}()
	}

	wg.Wait()

	if successCount != 1 {
		t.Fatalf("expected exactly 1 successful consumption, got %d", successCount)
	}
	if alreadyConsumedCount != workers-1 {
		t.Fatalf("expected %d replays blocked, got %d", workers-1, alreadyConsumedCount)
	}
}
