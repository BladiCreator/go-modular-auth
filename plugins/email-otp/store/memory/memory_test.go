package memory_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth-email-otp/store"
	"github.com/BladiCreator/go-modular-auth-email-otp/store/memory"
)

func TestMemoryStore_Lifecycle(t *testing.T) {
	s := memory.New()
	ctx := context.Background()
	now := time.Now()

	rec := &store.Record{
		ID:          "otp-1",
		Email:       "test@example.com",
		Subject:     "user-1",
		Purpose:     "email_otp:authenticate",
		OTPHash:     "dummyhash",
		Salt:        "dummysalt",
		ExpiresAt:   now.Add(10 * time.Minute),
		MaxAttempts: 3,
		Attempts:    0,
		CreatedAt:   now,
	}

	// Create
	if err := s.Create(ctx, rec); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// GetActiveByEmail
	fetched, err := s.GetActiveByEmail(ctx, "test@example.com", now)
	if err != nil {
		t.Fatalf("GetActiveByEmail failed: %v", err)
	}
	if fetched.ID != "otp-1" {
		t.Fatalf("expected ID otp-1, got %s", fetched.ID)
	}

	// IncrementAttempts
	count, err := s.IncrementAttempts(ctx, "otp-1")
	if err != nil {
		t.Fatalf("IncrementAttempts failed: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1, got %d", count)
	}

	// MarkUsed
	if err := s.MarkUsed(ctx, "otp-1", now); err != nil {
		t.Fatalf("MarkUsed failed: %v", err)
	}

	// MarkUsed again should yield ErrConflict
	if err := s.MarkUsed(ctx, "otp-1", now); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("expected ErrConflict on double consumption, got %v", err)
	}

	// RevokeByEmail
	if err := s.RevokeByEmail(ctx, "test@example.com"); err != nil {
		t.Fatalf("RevokeByEmail failed: %v", err)
	}

	// DeleteExpired
	deleted, err := s.DeleteExpired(ctx, now.Add(20*time.Minute))
	if err != nil {
		t.Fatalf("DeleteExpired failed: %v", err)
	}
	_ = deleted
}
