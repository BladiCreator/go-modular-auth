package repository_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/entity"
	"github.com/BladiCreator/go-modular-auth/domain/repository"
)

func TestMemoryVerificationRepository_CRUD(t *testing.T) {
	ctx := context.Background()
	repo := repository.NewMemoryVerificationRepository()

	// 1. Invalid input
	if err := repo.CreateVerification(ctx, nil); !errors.Is(err, repository.ErrInvalidVerification) {
		t.Fatalf("expected ErrInvalidVerification, got %v", err)
	}
	if err := repo.CreateVerification(ctx, &entity.Verification{}); !errors.Is(err, repository.ErrInvalidVerification) {
		t.Fatalf("expected ErrInvalidVerification on empty identifier, got %v", err)
	}

	// 2. Create valid record
	rec := &entity.Verification{
		Identifier: "user@example.com",
		Value:      "secret-code-123",
		ExpiresAt:  time.Now().Add(5 * time.Minute),
	}
	if err := repo.CreateVerification(ctx, rec); err != nil {
		t.Fatalf("unexpected error creating verification: %v", err)
	}

	// 3. Find valid record
	found, err := repo.FindVerification(ctx, "user@example.com")
	if err != nil {
		t.Fatalf("unexpected error finding verification: %v", err)
	}
	if found.Identifier != "user@example.com" || found.Value != "secret-code-123" {
		t.Fatalf("unexpected found record: %+v", found)
	}
	if found.ID == "" {
		t.Fatalf("expected auto-generated ID, got empty")
	}

	// 4. Overwrite record (upsert)
	recUpdated := &entity.Verification{
		Identifier: "user@example.com",
		Value:      "new-secret-456",
		ExpiresAt:  time.Now().Add(10 * time.Minute),
	}
	if err := repo.CreateVerification(ctx, recUpdated); err != nil {
		t.Fatalf("failed to update verification: %v", err)
	}
	found, err = repo.FindVerification(ctx, "user@example.com")
	if err != nil || found.Value != "new-secret-456" {
		t.Fatalf("expected updated value, got %v, err: %v", found, err)
	}

	// 5. Atomic consumption
	consumed, err := repo.ConsumeVerification(ctx, "user@example.com")
	if err != nil {
		t.Fatalf("unexpected error consuming verification: %v", err)
	}
	if consumed.Value != "new-secret-456" {
		t.Fatalf("unexpected consumed value: %s", consumed.Value)
	}

	// 6. After consumption, record should no longer exist
	_, err = repo.FindVerification(ctx, "user@example.com")
	if !errors.Is(err, repository.ErrVerificationNotFound) {
		t.Fatalf("expected ErrVerificationNotFound after consumption, got %v", err)
	}
	_, err = repo.ConsumeVerification(ctx, "user@example.com")
	if !errors.Is(err, repository.ErrVerificationNotFound) {
		t.Fatalf("expected ErrVerificationNotFound on double consume, got %v", err)
	}

	// 7. DeleteVerification
	recToDelete := &entity.Verification{
		Identifier: "delete-me",
		Value:      "val",
		ExpiresAt:  time.Now().Add(1 * time.Minute),
	}
	_ = repo.CreateVerification(ctx, recToDelete)
	if err := repo.DeleteVerification(ctx, "delete-me"); err != nil {
		t.Fatalf("unexpected delete error: %v", err)
	}
	_, err = repo.FindVerification(ctx, "delete-me")
	if !errors.Is(err, repository.ErrVerificationNotFound) {
		t.Fatalf("expected ErrVerificationNotFound after delete, got %v", err)
	}
}

func TestMemoryVerificationRepository_Expiration(t *testing.T) {
	ctx := context.Background()
	repo := repository.NewMemoryVerificationRepository()

	rec := &entity.Verification{
		Identifier: "expired-user",
		Value:      "expired-code",
		ExpiresAt:  time.Now().Add(-1 * time.Second), // already expired
	}
	if err := repo.CreateVerification(ctx, rec); err != nil {
		t.Fatalf("unexpected create error: %v", err)
	}

	// Find expired
	_, err := repo.FindVerification(ctx, "expired-user")
	if !errors.Is(err, repository.ErrVerificationExpired) {
		t.Fatalf("expected ErrVerificationExpired on Find, got %v", err)
	}

	// Consume expired
	_, err = repo.ConsumeVerification(ctx, "expired-user")
	if !errors.Is(err, repository.ErrVerificationExpired) {
		t.Fatalf("expected ErrVerificationExpired on Consume, got %v", err)
	}

	// Once consumed/expired, should be removed
	_, err = repo.FindVerification(ctx, "expired-user")
	if !errors.Is(err, repository.ErrVerificationNotFound) {
		t.Fatalf("expected ErrVerificationNotFound after expired consume, got %v", err)
	}
}

func TestMemoryVerificationRepository_Concurrency(t *testing.T) {
	ctx := context.Background()
	repo := repository.NewMemoryVerificationRepository()

	identifier := "concurrent-test"
	_ = repo.CreateVerification(ctx, &entity.Verification{
		Identifier: identifier,
		Value:      "single-use-token",
		ExpiresAt:  time.Now().Add(5 * time.Minute),
	})

	// Concurrent race for atomic single-use ConsumeVerification
	var wg sync.WaitGroup
	var successCount int
	var mu sync.Mutex

	for range 20 {
		wg.Go(func() {
			rec, err := repo.ConsumeVerification(ctx, identifier)
			if err == nil && rec != nil {
				mu.Lock()
				successCount++
				mu.Unlock()
			}
		})
	}
	wg.Wait()

	if successCount != 1 {
		t.Fatalf("expected exactly 1 successful consume in race, got %d", successCount)
	}
}
