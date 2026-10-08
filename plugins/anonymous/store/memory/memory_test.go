package memory_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth-anonymous/store"
	"github.com/BladiCreator/go-modular-auth-anonymous/store/memory"
)

func TestMemoryStore_CRUD(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	now := time.Now().UTC()

	ident := &store.Identity{
		ID:        "anon-1",
		UserID:    "user-1",
		ExpiresAt: now.Add(time.Hour),
		CreatedAt: now,
		UpdatedAt: now,
	}

	// Create
	if err := s.Create(ctx, ident); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Duplicate ID conflict
	if err := s.Create(ctx, ident); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("expected ErrConflict, got: %v", err)
	}

	// Duplicate UserID conflict
	dupUser := &store.Identity{
		ID:        "anon-2",
		UserID:    "user-1",
		ExpiresAt: now.Add(time.Hour),
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := s.Create(ctx, dupUser); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("expected ErrConflict for duplicate UserID, got: %v", err)
	}

	// GetByID
	got, err := s.GetByID(ctx, "anon-1")
	if err != nil {
		t.Fatalf("GetByID failed: %v", err)
	}
	if got.ID != "anon-1" || got.UserID != "user-1" {
		t.Fatalf("unexpected identity: %+v", got)
	}

	// GetByUserID
	gotByU, err := s.GetByUserID(ctx, "user-1")
	if err != nil {
		t.Fatalf("GetByUserID failed: %v", err)
	}
	if gotByU.ID != "anon-1" {
		t.Fatalf("unexpected identity: %+v", gotByU)
	}

	// Update
	convTime := now.Add(10 * time.Minute)
	got.ConvertedAt = &convTime
	if err := s.Update(ctx, got); err != nil {
		t.Fatalf("Update failed: %v", err)
	}
	updated, _ := s.GetByID(ctx, "anon-1")
	if updated.ConvertedAt == nil || !updated.Converted() {
		t.Fatalf("expected ConvertedAt to be set")
	}

	// Delete
	if err := s.Delete(ctx, "anon-1"); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
	if _, err := s.GetByID(ctx, "anon-1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound after delete, got: %v", err)
	}
}

func TestMemoryStore_ListExpired(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	now := time.Now().UTC()

	// 1: Expired and unconverted -> should be returned
	_ = s.Create(ctx, &store.Identity{
		ID:        "exp-1",
		UserID:    "u-1",
		ExpiresAt: now.Add(-time.Hour),
		CreatedAt: now.Add(-2 * time.Hour),
		UpdatedAt: now.Add(-2 * time.Hour),
	})

	// 2: Expired and unconverted -> should be returned
	_ = s.Create(ctx, &store.Identity{
		ID:        "exp-2",
		UserID:    "u-2",
		ExpiresAt: now.Add(-30 * time.Minute),
		CreatedAt: now.Add(-2 * time.Hour),
		UpdatedAt: now.Add(-2 * time.Hour),
	})

	// 3: Expired but CONVERTED -> should NOT be returned
	conv := now.Add(-40 * time.Minute)
	_ = s.Create(ctx, &store.Identity{
		ID:          "exp-3-converted",
		UserID:      "u-3",
		ExpiresAt:   now.Add(-time.Hour),
		ConvertedAt: &conv,
		CreatedAt:   now.Add(-2 * time.Hour),
		UpdatedAt:   now.Add(-2 * time.Hour),
	})

	// 4: Not expired -> should NOT be returned
	_ = s.Create(ctx, &store.Identity{
		ID:        "valid-1",
		UserID:    "u-4",
		ExpiresAt: now.Add(time.Hour),
		CreatedAt: now,
		UpdatedAt: now,
	})

	expired, err := s.ListExpired(ctx, now, 0)
	if err != nil {
		t.Fatalf("ListExpired failed: %v", err)
	}
	if len(expired) != 2 {
		t.Fatalf("expected 2 expired unconverted identities, got %d", len(expired))
	}
	if expired[0].ID != "exp-1" || expired[1].ID != "exp-2" {
		t.Fatalf("unexpected expired identities order: %v, %v", expired[0].ID, expired[1].ID)
	}

	// Limit test
	limited, err := s.ListExpired(ctx, now, 1)
	if err != nil || len(limited) != 1 {
		t.Fatalf("expected 1 identity with limit, got %d", len(limited))
	}
}
