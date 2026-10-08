package memory_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth-username/store"
	"github.com/BladiCreator/go-modular-auth-username/store/memory"
)

func TestMemoryStoreCRUD(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	now := time.Now()

	rec := &store.Record{
		UserID:     "user-1",
		Username:   "Alice",
		Normalized: "alice",
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	// 1. Create
	if err := s.Create(ctx, rec); err != nil {
		t.Fatalf("unexpected create error: %v", err)
	}

	// 2. Duplicate Create (same userID) -> ErrConflict
	dupUser := &store.Record{
		UserID:     "user-1",
		Username:   "Bob",
		Normalized: "bob",
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	if err := s.Create(ctx, dupUser); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("expected ErrConflict on duplicate UserID, got %v", err)
	}

	// 3. Duplicate Create (same normalized) -> ErrConflict
	dupNorm := &store.Record{
		UserID:     "user-2",
		Username:   "ALICE",
		Normalized: "alice",
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	if err := s.Create(ctx, dupNorm); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("expected ErrConflict on duplicate Normalized, got %v", err)
	}

	// 4. GetByNormalized
	gotNorm, err := s.GetByNormalized(ctx, "alice")
	if err != nil {
		t.Fatalf("GetByNormalized failed: %v", err)
	}
	if gotNorm.UserID != "user-1" || gotNorm.Username != "Alice" {
		t.Fatalf("unexpected record: %+v", gotNorm)
	}

	// 5. GetByUserID
	gotUser, err := s.GetByUserID(ctx, "user-1")
	if err != nil {
		t.Fatalf("GetByUserID failed: %v", err)
	}
	if gotUser.Normalized != "alice" {
		t.Fatalf("unexpected record: %+v", gotUser)
	}

	// 6. Update
	updated := &store.Record{
		UserID:     "user-1",
		Username:   "AliceWonderland",
		Normalized: "alicewonderland",
		CreatedAt:  now,
		UpdatedAt:  now.Add(time.Minute),
	}
	if err := s.Update(ctx, updated); err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	// Old normalized must be freed
	if _, err := s.GetByNormalized(ctx, "alice"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for old normalized key, got %v", err)
	}

	// New normalized must be retrievable
	gotUpdated, err := s.GetByNormalized(ctx, "alicewonderland")
	if err != nil {
		t.Fatalf("GetByNormalized updated key failed: %v", err)
	}
	if gotUpdated.Username != "AliceWonderland" {
		t.Fatalf("expected AliceWonderland, got %s", gotUpdated.Username)
	}

	// 7. Delete
	if err := s.Delete(ctx, "user-1"); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	if _, err := s.GetByUserID(ctx, "user-1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound after deletion, got %v", err)
	}
	if _, err := s.GetByNormalized(ctx, "alicewonderland"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for normalized after deletion, got %v", err)
	}
}
