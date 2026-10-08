package memory_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth-multisession/store"
	"github.com/BladiCreator/go-modular-auth-multisession/store/memory"
)

func TestMemoryStore_CRUD(t *testing.T) {
	ctx := context.Background()
	s := memory.New()

	// Initial Get should return ErrNotFound
	_, err := s.Get(ctx, "session_1")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}

	rec := &store.MetadataRecord{
		SessionID: "session_1",
		UserID:    "user_1",
		Device: store.DeviceRecord{
			Name: "MacBook Pro",
			OS:   "macOS",
		},
		Custom: map[string]string{
			"env": "prod",
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Save
	if err := s.Save(ctx, rec); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Get
	got, err := s.Get(ctx, "session_1")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if got.Device.Name != "MacBook Pro" || got.Custom["env"] != "prod" {
		t.Fatalf("unexpected record: %+v", got)
	}

	// Verify deep copy mutation safety
	rec.Custom["env"] = "mutated"
	gotAfter, _ := s.Get(ctx, "session_1")
	if gotAfter.Custom["env"] != "prod" {
		t.Fatal("store records must be immune to external pointer/map mutations")
	}

	// Delete
	if err := s.Delete(ctx, "session_1"); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	_, err = s.Get(ctx, "session_1")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound after Delete, got %v", err)
	}
}

func TestMemoryStore_DeleteBySessionIDs(t *testing.T) {
	ctx := context.Background()
	s := memory.New()

	_ = s.Save(ctx, &store.MetadataRecord{SessionID: "s1", UserID: "u1"})
	_ = s.Save(ctx, &store.MetadataRecord{SessionID: "s2", UserID: "u1"})
	_ = s.Save(ctx, &store.MetadataRecord{SessionID: "s3", UserID: "u1"})

	if err := s.DeleteBySessionIDs(ctx, []string{"s1", "s2"}); err != nil {
		t.Fatalf("DeleteBySessionIDs failed: %v", err)
	}

	if _, err := s.Get(ctx, "s1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("s1 should be deleted")
	}
	if _, err := s.Get(ctx, "s2"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("s2 should be deleted")
	}
	if _, err := s.Get(ctx, "s3"); err != nil {
		t.Fatal("s3 should remain")
	}
}
