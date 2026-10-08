package memory

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth-apikeys/store"
)

func TestMemoryStore_CRUD(t *testing.T) {
	ctx := context.Background()
	s := New()
	now := time.Now()

	key := &store.APIKey{
		ID:             "ak_1",
		Name:           "Test Key",
		Prefix:         "gma_test1234",
		KeyHash:        "hash1234",
		UserID:         "u1",
		OrganizationID: "org1",
		Scopes:         []string{"read", "write"},
		Permissions:    []string{"admin"},
		Metadata:       map[string]string{"env": "staging"},
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	// Create
	if err := s.Create(ctx, key); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Conflict on duplicate ID
	if err := s.Create(ctx, key); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("expected ErrConflict on duplicate ID, got %v", err)
	}

	// GetByID
	got, err := s.GetByID(ctx, "ak_1")
	if err != nil {
		t.Fatalf("GetByID failed: %v", err)
	}
	if got.Name != "Test Key" || got.Prefix != "gma_test1234" {
		t.Errorf("unexpected key data: %+v", got)
	}

	// GetByHash
	gotByHash, err := s.GetByHash(ctx, "hash1234")
	if err != nil {
		t.Fatalf("GetByHash failed: %v", err)
	}
	if gotByHash.ID != "ak_1" {
		t.Errorf("expected ID ak_1, got %s", gotByHash.ID)
	}

	// Update
	got.Name = "Updated Key"
	if err := s.Update(ctx, got); err != nil {
		t.Fatalf("Update failed: %v", err)
	}
	updated, _ := s.GetByID(ctx, "ak_1")
	if updated.Name != "Updated Key" {
		t.Errorf("expected updated name, got %s", updated.Name)
	}

	// Revoke
	revTime := time.Now()
	if err := s.Revoke(ctx, "ak_1", revTime); err != nil {
		t.Fatalf("Revoke failed: %v", err)
	}
	revoked, _ := s.GetByID(ctx, "ak_1")
	if !revoked.IsRevoked() {
		t.Errorf("expected key to be revoked")
	}

	// TouchLastUsed
	touchTime := time.Now()
	if err := s.TouchLastUsed(ctx, "ak_1", touchTime, "127.0.0.1", "curl/7.68"); err != nil {
		t.Fatalf("TouchLastUsed failed: %v", err)
	}
	touched, _ := s.GetByID(ctx, "ak_1")
	if touched.LastUsedIP != "127.0.0.1" || touched.LastUsedUA != "curl/7.68" {
		t.Errorf("unexpected last used data: %+v", touched)
	}

	// Delete
	if err := s.Delete(ctx, "ak_1"); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
	if _, err := s.GetByID(ctx, "ak_1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound after deletion, got %v", err)
	}
}

func TestMemoryStore_ListAndFilters(t *testing.T) {
	ctx := context.Background()
	s := New()
	now := time.Now()

	s.Create(ctx, &store.APIKey{
		ID:        "ak_1",
		Name:      "K1",
		KeyHash:   "h1",
		UserID:    "u1",
		CreatedAt: now.Add(-3 * time.Minute),
		UpdatedAt: now,
	})
	s.Create(ctx, &store.APIKey{
		ID:             "ak_2",
		Name:           "K2",
		KeyHash:        "h2",
		UserID:         "u1",
		OrganizationID: "org1",
		CreatedAt:      now.Add(-2 * time.Minute),
		UpdatedAt:      now,
	})
	revTime := now
	s.Create(ctx, &store.APIKey{
		ID:        "ak_3",
		Name:      "K3",
		KeyHash:   "h3",
		UserID:    "u2",
		RevokedAt: &revTime,
		CreatedAt: now.Add(-1 * time.Minute),
		UpdatedAt: now,
	})

	// List by UserID
	u1Keys, err := s.List(ctx, store.ListFilter{UserID: "u1"})
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(u1Keys) != 2 {
		t.Errorf("expected 2 keys for u1, got %d", len(u1Keys))
	}

	// List excluding revoked (default)
	allActive, err := s.List(ctx, store.ListFilter{IncludeRevoked: false})
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(allActive) != 2 {
		t.Errorf("expected 2 active keys, got %d", len(allActive))
	}

	// List including revoked
	all, err := s.List(ctx, store.ListFilter{IncludeRevoked: true})
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(all) != 3 {
		t.Errorf("expected 3 total keys, got %d", len(all))
	}
}

func TestMemoryStore_DeleteExpired(t *testing.T) {
	ctx := context.Background()
	s := New()
	now := time.Now()

	expiredAt := now.Add(-10 * time.Minute)
	futureAt := now.Add(10 * time.Minute)

	s.Create(ctx, &store.APIKey{ID: "exp1", KeyHash: "h_exp1", ExpiresAt: &expiredAt, CreatedAt: now})
	s.Create(ctx, &store.APIKey{ID: "act1", KeyHash: "h_act1", ExpiresAt: &futureAt, CreatedAt: now})

	deleted, err := s.DeleteExpired(ctx, now)
	if err != nil {
		t.Fatalf("DeleteExpired failed: %v", err)
	}
	if deleted != 1 {
		t.Errorf("expected 1 deleted key, got %d", deleted)
	}

	if _, err := s.GetByID(ctx, "exp1"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expected exp1 to be deleted, got %v", err)
	}
	if _, err := s.GetByID(ctx, "act1"); err != nil {
		t.Errorf("expected act1 to remain, got %v", err)
	}
}

func TestMemoryStore_Concurrency(t *testing.T) {
	ctx := context.Background()
	s := New()
	now := time.Now()

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			id := "ak_" + time.Now().Format("150405.000000000") + "_" + string(rune('a'+idx%26))
			hash := "hash_" + id
			_ = s.Create(ctx, &store.APIKey{
				ID:        id,
				KeyHash:   hash,
				Name:      "Concurrent",
				CreatedAt: now,
			})
			_, _ = s.GetByID(ctx, id)
			_, _ = s.GetByHash(ctx, hash)
			_ = s.TouchLastUsed(ctx, id, time.Now(), "127.0.0.1", "test")
		}(i)
	}
	wg.Wait()
}
