package memory_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth-bearer/store"
	"github.com/BladiCreator/go-modular-auth-bearer/store/memory"
)

func TestMemoryStore_CRUD(t *testing.T) {
	ctx := context.Background()
	s := memory.New()

	now := time.Now().UTC()
	rec := &store.TokenRecord{
		ID:            "token-1",
		TokenHash:     "hash-1",
		Subject:       "user-123",
		PrincipalType: "user",
		Scopes:        []string{"read", "write"},
		Metadata:      map[string]string{"env": "test"},
		ExpiresAt:     now.Add(time.Hour),
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	// 1. Create
	if err := s.Create(ctx, rec); err != nil {
		t.Fatalf("unexpected create error: %v", err)
	}

	// 2. Conflict on duplicate ID
	dupID := &store.TokenRecord{
		ID:        "token-1",
		TokenHash: "hash-diff",
		Subject:   "user-123",
	}
	if err := s.Create(ctx, dupID); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("expected ErrConflict on duplicate ID, got %v", err)
	}

	// 3. Conflict on duplicate Hash
	dupHash := &store.TokenRecord{
		ID:        "token-2",
		TokenHash: "hash-1",
		Subject:   "user-123",
	}
	if err := s.Create(ctx, dupHash); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("expected ErrConflict on duplicate Hash, got %v", err)
	}

	// 4. GetByID
	got, err := s.GetByID(ctx, "token-1")
	if err != nil {
		t.Fatalf("unexpected GetByID error: %v", err)
	}
	if got.Subject != "user-123" || got.TokenHash != "hash-1" {
		t.Fatalf("unexpected record content: %+v", got)
	}

	// 5. GetByTokenHash
	gotHash, err := s.GetByTokenHash(ctx, "hash-1")
	if err != nil {
		t.Fatalf("unexpected GetByTokenHash error: %v", err)
	}
	if gotHash.ID != "token-1" {
		t.Fatalf("expected ID token-1, got %s", gotHash.ID)
	}

	// 6. Update
	got.Scopes = append(got.Scopes, "admin")
	got.TokenHash = "hash-1-updated"
	if err := s.Update(ctx, got); err != nil {
		t.Fatalf("unexpected Update error: %v", err)
	}
	updated, err := s.GetByID(ctx, "token-1")
	if err != nil || len(updated.Scopes) != 3 || updated.TokenHash != "hash-1-updated" {
		t.Fatalf("update verification failed: %+v", updated)
	}

	// 7. Revoke single token
	revokeTime := now.Add(10 * time.Minute)
	if err := s.Revoke(ctx, "token-1", revokeTime); err != nil {
		t.Fatalf("unexpected Revoke error: %v", err)
	}
	revoked, _ := s.GetByID(ctx, "token-1")
	if !revoked.Revoked() {
		t.Fatal("expected token to be marked revoked")
	}

	// 8. Delete
	if err := s.Delete(ctx, "token-1"); err != nil {
		t.Fatalf("unexpected Delete error: %v", err)
	}
	if _, err := s.GetByID(ctx, "token-1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound after delete, got %v", err)
	}
}

func TestMemoryStore_RevokeBySubject(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	now := time.Now().UTC()

	_ = s.Create(ctx, &store.TokenRecord{ID: "t1", TokenHash: "h1", Subject: "user-abc", ExpiresAt: now.Add(time.Hour)})
	_ = s.Create(ctx, &store.TokenRecord{ID: "t2", TokenHash: "h2", Subject: "user-abc", ExpiresAt: now.Add(time.Hour)})
	_ = s.Create(ctx, &store.TokenRecord{ID: "t3", TokenHash: "h3", Subject: "user-xyz", ExpiresAt: now.Add(time.Hour)})

	if err := s.RevokeBySubject(ctx, "user-abc", now); err != nil {
		t.Fatalf("unexpected RevokeBySubject error: %v", err)
	}

	t1, _ := s.GetByID(ctx, "t1")
	t2, _ := s.GetByID(ctx, "t2")
	t3, _ := s.GetByID(ctx, "t3")

	if !t1.Revoked() || !t2.Revoked() {
		t.Fatal("expected user-abc tokens to be revoked")
	}
	if t3.Revoked() {
		t.Fatal("user-xyz token should NOT be revoked")
	}
}

func TestMemoryStore_DeleteExpired(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	now := time.Now().UTC()

	_ = s.Create(ctx, &store.TokenRecord{ID: "t-exp", TokenHash: "h-exp", Subject: "user-1", ExpiresAt: now.Add(-time.Hour)})
	_ = s.Create(ctx, &store.TokenRecord{ID: "t-val", TokenHash: "h-val", Subject: "user-1", ExpiresAt: now.Add(time.Hour)})

	count, err := s.DeleteExpired(ctx, now)
	if err != nil {
		t.Fatalf("unexpected DeleteExpired error: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 deleted token, got %d", count)
	}

	if _, err := s.GetByID(ctx, "t-exp"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("expected expired token to be removed")
	}
	if _, err := s.GetByID(ctx, "t-val"); err != nil {
		t.Fatal("expected valid token to remain")
	}
}

func TestMemoryStore_Concurrency(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	var wg sync.WaitGroup

	const goroutines = 50
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			id := time.Now().Format(time.RFC3339Nano) + string(rune(idx))
			hash := "hash-" + id

			_ = s.Create(ctx, &store.TokenRecord{
				ID:        id,
				TokenHash: hash,
				Subject:   "concurrent-user",
				ExpiresAt: time.Now().Add(time.Hour),
			})
			_, _ = s.GetByID(ctx, id)
			_, _ = s.GetByTokenHash(ctx, hash)
			_ = s.Revoke(ctx, id, time.Now())
			_, _ = s.ListBySubject(ctx, "concurrent-user")
		}(i)
	}

	wg.Wait()
}
