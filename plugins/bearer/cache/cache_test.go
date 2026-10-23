package cache_test

import (
	"context"
	"errors"
	"testing"
	"time"

	corecache "github.com/BladiCreator/go-modular-auth/cache"
	corecpmem "github.com/BladiCreator/go-modular-auth/cache/memory"
	"github.com/BladiCreator/go-modular-auth/plugins/bearer/cache"
)

func TestCache_SetAndGet(t *testing.T) {
	ctx := context.Background()
	coreMem := corecpmem.New()
	c := cache.New(coreMem)

	rec := &cache.CachedToken{
		ID:            "token-123",
		TokenHash:     "hash-456",
		Subject:       "user-789",
		PrincipalType: "user",
		Scopes:        []string{"read"},
		ExpiresAt:     time.Now().Add(time.Hour),
	}

	// 1. Initially miss
	if _, err := c.GetByHash(ctx, "hash-456"); !errors.Is(err, corecache.ErrMiss) {
		t.Fatalf("expected ErrMiss, got %v", err)
	}

	// 2. Set
	if err := c.Set(ctx, rec, 5*time.Minute); err != nil {
		t.Fatalf("unexpected Set error: %v", err)
	}

	// 3. GetByHash
	got, err := c.GetByHash(ctx, "hash-456")
	if err != nil {
		t.Fatalf("unexpected GetByHash error: %v", err)
	}
	if got.ID != "token-123" || got.Subject != "user-789" {
		t.Fatalf("unexpected cached content: %+v", got)
	}

	// 4. DeleteByHash
	if err := c.DeleteByHash(ctx, "hash-456"); err != nil {
		t.Fatalf("unexpected DeleteByHash error: %v", err)
	}
	if _, err := c.GetByHash(ctx, "hash-456"); !errors.Is(err, corecache.ErrMiss) {
		t.Fatalf("expected ErrMiss after DeleteByHash, got %v", err)
	}

	// 5. Test DeleteByID
	_ = c.Set(ctx, rec, 5*time.Minute)
	if err := c.DeleteByID(ctx, "token-123"); err != nil {
		t.Fatalf("unexpected DeleteByID error: %v", err)
	}
	if _, err := c.GetByHash(ctx, "hash-456"); !errors.Is(err, corecache.ErrMiss) {
		t.Fatalf("expected ErrMiss after DeleteByID, got %v", err)
	}
}

func TestCache_NilCoreDegradation(t *testing.T) {
	ctx := context.Background()
	c := cache.New(nil)

	if c.Available() {
		t.Fatal("expected Available() to be false for nil core cache")
	}

	if err := c.Set(ctx, &cache.CachedToken{ID: "t"}, time.Minute); err != nil {
		t.Fatalf("expected nil error on degraded Set, got %v", err)
	}

	if _, err := c.GetByHash(ctx, "h"); !errors.Is(err, corecache.ErrMiss) {
		t.Fatalf("expected ErrMiss on degraded Get, got %v", err)
	}

	if err := c.DeleteByHash(ctx, "h"); err != nil {
		t.Fatalf("expected nil error on degraded Delete, got %v", err)
	}
}
