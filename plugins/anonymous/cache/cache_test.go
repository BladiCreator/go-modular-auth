package cache_test

import (
	"context"
	"sync"
	"testing"
	"time"

	corecache "github.com/BladiCreator/go-modular-auth/cache"
	"github.com/BladiCreator/go-modular-auth/plugins/anonymous/cache"
)

type mockCoreCache struct {
	mu   sync.Mutex
	data map[string]any
}

func newMockCoreCache() *mockCoreCache {
	return &mockCoreCache{data: make(map[string]any)}
}

func (m *mockCoreCache) Get(ctx context.Context, key string, val any) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.data[key]
	if !ok {
		return corecache.ErrMiss
	}
	if target, ok := val.(*cache.CachedIdentity); ok {
		if id, ok := v.(cache.CachedIdentity); ok {
			*target = id
			return nil
		}
	}
	return nil
}

func (m *mockCoreCache) Set(ctx context.Context, key string, val any, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if id, ok := val.(*cache.CachedIdentity); ok {
		m.data[key] = *id
	} else if id, ok := val.(cache.CachedIdentity); ok {
		m.data[key] = id
	}
	return nil
}

func (m *mockCoreCache) Delete(ctx context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, key)
	return nil
}

func TestCache_Identity(t *testing.T) {
	ctx := context.Background()
	mock := newMockCoreCache()
	c := cache.New(mock)

	now := time.Now().UTC()
	ident := &cache.CachedIdentity{
		ID:        "anon-1",
		UserID:    "user-1",
		ExpiresAt: now.Add(time.Hour),
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := c.SetIdentity(ctx, ident, time.Hour); err != nil {
		t.Fatalf("SetIdentity failed: %v", err)
	}

	got, err := c.GetIdentity(ctx, "user-1")
	if err != nil {
		t.Fatalf("GetIdentity failed: %v", err)
	}
	if got.ID != "anon-1" || got.UserID != "user-1" {
		t.Fatalf("unexpected cached identity: %+v", got)
	}

	if err := c.DeleteIdentity(ctx, "user-1"); err != nil {
		t.Fatalf("DeleteIdentity failed: %v", err)
	}

	if _, err := c.GetIdentity(ctx, "user-1"); err != corecache.ErrMiss {
		t.Fatalf("expected ErrMiss after delete, got %v", err)
	}
}

func TestCache_NilCore(t *testing.T) {
	ctx := context.Background()
	c := cache.New(nil)

	if c.Available() {
		t.Fatal("expected Available to be false for nil core cache")
	}

	// Should not panic or fail
	_ = c.SetIdentity(ctx, &cache.CachedIdentity{UserID: "u1"}, time.Hour)
	if _, err := c.GetIdentity(ctx, "u1"); err != corecache.ErrMiss {
		t.Fatalf("expected ErrMiss on nil cache, got %v", err)
	}
	_ = c.DeleteIdentity(ctx, "u1")
}
