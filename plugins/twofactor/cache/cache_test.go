package cache_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth-twofactor/cache"
	corecache "github.com/BladiCreator/go-modular-auth/cache"
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
	switch ptr := val.(type) {
	case *cache.ChallengeCacheEntry:
		if entry, ok := v.(cache.ChallengeCacheEntry); ok {
			*ptr = entry
			return nil
		}
	case *bool:
		if b, ok := v.(bool); ok {
			*ptr = b
			return nil
		}
	}
	return nil
}

func (m *mockCoreCache) Set(ctx context.Context, key string, val any, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	switch v := val.(type) {
	case *cache.ChallengeCacheEntry:
		m.data[key] = *v
	case bool:
		m.data[key] = v
	default:
		m.data[key] = val
	}
	return nil
}

func (m *mockCoreCache) Delete(ctx context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, key)
	return nil
}

func TestCache_Challenges(t *testing.T) {
	ctx := context.Background()
	mock := newMockCoreCache()
	c := cache.New(mock)

	now := time.Now().UTC()
	entry := &cache.ChallengeCacheEntry{
		ID:        "ch1",
		UserID:    "u1",
		ExpiresAt: now.Add(5 * time.Minute),
		CreatedAt: now,
	}

	if err := c.SetChallenge(ctx, entry, 5*time.Minute); err != nil {
		t.Fatalf("SetChallenge failed: %v", err)
	}

	got, err := c.GetChallenge(ctx, "ch1")
	if err != nil {
		t.Fatalf("GetChallenge failed: %v", err)
	}
	if got.ID != "ch1" || got.UserID != "u1" {
		t.Errorf("unexpected challenge cached: %+v", got)
	}

	if err := c.DeleteChallenge(ctx, "ch1"); err != nil {
		t.Fatalf("DeleteChallenge failed: %v", err)
	}

	if _, err := c.GetChallenge(ctx, "ch1"); err != corecache.ErrMiss {
		t.Errorf("expected ErrMiss after delete, got %v", err)
	}
}

func TestCache_ReplayTracking(t *testing.T) {
	ctx := context.Background()
	mock := newMockCoreCache()
	c := cache.New(mock)

	used, err := c.IsStepUsed(ctx, "f1", 100)
	if err != nil || used {
		t.Fatalf("expected unused, got %v, err=%v", used, err)
	}

	if err := c.MarkStepUsed(ctx, "f1", 100, time.Minute); err != nil {
		t.Fatalf("MarkStepUsed failed: %v", err)
	}

	usedAfter, err := c.IsStepUsed(ctx, "f1", 100)
	if err != nil || !usedAfter {
		t.Fatalf("expected used, got %v, err=%v", usedAfter, err)
	}
}

func TestCache_NilCoreDegraded(t *testing.T) {
	ctx := context.Background()
	c := cache.New(nil)

	if c.Available() {
		t.Error("expected Available to be false for nil core cache")
	}

	// Operations should not panic
	_ = c.SetChallenge(ctx, &cache.ChallengeCacheEntry{ID: "ch1"}, time.Minute)
	if _, err := c.GetChallenge(ctx, "ch1"); err != corecache.ErrMiss {
		t.Errorf("expected ErrMiss on nil core cache, got %v", err)
	}
	_ = c.DeleteChallenge(ctx, "ch1")
}
