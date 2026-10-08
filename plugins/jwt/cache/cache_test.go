package cache

import (
	"context"
	"testing"
	"time"

	corecache "github.com/BladiCreator/go-modular-auth/cache"
)

type mockCoreCache struct {
	items map[string]any
}

func newMockCoreCache() *mockCoreCache {
	return &mockCoreCache{items: make(map[string]any)}
}

func (m *mockCoreCache) Get(_ context.Context, key string, value any) error {
	v, exists := m.items[key]
	if !exists {
		return corecache.ErrMiss
	}
	switch target := value.(type) {
	case *bool:
		if b, ok := v.(bool); ok {
			*target = b
		} else if bp, ok := v.(*bool); ok {
			*target = *bp
		}
	case *int64:
		if i, ok := v.(int64); ok {
			*target = i
		} else if ip, ok := v.(*int64); ok {
			*target = *ip
		}
	}
	return nil
}

func (m *mockCoreCache) Set(_ context.Context, key string, value any, _ time.Duration) error {
	m.items[key] = value
	return nil
}

func (m *mockCoreCache) Delete(_ context.Context, key string) error {
	delete(m.items, key)
	return nil
}

func TestRevocationCache(t *testing.T) {
	mock := newMockCoreCache()
	rc := New(mock)
	ctx := context.Background()

	// 1. Token revocation
	revoked, found := rc.IsTokenRevoked(ctx, "jti-123")
	if found || revoked {
		t.Fatalf("expected cache miss, got found=%v, revoked=%v", found, revoked)
	}

	if err := rc.SetTokenRevoked(ctx, "jti-123", time.Minute); err != nil {
		t.Fatalf("SetTokenRevoked failed: %v", err)
	}

	revoked, found = rc.IsTokenRevoked(ctx, "jti-123")
	if !found || !revoked {
		t.Fatalf("expected cache hit revoked, got found=%v, revoked=%v", found, revoked)
	}

	// 2. Subject cutoff
	now := time.Now().Truncate(time.Second)
	cutoff, found := rc.GetSubjectCutoff(ctx, "user-456")
	if found {
		t.Fatal("expected miss for subject cutoff")
	}

	if err := rc.SetSubjectCutoff(ctx, "user-456", now, time.Minute); err != nil {
		t.Fatalf("SetSubjectCutoff failed: %v", err)
	}

	cutoff, found = rc.GetSubjectCutoff(ctx, "user-456")
	if !found || !cutoff.Equal(now) {
		t.Fatalf("expected cutoff %v, got %v (found=%v)", now, cutoff, found)
	}
}
