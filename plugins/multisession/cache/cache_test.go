package cache_test

import (
	"context"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth/plugins/multisession/cache"
	memcache "github.com/BladiCreator/go-modular-auth/cache/memory"
)

func TestCache_Metadata(t *testing.T) {
	ctx := context.Background()
	c := memcache.New()
	adapter := cache.New(c, 5*time.Minute)

	// Miss initially
	if _, ok := adapter.GetMetadata(ctx, "session_123"); ok {
		t.Fatal("expected cache miss")
	}

	rec := &cache.CachedMetadataRecord{
		SessionID: "session_123",
		UserID:    "user_456",
		Device: cache.CachedDeviceRecord{
			Name: "Pixel 8",
			OS:   "Android",
		},
	}

	// Set
	adapter.SetMetadata(ctx, rec)

	// Hit
	cached, ok := adapter.GetMetadata(ctx, "session_123")
	if !ok {
		t.Fatal("expected cache hit")
	}
	if cached.Device.Name != "Pixel 8" {
		t.Fatalf("unexpected cached value: %+v", cached)
	}

	// Invalidate
	adapter.InvalidateMetadata(ctx, "session_123")
	if _, ok := adapter.GetMetadata(ctx, "session_123"); ok {
		t.Fatal("expected cache miss after invalidation")
	}

	// InvalidateBulk
	adapter.SetMetadata(ctx, &cache.CachedMetadataRecord{SessionID: "s1"})
	adapter.SetMetadata(ctx, &cache.CachedMetadataRecord{SessionID: "s2"})
	adapter.InvalidateBulkMetadata(ctx, []string{"s1", "s2"})

	if _, ok := adapter.GetMetadata(ctx, "s1"); ok {
		t.Fatal("s1 should be invalidated")
	}
	if _, ok := adapter.GetMetadata(ctx, "s2"); ok {
		t.Fatal("s2 should be invalidated")
	}
}

func TestCache_NilGracefulHandling(t *testing.T) {
	ctx := context.Background()
	var adapter *cache.Cache

	if _, ok := adapter.GetMetadata(ctx, "any"); ok {
		t.Fatal("nil cache should gracefully return false")
	}
	adapter.SetMetadata(ctx, &cache.CachedMetadataRecord{})
	adapter.InvalidateMetadata(ctx, "any")
	adapter.InvalidateBulkMetadata(ctx, []string{"any"})
}
