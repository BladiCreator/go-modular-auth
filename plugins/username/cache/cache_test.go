package cache_test

import (
	"context"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth/plugins/username/cache"
	memcache "github.com/BladiCreator/go-modular-auth/cache/memory"
)

func TestSemanticCache(t *testing.T) {
	ctx := context.Background()
	underlying := memcache.New()
	c := cache.New(underlying, time.Minute)

	rec := &cache.CachedRecord{
		UserID:     "user-100",
		Username:   "BobBuilder",
		Normalized: "bobbuilder",
	}

	// 1. Initial miss
	if _, ok := c.GetByNormalized(ctx, "bobbuilder"); ok {
		t.Fatal("expected miss")
	}
	if _, ok := c.GetByUserID(ctx, "user-100"); ok {
		t.Fatal("expected miss")
	}

	// 2. Set
	c.Set(ctx, rec)

	// 3. Hit on both keys
	gotNorm, ok := c.GetByNormalized(ctx, "bobbuilder")
	if !ok || gotNorm.Username != "BobBuilder" {
		t.Fatalf("expected hit on normalized key, got %+v", gotNorm)
	}

	gotUser, ok := c.GetByUserID(ctx, "user-100")
	if !ok || gotUser.Username != "BobBuilder" {
		t.Fatalf("expected hit on user key, got %+v", gotUser)
	}

	// 4. Invalidate
	c.Invalidate(ctx, "bobbuilder", "user-100")
	if _, ok := c.GetByNormalized(ctx, "bobbuilder"); ok {
		t.Fatal("expected miss after invalidation")
	}
	if _, ok := c.GetByUserID(ctx, "user-100"); ok {
		t.Fatal("expected miss after invalidation")
	}

	// 5. Nil Cache gracefully handles operations without crashing
	var nilCache *cache.Cache
	if _, ok := nilCache.GetByNormalized(ctx, "test"); ok {
		t.Fatal("expected false on nil cache")
	}
	nilCache.Set(ctx, rec)
	nilCache.Invalidate(ctx, "test", "user-100")
}
