package cache_test

import (
	"context"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth/plugins/email-otp/cache"
	cachememory "github.com/BladiCreator/go-modular-auth/cache/memory"
)

func TestCacheLimiter_WithCoreCache(t *testing.T) {
	c := cachememory.New()
	limiter := cache.NewLimiter(c, cache.FailClosed, time.Now)
	ctx := context.Background()

	emailAddr := "limiter@example.com"

	// Cooldown
	allowed, err := limiter.CheckAndSetCooldown(ctx, emailAddr, 100*time.Millisecond)
	if err != nil || !allowed {
		t.Fatalf("first cooldown should be allowed, got allowed=%v, err=%v", allowed, err)
	}

	allowed, err = limiter.CheckAndSetCooldown(ctx, emailAddr, 100*time.Millisecond)
	if err != nil || allowed {
		t.Fatalf("second cooldown check should be rejected, got allowed=%v, err=%v", allowed, err)
	}

	// Rate limit
	for i := 1; i <= 3; i++ {
		ok, err := limiter.CheckRateLimit(ctx, emailAddr, 3, time.Minute)
		if err != nil || !ok {
			t.Fatalf("request %d should be allowed: ok=%v, err=%v", i, ok, err)
		}
	}

	// 4th request must be rejected
	ok, err := limiter.CheckRateLimit(ctx, emailAddr, 3, time.Minute)
	if err != nil || ok {
		t.Fatalf("4th request should exceed limit: ok=%v, err=%v", ok, err)
	}
}
