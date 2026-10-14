package cache

import (
	"context"
	"testing"
	"time"
)

func TestLimiter_RateLimitAndCooldown(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	nowFn := func() time.Time { return now }

	lim := NewLimiter(nil, FailOpen, nowFn)

	phone := "+12025550123"

	// Initial cooldown check
	ok, err := lim.CheckAndSetCooldown(ctx, phone, 1*time.Minute)
	if err != nil || !ok {
		t.Fatalf("expected cooldown check to pass, got ok=%v, err=%v", ok, err)
	}

	// Immediate second attempt within cooldown should be blocked
	ok, err = lim.CheckAndSetCooldown(ctx, phone, 1*time.Minute)
	if err != nil || ok {
		t.Fatalf("expected cooldown to block second request, got ok=%v", ok)
	}

	// Advance time past cooldown
	now = now.Add(61 * time.Second)
	ok, err = lim.CheckAndSetCooldown(ctx, phone, 1*time.Minute)
	if err != nil || !ok {
		t.Fatalf("expected cooldown to pass after time advance, got ok=%v", ok)
	}

	// Rate limit check: max 3 per window
	for i := 1; i <= 3; i++ {
		allowed, err := lim.CheckRateLimit(ctx, phone, 3, 10*time.Minute)
		if err != nil || !allowed {
			t.Fatalf("request %d should be allowed, got %v, err=%v", i, allowed, err)
		}
	}

	// 4th request must be blocked
	allowed, err := lim.CheckRateLimit(ctx, phone, 3, 10*time.Minute)
	if err != nil || allowed {
		t.Fatalf("4th request should exceed limit, got allowed=%v", allowed)
	}
}
