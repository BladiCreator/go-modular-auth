package cache

import (
	"context"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth-phone/store"
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

func TestPhoneCache_SetGetInvalidate(t *testing.T) {
	ctx := context.Background()

	// When underlying cache is nil, operations should be safe no-ops / misses
	pc := NewPhoneCache(nil, 5*time.Minute)
	_, err := pc.GetByUserID(ctx, "u1")
	if err == nil {
		t.Fatal("expected miss on nil cache")
	}

	rec := &store.PhoneRecord{
		ID:          "p1",
		UserID:      "u1",
		PhoneNumber: "+12025550123",
		Verified:    true,
	}
	if err := pc.SetByUserID(ctx, "u1", rec); err != nil {
		t.Fatalf("unexpected error setting nil cache: %v", err)
	}

	pc.Invalidate(ctx, "u1", "+12025550123")
}
