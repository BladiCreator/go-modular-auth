package cache

import (
	"context"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth-apikeys/store"
	corecache "github.com/BladiCreator/go-modular-auth/cache/memory"
)

func TestCacheLimiter_KeyCachingAndInvalidation(t *testing.T) {
	ctx := context.Background()
	coreMem := corecache.New()
	limiter := NewLimiter(coreMem, 5, 1*time.Minute, 5*time.Minute)

	key := &store.APIKey{
		ID:      "ak_test",
		Name:    "Cached Key",
		KeyHash: "sha256_mock_hash",
	}

	// Initial Get should miss
	_, err := limiter.GetKey(ctx, "sha256_mock_hash")
	if err == nil {
		t.Fatalf("expected cache miss initially")
	}

	// SetKey
	if err := limiter.SetKey(ctx, key); err != nil {
		t.Fatalf("SetKey failed: %v", err)
	}

	// GetKey should hit
	cached, err := limiter.GetKey(ctx, "sha256_mock_hash")
	if err != nil {
		t.Fatalf("GetKey failed after SetKey: %v", err)
	}
	if cached.ID != "ak_test" {
		t.Errorf("expected cached ID ak_test, got %s", cached.ID)
	}

	// Invalidate by ID and hash
	if err := limiter.Invalidate(ctx, "ak_test", "sha256_mock_hash"); err != nil {
		t.Fatalf("Invalidate failed: %v", err)
	}

	// GetKey should miss again
	_, err = limiter.GetKey(ctx, "sha256_mock_hash")
	if err == nil {
		t.Fatalf("expected cache miss after Invalidate")
	}
}

func TestCacheLimiter_BruteForceMitigation(t *testing.T) {
	ctx := context.Background()
	coreMem := corecache.New()
	limiter := NewLimiter(coreMem, 3, 1*time.Minute, 5*time.Minute)

	ip := "192.168.1.50"

	// Initial check: not blocked
	blocked, err := limiter.CheckRateLimit(ctx, ip)
	if err != nil || blocked {
		t.Fatalf("expected not blocked initially, got blocked=%v, err=%v", blocked, err)
	}

	// Record 2 failures
	_ = limiter.RecordFailure(ctx, ip)
	_ = limiter.RecordFailure(ctx, ip)

	blocked, _ = limiter.CheckRateLimit(ctx, ip)
	if blocked {
		t.Fatalf("should not be blocked after 2 failures (limit is 3)")
	}

	// Record 3rd failure (hits threshold)
	_ = limiter.RecordFailure(ctx, ip)

	blocked, _ = limiter.CheckRateLimit(ctx, ip)
	if !blocked {
		t.Fatalf("expected client to be blocked after 3 failures")
	}

	// Different IP should still be allowed
	blockedOther, _ := limiter.CheckRateLimit(ctx, "10.0.0.1")
	if blockedOther {
		t.Fatalf("different client IP should not be blocked")
	}
}

func TestCacheLimiter_LocalFallbackWhenNoCache(t *testing.T) {
	ctx := context.Background()
	limiter := NewLimiter(nil, 2, 100*time.Millisecond, 1*time.Minute)

	ip := "127.0.0.1"
	_ = limiter.RecordFailure(ctx, ip)
	blocked, _ := limiter.CheckRateLimit(ctx, ip)
	if blocked {
		t.Fatalf("should not be blocked at 1 attempt")
	}

	_ = limiter.RecordFailure(ctx, ip)
	blocked, _ = limiter.CheckRateLimit(ctx, ip)
	if !blocked {
		t.Fatalf("should be blocked at 2 attempts")
	}

	// Sleep past window
	time.Sleep(150 * time.Millisecond)
	blocked, _ = limiter.CheckRateLimit(ctx, ip)
	if blocked {
		t.Fatalf("should not be blocked after window expires")
	}
}
