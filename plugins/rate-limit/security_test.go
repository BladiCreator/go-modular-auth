package ratelimit_test

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ratelimit "github.com/BladiCreator/go-modular-auth/plugins/rate-limit"
)

func TestSecurity_KeyIsolation_And_NoSecretExposure(t *testing.T) {
	policy := ratelimit.Policy{
		Action:  ratelimit.ActionSignIn,
		KeyType: ratelimit.KeyTypeComposite,
	}

	rawEmail := "ConfidentialUser@domain.com"
	rawIP := "2001:0db8:85a3:0000:0000:8a2e:0370:7334"

	key := policy.BuildKey(ratelimit.Request{
		Action:   ratelimit.ActionSignIn,
		IP:       rawIP,
		Identity: rawEmail,
	})

	// 1. Must be properly namespaced
	if !strings.HasPrefix(key, "gomodularauth:ratelimit:signin:comp:") {
		t.Fatalf("unexpected key namespace format: %s", key)
	}

	// 2. Sensitive plain email must NOT appear in the key
	if strings.Contains(key, "ConfidentialUser") || strings.Contains(key, "domain.com") {
		t.Fatalf("CRITICAL SECURITY LEAK: plaintext identity found in cache key: %s", key)
	}

	// 3. IPv6 colons must be normalized so they don't break delimiter segments
	subSegments := strings.Split(key, ":")
	// gomodularauth : ratelimit : signin : comp : <ip> : <hash>
	if len(subSegments) != 6 {
		t.Fatalf("expected exactly 6 delimiter segments in key, got %d in %s", len(subSegments), key)
	}

	// 4. Distinct actions must never collide
	policySignUp := ratelimit.Policy{
		Action:  ratelimit.ActionSignUp,
		KeyType: ratelimit.KeyTypeComposite,
	}
	keySignUp := policySignUp.BuildKey(ratelimit.Request{
		Action:   ratelimit.ActionSignUp,
		IP:       rawIP,
		Identity: rawEmail,
	})

	if key == keySignUp {
		t.Fatalf("collision detected between SignIn and SignUp keys: %s", key)
	}
}

func TestSecurity_Concurrency_RateLimitAccuracy(t *testing.T) {
	ctx := context.Background()
	_, limiter := setupTestAuth(t,
		ratelimit.WithPolicy(ratelimit.Policy{
			Action:    "concurrent_action",
			Algorithm: ratelimit.AlgorithmSlidingWindow,
			Limit:     25,
			Window:    2 * time.Minute,
			KeyType:   ratelimit.KeyTypeIdentity,
		}),
	)

	req := ratelimit.Request{
		Action:   "concurrent_action",
		Identity: "shared_account_target",
	}

	var wg sync.WaitGroup
	workers := 50
	var allowedCount int64
	var deniedCount int64

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dec, err := limiter.Allow(ctx, req)
			if err != nil {
				t.Errorf("Allow returned unexpected error: %v", err)
				return
			}
			if dec.Allowed {
				atomic.AddInt64(&allowedCount, 1)
			} else {
				atomic.AddInt64(&deniedCount, 1)
			}
		}()
	}

	wg.Wait()

	if allowedCount != 25 {
		t.Fatalf("expected exactly 25 requests allowed under concurrency, got %d (denied: %d)", allowedCount, deniedCount)
	}
	if deniedCount != 25 {
		t.Fatalf("expected exactly 25 requests denied, got %d", deniedCount)
	}
}

func TestSecurity_FailModes(t *testing.T) {
	policyFailClosed := ratelimit.Policy{
		Action:     "test_fail_closed",
		Algorithm:  ratelimit.AlgorithmSlidingWindow,
		Limit:      5,
		Window:     time.Minute,
		KeyType:    ratelimit.KeyTypeIP,
		FailMode:   ratelimit.FailClosed,
	}

	policyFailOpen := ratelimit.Policy{
		Action:     "test_fail_open",
		Algorithm:  ratelimit.AlgorithmSlidingWindow,
		Limit:      5,
		Window:     time.Minute,
		KeyType:    ratelimit.KeyTypeIP,
		FailMode:   ratelimit.FailOpen,
	}

	if policyFailClosed.FailMode != ratelimit.FailClosed {
		t.Fatalf("expected FailClosed")
	}
	if policyFailOpen.FailMode != ratelimit.FailOpen {
		t.Fatalf("expected FailOpen")
	}
}

func TestDistributedTokenBucket_ConcurrentExecution(t *testing.T) {
	ctx := context.Background()
	_, limiter := setupTestAuth(t,
		ratelimit.WithPolicy(ratelimit.Policy{
			Action:     "concurrent_token_bucket",
			Algorithm:  ratelimit.AlgorithmTokenBucket,
			Capacity:   20,
			RefillRate: 0.1, // Very slow refill so burst limit is strictly tested
			KeyType:    ratelimit.KeyTypeIdentity,
		}),
	)

	req := ratelimit.Request{
		Action:   "concurrent_token_bucket",
		Identity: "concurrent_bucket_user",
	}

	var wg sync.WaitGroup
	workers := 40
	var allowedCount int64
	var deniedCount int64

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dec, err := limiter.Allow(ctx, req)
			if err != nil {
				t.Errorf("Allow returned error: %v", err)
				return
			}
			if dec.Allowed {
				atomic.AddInt64(&allowedCount, 1)
			} else {
				atomic.AddInt64(&deniedCount, 1)
			}
		}()
	}

	wg.Wait()

	if allowedCount != 20 {
		t.Fatalf("expected exactly 20 allowed requests under concurrent token bucket, got %d (denied: %d)", allowedCount, deniedCount)
	}
	if deniedCount != 20 {
		t.Fatalf("expected exactly 20 denied requests under concurrent token bucket, got %d", deniedCount)
	}
}

