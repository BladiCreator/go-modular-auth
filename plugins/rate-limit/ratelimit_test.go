package ratelimit_test

import (
	"context"
	"errors"
	"testing"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	ratelimit "github.com/BladiCreator/go-modular-auth-rate-limit"
	"github.com/BladiCreator/go-modular-auth-rate-limit/plugins"
	corecache "github.com/BladiCreator/go-modular-auth/cache/memory"
	corememory "github.com/BladiCreator/go-modular-auth/store/memory"
)

func setupTestAuth(t *testing.T, opts ...ratelimit.Option) (*auth.Auth, plugins.RateLimit) {
	t.Helper()
	cStore := corememory.New()
	cCache := corecache.New()

	rlModule := ratelimit.New(opts...)

	a, err := auth.New(auth.Config{
		Store:   cStore,
		Cache:   cCache,
		Plugins: []auth.PluginModule{rlModule},
	})
	if err != nil {
		t.Fatalf("auth.New failed: %v", err)
	}

	rlCap, err := auth.Get[plugins.RateLimit](a)
	if err != nil {
		t.Fatalf("auth.Get[plugins.RateLimit] failed: %v", err)
	}

	return a, rlCap
}

func TestRateLimit_SlidingWindow_LimitAndReset(t *testing.T) {
	ctx := context.Background()
	_, limiter := setupTestAuth(t)

	// ActionSignIn has default limit: 5 per 1 minute
	req := ratelimit.Request{
		Action:   ratelimit.ActionSignIn,
		IP:       "198.51.100.25",
		Identity: "alice@example.com",
	}

	// 1. Check does not consume capacity
	chk, err := limiter.Check(ctx, req)
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}
	if !chk.Allowed || chk.Remaining != 5 {
		t.Fatalf("expected 5 remaining on Check, got %d", chk.Remaining)
	}

	// 2. Consume 5 tokens
	for i := 1; i <= 5; i++ {
		dec, err := limiter.Allow(ctx, req)
		if err != nil {
			t.Fatalf("Allow(%d) failed: %v", i, err)
		}
		if !dec.Allowed {
			t.Fatalf("expected request %d to be allowed", i)
		}
		expectedRemaining := int64(5 - i)
		if dec.Remaining != expectedRemaining {
			t.Errorf("expected remaining %d, got %d", expectedRemaining, dec.Remaining)
		}
	}

	// 3. 6th token must be throttled
	dec, err := limiter.Allow(ctx, req)
	if err != nil {
		t.Fatalf("Allow(6) failed: %v", err)
	}
	if dec.Allowed {
		t.Fatalf("expected 6th request to be denied")
	}
	if dec.RetryAfter <= 0 {
		t.Errorf("expected positive RetryAfter, got %v", dec.RetryAfter)
	}

	// Require returns ErrRateLimitExceeded
	err = limiter.Require(ctx, req)
	if !errors.Is(err, ratelimit.ErrRateLimitExceeded) {
		t.Fatalf("expected ErrRateLimitExceeded, got %v", err)
	}

	// 4. Reset counter (simulating successful login or administrative reset)
	err = limiter.Reset(ctx, req)
	if err != nil {
		t.Fatalf("Reset failed: %v", err)
	}

	// Immediately allowed again
	err = limiter.Require(ctx, req)
	if err != nil {
		t.Fatalf("expected request to be allowed after Reset, got %v", err)
	}
}

func TestRateLimit_TokenBucket_BurstAndRefill(t *testing.T) {
	ctx := context.Background()
	_, limiter := setupTestAuth(t,
		ratelimit.WithPolicy(ratelimit.Policy{
			Action:     "api_token_bucket",
			Algorithm:  ratelimit.AlgorithmTokenBucket,
			Capacity:   3,
			RefillRate: 10.0, // 10 tokens per second = 1 token per 100ms
			KeyType:    ratelimit.KeyTypeIdentity,
		}),
	)

	req := ratelimit.Request{
		Action:   "api_token_bucket",
		Identity: "service_account_1",
	}

	// 1. Consume 3 burst tokens
	for i := 1; i <= 3; i++ {
		dec, err := limiter.Allow(ctx, req)
		if err != nil {
			t.Fatalf("burst Allow(%d) failed: %v", i, err)
		}
		if !dec.Allowed {
			t.Fatalf("expected burst token %d to be allowed", i)
		}
	}

	// 2. 4th immediate request should be throttled
	dec, err := limiter.Allow(ctx, req)
	if err != nil {
		t.Fatalf("Allow failed: %v", err)
	}
	if dec.Allowed {
		t.Fatalf("expected request over capacity to be denied")
	}

	// 3. Sleep 120ms to allow refill of at least 1 token
	time.Sleep(120 * time.Millisecond)

	dec, err = limiter.Allow(ctx, req)
	if err != nil {
		t.Fatalf("Allow after refill failed: %v", err)
	}
	if !dec.Allowed {
		t.Fatalf("expected refilled token to be allowed")
	}
}

func TestRateLimit_CoreHook_Interception(t *testing.T) {
	ctx := context.Background()
	a, _ := setupTestAuth(t,
		ratelimit.WithPolicy(ratelimit.Policy{
			Action:    ratelimit.ActionSignIn,
			Algorithm: ratelimit.AlgorithmSlidingWindow,
			Limit:     2,
			Window:    1 * time.Minute,
			KeyType:   ratelimit.KeyTypeIdentity,
			FailMode:  ratelimit.FailOpen,
		}),
	)

	// Create user
	_, err := a.SignUp(ctx, auth.SignUpInput{
		Email:    "bob@example.com",
		Password: "Password123!",
	})
	if err != nil {
		t.Fatalf("SignUp failed: %v", err)
	}

	// 1. Attempt 1 with bad password -> fails credentials check
	_, err = a.SignIn(ctx, auth.SignInInput{
		Email:    "bob@example.com",
		Password: "WrongPassword!",
	})
	if err == nil {
		t.Fatalf("expected credential failure")
	}

	// 2. Attempt 2 with bad password -> fails credentials check
	_, err = a.SignIn(ctx, auth.SignInInput{
		Email:    "bob@example.com",
		Password: "WrongPassword!",
	})
	if err == nil {
		t.Fatalf("expected credential failure")
	}

	// 3. Attempt 3 -> blocked by BeforeSignIn hook!
	_, err = a.SignIn(ctx, auth.SignInInput{
		Email:    "bob@example.com",
		Password: "Password123!", // Even with correct password, blocked by rate limit!
	})
	if !errors.Is(err, ratelimit.ErrRateLimitExceeded) {
		t.Fatalf("expected BeforeSignIn hook to return ErrRateLimitExceeded, got %v", err)
	}
}

func TestRateLimit_NoCache_InMemoryFallback(t *testing.T) {
	ctx := context.Background()
	cStore := corememory.New()

	rlModule := ratelimit.New(
		ratelimit.WithPolicy(ratelimit.Policy{
			Action:    "local_action",
			Algorithm: ratelimit.AlgorithmSlidingWindow,
			Limit:     2,
			Window:    time.Minute,
			KeyType:   ratelimit.KeyTypeIdentity,
		}),
	)

	// Host initialized with nil Cache
	a, err := auth.New(auth.Config{
		Store:   cStore,
		Cache:   nil,
		Plugins: []auth.PluginModule{rlModule},
	})
	if err != nil {
		t.Fatalf("auth.New failed: %v", err)
	}

	limiter, err := auth.Get[plugins.RateLimit](a)
	if err != nil {
		t.Fatalf("auth.Get failed: %v", err)
	}

	req := ratelimit.Request{
		Action:   "local_action",
		Identity: "user_in_memory",
	}

	if err := limiter.Require(ctx, req); err != nil {
		t.Fatalf("req 1 failed: %v", err)
	}
	if err := limiter.Require(ctx, req); err != nil {
		t.Fatalf("req 2 failed: %v", err)
	}
	if err := limiter.Require(ctx, req); !errors.Is(err, ratelimit.ErrRateLimitExceeded) {
		t.Fatalf("expected ErrRateLimitExceeded on req 3 without cache, got %v", err)
	}
}

func TestRateLimit_DynamicPolicyUpdate(t *testing.T) {
	_, limiter := setupTestAuth(t)

	p, ok := limiter.Policy(ratelimit.ActionSignIn)
	if !ok || p.Limit != 5 {
		t.Fatalf("expected default limit 5 for signin")
	}

	// Update policy dynamically
	p.Limit = 10
	err := limiter.SetPolicy(p)
	if err != nil {
		t.Fatalf("SetPolicy failed: %v", err)
	}

	updated, ok := limiter.Policy(ratelimit.ActionSignIn)
	if !ok || updated.Limit != 10 {
		t.Fatalf("expected updated limit 10 for signin")
	}
}
