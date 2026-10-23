package ratelimit

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/BladiCreator/go-modular-auth/cache"
)

type limiterEngine struct {
	cache cache.Cache
	now   func() time.Time

	// In-memory fallbacks when distributed cache is nil or in local test mode
	mu          sync.Mutex
	memWindows  map[string][]time.Time
	memBuckets  map[string]*tokenBucketState
	lastCleaned time.Time
}

type tokenBucketState struct {
	Tokens     float64   `json:"tokens"`
	LastRefill time.Time `json:"last_refill"`
}

func newEngine(c cache.Cache, now func() time.Time) *limiterEngine {
	if now == nil {
		now = time.Now
	}
	return &limiterEngine{
		cache:       c,
		now:         now,
		memWindows:  make(map[string][]time.Time),
		memBuckets:  make(map[string]*tokenBucketState),
		lastCleaned: now(),
	}
}

func (e *limiterEngine) evaluate(ctx context.Context, key string, p Policy, consume bool) (*Decision, error) {
	switch p.Algorithm {
	case AlgorithmTokenBucket:
		return e.evaluateTokenBucket(ctx, key, p, consume)
	case AlgorithmSlidingWindow:
		fallthrough
	default:
		return e.evaluateSlidingWindow(ctx, key, p, consume)
	}
}

func (e *limiterEngine) evaluateSlidingWindow(ctx context.Context, key string, p Policy, consume bool) (*Decision, error) {
	now := e.now().UTC()
	window := p.Window
	if window <= 0 {
		window = time.Minute
	}
	limit := p.Limit
	if limit <= 0 {
		limit = 1
	}

	// 1. If Cache Adapter with Counter capability is available, use distributed sub-window counters
	if e.cache != nil {
		if counter, ok := e.cache.(cache.Counter); ok {
			decision, err := e.distributedSlidingWindow(ctx, counter, key, p, consume, now)
			if err != nil {
				if p.FailMode == FailClosed {
					return nil, ErrRateLimiterUnavailable
				}
				// FailOpen: allow on cache error
				return &Decision{
					Allowed:    true,
					Remaining:  limit,
					Limit:      limit,
					ResetAfter: window,
					Action:     p.Action,
					Key:        key,
				}, nil
			}
			return decision, nil
		}
	}

	// 2. In-Memory thread-safe sliding window implementation
	e.mu.Lock()
	defer e.mu.Unlock()

	e.cleanupExpiredLocked(now)

	cutoff := now.Add(-window)
	timestamps := e.memWindows[key]

	// Purge timestamps older than window
	validIdx := 0
	for i, ts := range timestamps {
		if !ts.Before(cutoff) {
			validIdx = i
			break
		}
		if i == len(timestamps)-1 {
			validIdx = len(timestamps)
		}
	}
	active := timestamps[validIdx:]

	currentCount := int64(len(active))
	if currentCount >= limit {
		// Limit reached
		oldest := now
		if len(active) > 0 {
			oldest = active[0]
		}
		retryAfter := window - now.Sub(oldest)
		if retryAfter < 0 {
			retryAfter = time.Second
		}

		return &Decision{
			Allowed:    false,
			Remaining:  0,
			Limit:      limit,
			ResetAfter: retryAfter,
			RetryAfter: retryAfter,
			Action:     p.Action,
			Key:        key,
		}, nil
	}

	if consume {
		active = append(active, now)
		e.memWindows[key] = active
		currentCount++
	}

	remaining := limit - currentCount
	if remaining < 0 {
		remaining = 0
	}

	return &Decision{
		Allowed:    true,
		Remaining:  remaining,
		Limit:      limit,
		ResetAfter: window,
		Action:     p.Action,
		Key:        key,
	}, nil
}

func (e *limiterEngine) distributedSlidingWindow(ctx context.Context, counter cache.Counter, key string, p Policy, consume bool, now time.Time) (*Decision, error) {
	windowSec := int64(p.Window.Seconds())
	if windowSec <= 0 {
		windowSec = 60
	}

	currentBucket := now.Unix() / windowSec
	prevBucket := currentBucket - 1
	timeInBucket := now.Unix() % windowSec
	proportion := float64(timeInBucket) / float64(windowSec)

	currKey := fmt.Sprintf("%s:b:%d", key, currentBucket)
	prevKey := fmt.Sprintf("%s:b:%d", key, prevBucket)
	ttl := p.Window * 2

	var prevVal int64
	_ = e.cache.Get(ctx, prevKey, &prevVal)

	var currVal int64
	if consume {
		var err error
		currVal, err = counter.Increment(ctx, currKey, 1, ttl)
		if err != nil {
			return nil, err
		}
	} else {
		_ = e.cache.Get(ctx, currKey, &currVal)
	}

	estimated := float64(prevVal)*(1.0-proportion) + float64(currVal)
	if estimated > float64(p.Limit) {
		retryAfter := time.Duration(float64(windowSec)-float64(timeInBucket)) * time.Second
		return &Decision{
			Allowed:    false,
			Remaining:  0,
			Limit:      p.Limit,
			ResetAfter: retryAfter,
			RetryAfter: retryAfter,
			Action:     p.Action,
			Key:        key,
		}, nil
	}

	rem := p.Limit - int64(math.Ceil(estimated))
	if rem < 0 {
		rem = 0
	}

	return &Decision{
		Allowed:    true,
		Remaining:  rem,
		Limit:      p.Limit,
		ResetAfter: p.Window,
		Action:     p.Action,
		Key:        key,
	}, nil
}

func (e *limiterEngine) evaluateTokenBucket(ctx context.Context, key string, p Policy, consume bool) (*Decision, error) {
	now := e.now().UTC()
	capacity := p.Capacity
	if capacity <= 0 {
		capacity = 10
	}
	refillRate := p.RefillRate
	if refillRate <= 0 {
		refillRate = 1.0 // 1 token per second
	}

	// Synchronize access to prevent concurrent read-modify-write data races
	e.mu.Lock()
	defer e.mu.Unlock()

	// 1. If Cache is available, load and store state in cache
	if e.cache != nil {
		decision, err := e.distributedTokenBucket(ctx, key, p, capacity, refillRate, consume, now)
		if err != nil {
			if p.FailMode == FailClosed {
				return nil, ErrRateLimiterUnavailable
			}
			return &Decision{
				Allowed:    true,
				Remaining:  capacity,
				Limit:      capacity,
				ResetAfter: time.Second,
				Action:     p.Action,
				Key:        key,
			}, nil
		}
		return decision, nil
	}

	// 2. In-memory token bucket implementation

	state, ok := e.memBuckets[key]
	if !ok {
		state = &tokenBucketState{
			Tokens:     float64(capacity),
			LastRefill: now,
		}
		e.memBuckets[key] = state
	}

	// Refill tokens
	elapsed := now.Sub(state.LastRefill).Seconds()
	state.Tokens = math.Min(float64(capacity), state.Tokens+elapsed*refillRate)
	state.LastRefill = now

	if state.Tokens < 1.0 {
		missing := 1.0 - state.Tokens
		retryAfter := time.Duration(missing/refillRate*float64(time.Second)) + 10*time.Millisecond

		return &Decision{
			Allowed:    false,
			Remaining:  0,
			Limit:      capacity,
			ResetAfter: retryAfter,
			RetryAfter: retryAfter,
			Action:     p.Action,
			Key:        key,
		}, nil
	}

	if consume {
		state.Tokens -= 1.0
	}

	return &Decision{
		Allowed:    true,
		Remaining:  int64(state.Tokens),
		Limit:      capacity,
		ResetAfter: time.Duration((float64(capacity)-state.Tokens)/refillRate) * time.Second,
		Action:     p.Action,
		Key:        key,
	}, nil
}

func (e *limiterEngine) distributedTokenBucket(ctx context.Context, key string, p Policy, capacity int64, refillRate float64, consume bool, now time.Time) (*Decision, error) {
	var state tokenBucketState
	err := e.cache.Get(ctx, key, &state)
	if err != nil {
		if errors.Is(err, cache.ErrMiss) {
			state = tokenBucketState{
				Tokens:     float64(capacity),
				LastRefill: now,
			}
		} else {
			return nil, err
		}
	}

	elapsed := now.Sub(state.LastRefill).Seconds()
	if elapsed > 0 {
		state.Tokens = math.Min(float64(capacity), state.Tokens+elapsed*refillRate)
		state.LastRefill = now
	}

	ttl := time.Duration(float64(capacity)/refillRate*2)*time.Second + time.Minute

	if state.Tokens < 1.0 {
		missing := 1.0 - state.Tokens
		retryAfter := time.Duration(missing/refillRate*float64(time.Second)) + 10*time.Millisecond
		return &Decision{
			Allowed:    false,
			Remaining:  0,
			Limit:      capacity,
			ResetAfter: retryAfter,
			RetryAfter: retryAfter,
			Action:     p.Action,
			Key:        key,
		}, nil
	}

	if consume {
		state.Tokens -= 1.0
		if err := e.cache.Set(ctx, key, state, ttl); err != nil {
			return nil, err
		}
	}

	return &Decision{
		Allowed:    true,
		Remaining:  int64(state.Tokens),
		Limit:      capacity,
		ResetAfter: time.Duration((float64(capacity)-state.Tokens)/refillRate) * time.Second,
		Action:     p.Action,
		Key:        key,
	}, nil
}

func (e *limiterEngine) reset(ctx context.Context, key string, window time.Duration) error {
	if e.cache != nil {
		_ = e.cache.Delete(ctx, key)
		if window <= 0 {
			window = time.Minute
		}
		windowSec := int64(window.Seconds())
		if windowSec <= 0 {
			windowSec = 60
		}
		now := e.now().UTC()
		currentBucket := now.Unix() / windowSec
		_ = e.cache.Delete(ctx, fmt.Sprintf("%s:b:%d", key, currentBucket))
		_ = e.cache.Delete(ctx, fmt.Sprintf("%s:b:%d", key, currentBucket-1))
	}

	e.mu.Lock()
	delete(e.memWindows, key)
	delete(e.memBuckets, key)
	e.mu.Unlock()

	return nil
}

func (e *limiterEngine) cleanupExpiredLocked(now time.Time) {
	if now.Sub(e.lastCleaned) < 5*time.Minute {
		return
	}
	e.lastCleaned = now

	// Purge stale memory window entries
	cutoff := now.Add(-1 * time.Hour)
	for k, timestamps := range e.memWindows {
		if len(timestamps) == 0 || timestamps[len(timestamps)-1].Before(cutoff) {
			delete(e.memWindows, k)
		}
	}
	// Purge stale memory bucket entries
	for k, bucket := range e.memBuckets {
		if bucket.LastRefill.Before(cutoff) {
			delete(e.memBuckets, k)
		}
	}
}
