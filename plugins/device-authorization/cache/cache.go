// Package cache provides rate limiting and temporary throttle helpers for device authorization.
// The persistent store remains the authoritative source of truth for all device grant state.
package cache

import (
	"context"
	"sync"
	"time"

	corecache "github.com/BladiCreator/go-modular-auth/cache"
)

// RateLimiter provides rate limiting checks to prevent brute-forcing user codes.
type RateLimiter interface {
	// Allow checks if the request with key is within limit for window.
	Allow(ctx context.Context, key string, limit int64, window time.Duration) (bool, error)
}

type cacheRateLimiter struct {
	counter corecache.Counter
	mu      sync.Mutex
	mem     map[string]*memLimit
}

type memLimit struct {
	count     int64
	expiresAt time.Time
}

// NewRateLimiter creates a RateLimiter wrapping Core's cache adapter or an in-memory fallback.
func NewRateLimiter(c corecache.Cache) RateLimiter {
	var counter corecache.Counter
	if cnt, ok := c.(corecache.Counter); ok {
		counter = cnt
	}
	return &cacheRateLimiter{
		counter: counter,
		mem:     make(map[string]*memLimit),
	}
}

func (l *cacheRateLimiter) Allow(ctx context.Context, key string, limit int64, window time.Duration) (bool, error) {
	namespacedKey := corecache.Key("deviceauth", "ratelimit", key)

	if l.counter != nil {
		val, err := l.counter.Increment(ctx, namespacedKey, 1, window)
		if err != nil {
			return true, nil // Fail open on cache errors, store provides second line of defense
		}
		return val <= limit, nil
	}

	// In-memory fallback
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	entry, ok := l.mem[namespacedKey]
	if !ok || now.After(entry.expiresAt) {
		l.mem[namespacedKey] = &memLimit{
			count:     1,
			expiresAt: now.Add(window),
		}
		return true, nil
	}

	entry.count++
	return entry.count <= limit, nil
}
