// Package cache provides rate limiting and throttling abstractions for the magic link plugin.
package cache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"

	corecache "github.com/BladiCreator/go-modular-auth/cache"
)

// RateLimiter enforces rate limiting and cooldown rules for magic link requests.
type RateLimiter interface {
	// CheckRateLimit verifies if an email is permitted to request a magic link.
	// Returns true if allowed, false if rate limited.
	CheckRateLimit(ctx context.Context, email string, maxRequests int, window time.Duration) (bool, error)

	// CheckAndSetCooldown verifies if cooldown is active, and if not sets it.
	// Returns true if allowed, false if cooldown is active.
	CheckAndSetCooldown(ctx context.Context, email string, cooldown time.Duration) (bool, error)
}

// Limiter is a cache-backed rate limiter implementation.
type Limiter struct {
	cache corecache.Cache

	// Fallback in-memory state when no cache is configured
	mu        sync.Mutex
	memCounts map[string]entry
	now       func() time.Time
}

type entry struct {
	count     int
	expiresAt time.Time
}

// NewLimiter creates a new Limiter backed by an optional cache.
func NewLimiter(c corecache.Cache, now func() time.Time) *Limiter {
	if now == nil {
		now = time.Now
	}
	return &Limiter{
		cache:     c,
		memCounts: make(map[string]entry),
		now:       now,
	}
}

// HashIdentifier produces an opaque hash of the identifier to avoid storing plaintext emails in cache keys.
func HashIdentifier(identifier string) string {
	sum := sha256.Sum256([]byte(identifier))
	return hex.EncodeToString(sum[:])
}

// CheckRateLimit checks whether requests within the given window exceeded maxRequests.
func (l *Limiter) CheckRateLimit(ctx context.Context, email string, maxRequests int, window time.Duration) (bool, error) {
	if maxRequests <= 0 || window <= 0 {
		return true, nil
	}

	key := corecache.Key("magiclink", "ratelimit", HashIdentifier(email))

	// If the cache adapter supports atomic counters, use Counter
	if counter, ok := l.cache.(corecache.Counter); ok {
		count, err := counter.Increment(ctx, key, 1, window)
		if err != nil {
			return true, err // Fail open on cache errors to avoid denial of service
		}
		return count <= int64(maxRequests), nil
	}

	// Fallback to in-memory tracking if no distributed counter is available
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	e, exists := l.memCounts[key]
	if !exists || !now.Before(e.expiresAt) {
		l.memCounts[key] = entry{count: 1, expiresAt: now.Add(window)}
		return true, nil
	}

	e.count++
	l.memCounts[key] = e
	return e.count <= maxRequests, nil
}

// CheckAndSetCooldown checks and activates cooldown for the identifier.
func (l *Limiter) CheckAndSetCooldown(ctx context.Context, email string, cooldown time.Duration) (bool, error) {
	if cooldown <= 0 {
		return true, nil
	}

	key := corecache.Key("magiclink", "cooldown", HashIdentifier(email))

	if l.cache != nil {
		var dummy bool
		err := l.cache.Get(ctx, key, &dummy)
		if err == nil {
			// Key exists: cooldown is still active
			return false, nil
		}
		// Set cooldown key
		_ = l.cache.Set(ctx, key, true, cooldown)
		return true, nil
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	e, exists := l.memCounts[key]
	if exists && now.Before(e.expiresAt) {
		return false, nil
	}

	l.memCounts[key] = entry{count: 1, expiresAt: now.Add(cooldown)}
	return true, nil
}
