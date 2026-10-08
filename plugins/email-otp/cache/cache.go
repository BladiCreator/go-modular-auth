// Package cache provides rate limiting, cooldown, and failure-policy abstractions for Email OTP.
package cache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	corecache "github.com/BladiCreator/go-modular-auth/cache"
)

// FailurePolicy defines how cache failures (timeouts, partition, downtime) are handled for security controls.
type FailurePolicy string

const (
	// FailOpen allows requests to proceed when cache operations fail, prioritizing availability.
	FailOpen FailurePolicy = "fail_open"

	// FailClosed denies requests when cache operations fail, prioritizing abuse protection.
	FailClosed FailurePolicy = "fail_closed"
)

// ErrCacheCheckFailed is returned when an operation is rejected due to a cache failure under FailClosed.
var ErrCacheCheckFailed = errors.New("cache: security check failed")

// Limiter manages rate limiting and cooldown state, utilizing Core Cache when available.
type Limiter struct {
	cache         corecache.Cache
	failurePolicy FailurePolicy
	mu            sync.Mutex
	memCounts     map[string]memEntry
	now           func() time.Time
}

type memEntry struct {
	count     int
	expiresAt time.Time
}

// NewLimiter constructs a Limiter instance.
func NewLimiter(c corecache.Cache, policy FailurePolicy, now func() time.Time) *Limiter {
	if now == nil {
		now = time.Now
	}
	if policy == "" {
		policy = FailOpen
	}
	return &Limiter{
		cache:         c,
		failurePolicy: policy,
		memCounts:     make(map[string]memEntry),
		now:           now,
	}
}

// HashIdentifier produces an opaque hex hash of the identifier to avoid storing plaintext emails in cache keys.
func HashIdentifier(identifier string) string {
	sum := sha256.Sum256([]byte(identifier))
	return hex.EncodeToString(sum[:])
}

// CheckRateLimit verifies if an email request is within the allowable limit.
func (l *Limiter) CheckRateLimit(ctx context.Context, email string, maxRequests int, window time.Duration) (bool, error) {
	if maxRequests <= 0 || window <= 0 {
		return true, nil
	}

	key := corecache.Key("email_otp", "ratelimit", HashIdentifier(email))

	if counter, ok := l.cache.(corecache.Counter); ok {
		count, err := counter.Increment(ctx, key, 1, window)
		if err != nil {
			if l.failurePolicy == FailClosed {
				return false, errors.Join(ErrCacheCheckFailed, err)
			}
			return true, nil // Fail open
		}
		return count <= int64(maxRequests), nil
	}

	// Fallback to thread-safe in-memory map
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	entry, exists := l.memCounts[key]
	if !exists || !now.Before(entry.expiresAt) {
		l.memCounts[key] = memEntry{count: 1, expiresAt: now.Add(window)}
		return true, nil
	}

	entry.count++
	l.memCounts[key] = entry
	return entry.count <= maxRequests, nil
}

// CheckAndSetCooldown checks whether a cooldown is currently active, and activates it if not.
func (l *Limiter) CheckAndSetCooldown(ctx context.Context, email string, cooldown time.Duration) (bool, error) {
	if cooldown <= 0 {
		return true, nil
	}

	key := corecache.Key("email_otp", "cooldown", HashIdentifier(email))

	if l.cache != nil {
		var dummy bool
		err := l.cache.Get(ctx, key, &dummy)
		if err == nil {
			// Key exists: cooldown is currently active
			return false, nil
		}

		if !errors.Is(err, corecache.ErrMiss) {
			// Cache error occurred
			if l.failurePolicy == FailClosed {
				return false, errors.Join(ErrCacheCheckFailed, err)
			}
			// Fail open: proceed with in-memory tracking
		} else {
			// Key does not exist: activate cooldown
			if setErr := l.cache.Set(ctx, key, true, cooldown); setErr != nil && l.failurePolicy == FailClosed {
				return false, errors.Join(ErrCacheCheckFailed, setErr)
			}
			return true, nil
		}
	}

	// Fallback in-memory tracking
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	entry, exists := l.memCounts[key]
	if exists && now.Before(entry.expiresAt) {
		return false, nil
	}

	l.memCounts[key] = memEntry{count: 1, expiresAt: now.Add(cooldown)}
	return true, nil
}
