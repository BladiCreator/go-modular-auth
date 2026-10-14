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

// FailurePolicy defines how cache failures (e.g. timeout, partition) are handled for security controls.
type FailurePolicy string

const (
	// FailOpen allows operations when cache operations fail, prioritizing availability.
	FailOpen FailurePolicy = "fail_open"

	// FailClosed rejects operations when cache operations fail, prioritizing abuse mitigation.
	FailClosed FailurePolicy = "fail_closed"
)

// ErrCacheCheckFailed is returned when an operation is rejected due to a cache failure under FailClosed.
var ErrCacheCheckFailed = errors.New("phone cache: security check failed")

// HashIdentifier produces an opaque hex hash of sensitive identifiers (phone number, user ID)
// to prevent exposing plaintext phone numbers in cache keys or logs.
func HashIdentifier(identifier string) string {
	sum := sha256.Sum256([]byte(identifier))
	return hex.EncodeToString(sum[:])
}

// Limiter manages rate limiting and cooldown periods for OTP requests.
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

// CheckRateLimit verifies whether requests for the given phone number are within the allowed limit.
func (l *Limiter) CheckRateLimit(ctx context.Context, phone string, maxRequests int, window time.Duration) (bool, error) {
	if maxRequests <= 0 || window <= 0 {
		return true, nil
	}

	key := corecache.Key("phone", "ratelimit", HashIdentifier(phone))

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

	// In-memory fallback
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

// CheckAndSetCooldown checks whether a cooldown is currently active, activating it if not.
func (l *Limiter) CheckAndSetCooldown(ctx context.Context, phone string, cooldown time.Duration) (bool, error) {
	if cooldown <= 0 {
		return true, nil
	}

	key := corecache.Key("phone", "cooldown", HashIdentifier(phone))

	if l.cache != nil {
		var dummy bool
		err := l.cache.Get(ctx, key, &dummy)
		if err == nil {
			// Cooldown key exists: request is throttled
			return false, nil
		}

		if !errors.Is(err, corecache.ErrMiss) {
			if l.failurePolicy == FailClosed {
				return false, errors.Join(ErrCacheCheckFailed, err)
			}
		} else {
			// Key does not exist: activate cooldown
			if setErr := l.cache.Set(ctx, key, true, cooldown); setErr != nil && l.failurePolicy == FailClosed {
				return false, errors.Join(ErrCacheCheckFailed, setErr)
			}
			return true, nil
		}
	}

	// In-memory fallback
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
