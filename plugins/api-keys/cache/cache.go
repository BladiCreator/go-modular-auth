// Package cache provides caching and brute force prevention abstractions for the API keys module.
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

// KeyRecord represents cached API key attributes.
type KeyRecord struct {
	ID             string            `json:"id"`
	Name           string            `json:"name"`
	Prefix         string            `json:"prefix"`
	KeyHash        string            `json:"key_hash"`
	UserID         string            `json:"user_id,omitempty"`
	OrganizationID string            `json:"organization_id,omitempty"`
	ServiceID      string            `json:"service_id,omitempty"`
	Scopes         []string          `json:"scopes,omitempty"`
	Permissions    []string          `json:"permissions,omitempty"`
	Metadata       map[string]string `json:"metadata,omitempty"`
	ExpiresAt      *time.Time        `json:"expires_at,omitempty"`
	RevokedAt      *time.Time        `json:"revoked_at,omitempty"`
	LastUsedAt     *time.Time        `json:"last_used_at,omitempty"`
	LastUsedIP     string            `json:"last_used_ip,omitempty"`
	LastUsedUA     string            `json:"last_used_ua,omitempty"`
	CreatedAt      time.Time         `json:"created_at"`
	UpdatedAt      time.Time         `json:"updated_at"`
}

// Default settings for caching and abuse mitigation.
const (
	DefaultKeyTTL           = 5 * time.Minute
	DefaultBruteForceLimit  = 10
	DefaultBruteForceWindow = 1 * time.Minute
)

// Limiter coordinates cached key resolution and brute-force mitigation using the shared cache.
type Limiter struct {
	cache       corecache.Cache
	maxAttempts int
	window      time.Duration
	keyTTL      time.Duration

	// Local fallback limiter when Core Cache is not configured.
	mu          sync.Mutex
	localCounts map[string]*attemptWindow
}

type attemptWindow struct {
	count     int
	resetTime time.Time
}

// NewLimiter constructs an API key cache and abuse limiter.
func NewLimiter(c corecache.Cache, maxAttempts int, window time.Duration, keyTTL time.Duration) *Limiter {
	if maxAttempts <= 0 {
		maxAttempts = DefaultBruteForceLimit
	}
	if window <= 0 {
		window = DefaultBruteForceWindow
	}
	if keyTTL <= 0 {
		keyTTL = DefaultKeyTTL
	}

	return &Limiter{
		cache:       c,
		maxAttempts: maxAttempts,
		window:      window,
		keyTTL:      keyTTL,
		localCounts: make(map[string]*attemptWindow),
	}
}

// HashIdentifier produces an opaque hash of sensitive identifiers (such as IP addresses)
// to avoid exposing plaintext client identifiers in cache keys or logs.
func HashIdentifier(identifier string) string {
	sum := sha256.Sum256([]byte(identifier))
	return hex.EncodeToString(sum[:])
}

// CheckRateLimit checks whether the given client identifier is currently rate limited.
// Returns true if requests should be blocked.
func (l *Limiter) CheckRateLimit(ctx context.Context, identifier string) (bool, error) {
	if identifier == "" {
		return false, nil
	}

	h := HashIdentifier(identifier)

	if l.cache != nil {
		if counter, ok := l.cache.(corecache.Counter); ok {
			key := corecache.Key("apikeys", "failures", h)
			var current int64
			err := l.cache.Get(ctx, key, &current)
			if err == nil && current >= int64(l.maxAttempts) {
				return true, nil
			}
			_ = counter
		} else {
			key := corecache.Key("apikeys", "failures", h)
			var count int
			err := l.cache.Get(ctx, key, &count)
			if err == nil && count >= l.maxAttempts {
				return true, nil
			}
		}
		return false, nil
	}

	// Local fallback
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	w, exists := l.localCounts[h]
	if !exists || now.After(w.resetTime) {
		return false, nil
	}
	return w.count >= l.maxAttempts, nil
}

// RecordFailure increments the failure count for brute-force protection.
func (l *Limiter) RecordFailure(ctx context.Context, identifier string) error {
	if identifier == "" {
		return nil
	}

	h := HashIdentifier(identifier)

	if l.cache != nil {
		key := corecache.Key("apikeys", "failures", h)
		if counter, ok := l.cache.(corecache.Counter); ok {
			_, err := counter.Increment(ctx, key, 1, l.window)
			return err
		}
		var count int
		if err := l.cache.Get(ctx, key, &count); err != nil && !errors.Is(err, corecache.ErrMiss) {
			return err
		}
		count++
		return l.cache.Set(ctx, key, count, l.window)
	}

	// Local fallback
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	w, exists := l.localCounts[h]
	if !exists || now.After(w.resetTime) {
		l.localCounts[h] = &attemptWindow{count: 1, resetTime: now.Add(l.window)}
		return nil
	}
	w.count++
	return nil
}

// GetKey retrieves a cached API key by its SHA-256 hash.
func (l *Limiter) GetKey(ctx context.Context, keyHash string) (*KeyRecord, error) {
	if l.cache == nil {
		return nil, corecache.ErrMiss
	}

	cacheKey := corecache.Key("apikeys", "hash", keyHash)
	var k KeyRecord
	if err := l.cache.Get(ctx, cacheKey, &k); err != nil {
		return nil, err
	}
	return &k, nil
}

// SetKey stores an active API key in cache by both hash and ID to enable fast lookup and invalidation.
func (l *Limiter) SetKey(ctx context.Context, key *KeyRecord) error {
	if l.cache == nil || key == nil {
		return nil
	}

	hashKey := corecache.Key("apikeys", "hash", key.KeyHash)
	idKey := corecache.Key("apikeys", "id", key.ID)

	_ = l.cache.Set(ctx, idKey, key.KeyHash, l.keyTTL)
	return l.cache.Set(ctx, hashKey, key, l.keyTTL)
}

// Invalidate immediately purges the cache entries for an API key by ID and hash.
func (l *Limiter) Invalidate(ctx context.Context, id string, keyHash string) error {
	if l.cache == nil {
		return nil
	}

	var errs []error
	if id != "" {
		idKey := corecache.Key("apikeys", "id", id)
		var storedHash string
		if err := l.cache.Get(ctx, idKey, &storedHash); err == nil && storedHash != "" {
			_ = l.cache.Delete(ctx, corecache.Key("apikeys", "hash", storedHash))
		}
		if err := l.cache.Delete(ctx, idKey); err != nil && !errors.Is(err, corecache.ErrMiss) {
			errs = append(errs, err)
		}
	}

	if keyHash != "" {
		hashKey := corecache.Key("apikeys", "hash", keyHash)
		if err := l.cache.Delete(ctx, hashKey); err != nil && !errors.Is(err, corecache.ErrMiss) {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}
