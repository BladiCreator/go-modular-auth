package cache

import (
	"context"
	"fmt"
	"time"

	corecache "github.com/BladiCreator/go-modular-auth/cache"
)

const (
	// SubNamespace is the plugin sub-namespace within GoModularAuth cache keys.
	SubNamespace = "twofactor"
)

// ChallengeCacheEntry is the serialized representation of an ephemeral MFA challenge stored in cache.
type ChallengeCacheEntry struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

// Cache wraps the core cache adapter for the twofactor plugin.
type Cache struct {
	core corecache.Cache
}

// New creates a Cache wrapper. If core is nil, the wrapper operates in degraded mode.
func New(core corecache.Cache) *Cache {
	return &Cache{core: core}
}

// Available reports whether a backing cache is configured.
func (c *Cache) Available() bool {
	return c != nil && c.core != nil
}

// challengeKey formats the namespaced key for an MFA challenge.
func challengeKey(challengeID string) string {
	return corecache.Key(SubNamespace, "challenge", challengeID)
}

// replayKey formats the namespaced key for OTP replay tracking.
func replayKey(factorID string, timeStep int64) string {
	return corecache.Key(SubNamespace, "replay", factorID, fmt.Sprintf("%d", timeStep))
}

// SetChallenge caches a short-lived MFA challenge.
func (c *Cache) SetChallenge(ctx context.Context, entry *ChallengeCacheEntry, ttl time.Duration) error {
	if !c.Available() {
		return nil
	}
	return c.core.Set(ctx, challengeKey(entry.ID), entry, ttl)
}

// GetChallenge retrieves an MFA challenge from cache.
func (c *Cache) GetChallenge(ctx context.Context, challengeID string) (*ChallengeCacheEntry, error) {
	if !c.Available() {
		return nil, corecache.ErrMiss
	}
	var entry ChallengeCacheEntry
	if err := c.core.Get(ctx, challengeKey(challengeID), &entry); err != nil {
		return nil, err
	}
	return &entry, nil
}

// DeleteChallenge removes an MFA challenge from cache upon consumption.
func (c *Cache) DeleteChallenge(ctx context.Context, challengeID string) error {
	if !c.Available() {
		return nil
	}
	return c.core.Delete(ctx, challengeKey(challengeID))
}

// MarkStepUsed sets an ephemeral replay marker in the cache for a specific factor time-step.
func (c *Cache) MarkStepUsed(ctx context.Context, factorID string, timeStep int64, ttl time.Duration) error {
	if !c.Available() {
		return nil
	}
	return c.core.Set(ctx, replayKey(factorID, timeStep), true, ttl)
}

// IsStepUsed checks whether a specific time-step for a factor was already seen in the cache.
func (c *Cache) IsStepUsed(ctx context.Context, factorID string, timeStep int64) (bool, error) {
	if !c.Available() {
		return false, nil
	}
	var used bool
	err := c.core.Get(ctx, replayKey(factorID, timeStep), &used)
	if err == nil && used {
		return true, nil
	}
	return false, nil
}
