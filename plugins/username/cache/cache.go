package cache

import (
	"context"
	"time"

	corecache "github.com/BladiCreator/go-modular-auth/cache"
)

// CachedRecord is the cached representation of a username mapping.
type CachedRecord struct {
	UserID     string    `json:"user_id"`
	Username   string    `json:"username"`
	Normalized string    `json:"normalized"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// KeyNormalized returns the namespaced cache key for a normalized username.
// Format: gomodularauth:username:norm:<normalized>
func KeyNormalized(norm string) string {
	return corecache.Key("username", "norm", norm)
}

// KeyUserID returns the namespaced cache key for a Core user ID.
// Format: gomodularauth:username:user:<userID>
func KeyUserID(userID string) string {
	return corecache.Key("username", "user", userID)
}

// Cache wraps the core Cache adapter with semantic username operations.
type Cache struct {
	c   corecache.Cache
	ttl time.Duration
}

// New constructs a semantic Cache wrapper around an optional core Cache.
// If c is nil, Cache gracefully acts as a no-op layer.
func New(c corecache.Cache, ttl time.Duration) *Cache {
	if c == nil {
		return nil
	}
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &Cache{c: c, ttl: ttl}
}

// GetByNormalized returns the cached username record for a normalized username, if present.
func (c *Cache) GetByNormalized(ctx context.Context, norm string) (*CachedRecord, bool) {
	if c == nil || c.c == nil {
		return nil, false
	}
	var rec CachedRecord
	if err := c.c.Get(ctx, KeyNormalized(norm), &rec); err != nil {
		return nil, false
	}
	return &rec, true
}

// GetByUserID returns the cached username record for a user ID, if present.
func (c *Cache) GetByUserID(ctx context.Context, userID string) (*CachedRecord, bool) {
	if c == nil || c.c == nil {
		return nil, false
	}
	var rec CachedRecord
	if err := c.c.Get(ctx, KeyUserID(userID), &rec); err != nil {
		return nil, false
	}
	return &rec, true
}

// Set stores the record in both normalized and user ID cache entries.
func (c *Cache) Set(ctx context.Context, rec *CachedRecord) {
	if c == nil || c.c == nil || rec == nil {
		return
	}
	_ = c.c.Set(ctx, KeyNormalized(rec.Normalized), rec, c.ttl)
	_ = c.c.Set(ctx, KeyUserID(rec.UserID), rec, c.ttl)
}

// Invalidate removes cached entries for the normalized username and user ID.
func (c *Cache) Invalidate(ctx context.Context, norm, userID string) {
	if c == nil || c.c == nil {
		return
	}
	if norm != "" {
		_ = c.c.Delete(ctx, KeyNormalized(norm))
	}
	if userID != "" {
		_ = c.c.Delete(ctx, KeyUserID(userID))
	}
}
