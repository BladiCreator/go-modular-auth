package cache

import (
	"context"
	"time"

	corecache "github.com/BladiCreator/go-modular-auth/cache"
	"github.com/BladiCreator/go-modular-auth-multisession/store"
)

// KeyMetadata returns the namespaced cache key for session metadata.
// Format: gomodularauth:multisession:meta:<sessionID>
func KeyMetadata(sessionID string) string {
	return corecache.Key("multisession", "meta", sessionID)
}

// Cache wraps the Core cache adapter with semantic multisession metadata operations.
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
		ttl = 10 * time.Minute
	}
	return &Cache{c: c, ttl: ttl}
}

// GetMetadata returns cached session metadata, if present.
func (c *Cache) GetMetadata(ctx context.Context, sessionID string) (*store.MetadataRecord, bool) {
	if c == nil || c.c == nil || sessionID == "" {
		return nil, false
	}
	var rec store.MetadataRecord
	if err := c.c.Get(ctx, KeyMetadata(sessionID), &rec); err != nil {
		return nil, false
	}
	return &rec, true
}

// SetMetadata stores the session metadata in cache.
func (c *Cache) SetMetadata(ctx context.Context, rec *store.MetadataRecord) {
	if c == nil || c.c == nil || rec == nil || rec.SessionID == "" {
		return
	}
	_ = c.c.Set(ctx, KeyMetadata(rec.SessionID), rec, c.ttl)
}

// InvalidateMetadata removes cached metadata for the given session ID.
func (c *Cache) InvalidateMetadata(ctx context.Context, sessionID string) {
	if c == nil || c.c == nil || sessionID == "" {
		return
	}
	_ = c.c.Delete(ctx, KeyMetadata(sessionID))
}

// InvalidateBulkMetadata removes cached metadata for multiple session IDs.
func (c *Cache) InvalidateBulkMetadata(ctx context.Context, sessionIDs []string) {
	if c == nil || c.c == nil {
		return
	}
	for _, id := range sessionIDs {
		if id != "" {
			_ = c.c.Delete(ctx, KeyMetadata(id))
		}
	}
}
