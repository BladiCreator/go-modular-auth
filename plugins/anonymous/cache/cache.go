package cache

import (
	"context"
	"time"

	"github.com/BladiCreator/go-modular-auth-anonymous/store"
	corecache "github.com/BladiCreator/go-modular-auth/cache"
)

const (
	// SubNamespace is the plugin sub-namespace within GoModularAuth cache keys.
	SubNamespace = "anonymous"
)

// Cache wraps the core cache adapter for anonymous identity caching.
type Cache struct {
	core corecache.Cache
}

// New creates a new Cache wrapper. If core is nil, the cache operates in no-op/degraded mode.
func New(core corecache.Cache) *Cache {
	return &Cache{core: core}
}

// Available reports whether a backing cache is configured.
func (c *Cache) Available() bool {
	return c != nil && c.core != nil
}

func identityKey(userID string) string {
	return corecache.Key(SubNamespace, "user", userID)
}

// SetIdentity stores an anonymous identity in cache with a TTL.
func (c *Cache) SetIdentity(ctx context.Context, id *store.Identity, ttl time.Duration) error {
	if !c.Available() || id == nil {
		return nil
	}
	return c.core.Set(ctx, identityKey(id.UserID), id, ttl)
}

// GetIdentity retrieves an anonymous identity from cache by Core User ID.
func (c *Cache) GetIdentity(ctx context.Context, userID string) (*store.Identity, error) {
	if !c.Available() {
		return nil, corecache.ErrMiss
	}
	var id store.Identity
	if err := c.core.Get(ctx, identityKey(userID), &id); err != nil {
		return nil, err
	}
	return &id, nil
}

// DeleteIdentity invalidates the cached anonymous identity for a user.
func (c *Cache) DeleteIdentity(ctx context.Context, userID string) error {
	if !c.Available() {
		return nil
	}
	return c.core.Delete(ctx, identityKey(userID))
}
