// Package cache provides performance acceleration for bearer token validation
// using GoModularAuth's core cache adapter.
//
// The Store remains the source of truth at all times; Cache is derived and ephemeral.
// Cache keys are strictly derived from cryptographic token hashes or IDs, never from plaintext secrets.
package cache

import (
	"context"
	"time"

	"github.com/BladiCreator/go-modular-auth-bearer/store"
	corecache "github.com/BladiCreator/go-modular-auth/cache"
)

const (
	// SubNamespace is the plugin sub-namespace within GoModularAuth cache keys.
	SubNamespace = "bearer"
)

// Cache wraps the core cache adapter for bearer token lookups.
type Cache struct {
	core corecache.Cache
}

// New creates a new Cache wrapper. If core is nil, the cache operates in no-op mode.
func New(core corecache.Cache) *Cache {
	return &Cache{core: core}
}

// Available reports whether a backing cache is configured.
func (c *Cache) Available() bool {
	return c != nil && c.core != nil
}

func tokenHashKey(tokenHash string) string {
	return corecache.Key(SubNamespace, "token", tokenHash)
}

func tokenIDKey(id string) string {
	return corecache.Key(SubNamespace, "id", id)
}

// Set stores a token record in cache for fast lookup by token hash and id.
func (c *Cache) Set(ctx context.Context, record *store.TokenRecord, ttl time.Duration) error {
	if !c.Available() || record == nil || ttl <= 0 {
		return nil
	}
	// Store record by token hash
	if err := c.core.Set(ctx, tokenHashKey(record.TokenHash), record, ttl); err != nil {
		return err
	}
	// Also store hash mapping by ID so revoking by ID can invalidate the hash entry
	return c.core.Set(ctx, tokenIDKey(record.ID), record.TokenHash, ttl)
}

// GetByHash retrieves a token record by the SHA-256 hash of its token.
func (c *Cache) GetByHash(ctx context.Context, tokenHash string) (*store.TokenRecord, error) {
	if !c.Available() || tokenHash == "" {
		return nil, corecache.ErrMiss
	}
	var rec store.TokenRecord
	if err := c.core.Get(ctx, tokenHashKey(tokenHash), &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

// DeleteByHash invalidates the cached record by token hash.
func (c *Cache) DeleteByHash(ctx context.Context, tokenHash string) error {
	if !c.Available() || tokenHash == "" {
		return nil
	}
	return c.core.Delete(ctx, tokenHashKey(tokenHash))
}

// DeleteByID invalidates cache entries associated with the token ID.
func (c *Cache) DeleteByID(ctx context.Context, id string) error {
	if !c.Available() || id == "" {
		return nil
	}
	var tokenHash string
	if err := c.core.Get(ctx, tokenIDKey(id), &tokenHash); err == nil && tokenHash != "" {
		_ = c.core.Delete(ctx, tokenHashKey(tokenHash))
	}
	return c.core.Delete(ctx, tokenIDKey(id))
}
