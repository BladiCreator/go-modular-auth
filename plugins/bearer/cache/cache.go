// Package cache provides performance acceleration for bearer token validation
// using GoModularAuth's core cache adapter.
//
// The database adapter remains the source of truth at all times; Cache is derived and ephemeral.
// Cache keys are strictly derived from cryptographic token hashes or IDs, never from plaintext secrets.
package cache

import (
	"context"
	"slices"
	"time"

	corecache "github.com/BladiCreator/go-modular-auth/cache"
)

const (
	// SubNamespace is the plugin sub-namespace within GoModularAuth cache keys.
	SubNamespace = "bearer"
)

// CachedToken represents the cached attributes of a bearer token.
type CachedToken struct {
	ID            string            `json:"id"`
	TokenHash     string            `json:"token_hash"`
	Subject       string            `json:"subject"`
	PrincipalType string            `json:"principal_type"`
	Scopes        []string          `json:"scopes"`
	Metadata      map[string]string `json:"metadata,omitempty"`
	ExpiresAt     time.Time         `json:"expires_at"`
	RevokedAt     *time.Time        `json:"revoked_at,omitempty"`
	CreatedAt     time.Time         `json:"created_at"`
	UpdatedAt     time.Time         `json:"updated_at"`
}

// Expired reports whether the token has expired relative to the given time.
func (r *CachedToken) Expired(now time.Time) bool {
	if r.ExpiresAt.IsZero() {
		return false
	}
	return !now.Before(r.ExpiresAt)
}

// Revoked reports whether the token has been marked as revoked.
func (r *CachedToken) Revoked() bool {
	return r.RevokedAt != nil
}

// Active reports whether the token is neither expired nor revoked.
func (r *CachedToken) Active(now time.Time) bool {
	return !r.Revoked() && !r.Expired(now)
}

// HasScope reports whether the record contains the specified scope.
func (r *CachedToken) HasScope(scope string) bool {
	return slices.Contains(r.Scopes, scope)
}

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
func (c *Cache) Set(ctx context.Context, record *CachedToken, ttl time.Duration) error {
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
func (c *Cache) GetByHash(ctx context.Context, tokenHash string) (*CachedToken, error) {
	if !c.Available() || tokenHash == "" {
		return nil, corecache.ErrMiss
	}
	var rec CachedToken
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
