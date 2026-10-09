// Package cache provides performance acceleration for organization and membership lookups
// using GoModularAuth's core cache adapter.
//
// The Store remains the source of truth at all times; Cache is derived and ephemeral.
package cache

import (
	"context"
	"time"

	"github.com/BladiCreator/go-modular-auth-organizations/store"
	corecache "github.com/BladiCreator/go-modular-auth/cache"
)

const (
	// SubNamespace is the plugin sub-namespace within GoModularAuth cache keys.
	SubNamespace = "organizations"
)

// Cache wraps the core cache adapter for organization and membership lookups.
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

func orgIDKey(id string) string {
	return corecache.Key(SubNamespace, "org", id)
}

func orgSlugKey(slug string) string {
	return corecache.Key(SubNamespace, "slug", slug)
}

func membershipKey(orgID, userID string) string {
	return corecache.Key(SubNamespace, "membership", orgID, userID)
}

// SetOrganization caches an organization by its ID and slug.
func (c *Cache) SetOrganization(ctx context.Context, org *store.Organization, ttl time.Duration) error {
	if !c.Available() || org == nil || ttl <= 0 {
		return nil
	}
	if err := c.core.Set(ctx, orgIDKey(org.ID), org, ttl); err != nil {
		return err
	}
	return c.core.Set(ctx, orgSlugKey(org.Slug), org, ttl)
}

// GetOrganizationByID retrieves an organization by ID from cache.
func (c *Cache) GetOrganizationByID(ctx context.Context, id string) (*store.Organization, error) {
	if !c.Available() || id == "" {
		return nil, corecache.ErrMiss
	}
	var org store.Organization
	if err := c.core.Get(ctx, orgIDKey(id), &org); err != nil {
		return nil, err
	}
	return &org, nil
}

// GetOrganizationBySlug retrieves an organization by slug from cache.
func (c *Cache) GetOrganizationBySlug(ctx context.Context, slug string) (*store.Organization, error) {
	if !c.Available() || slug == "" {
		return nil, corecache.ErrMiss
	}
	var org store.Organization
	if err := c.core.Get(ctx, orgSlugKey(slug), &org); err != nil {
		return nil, err
	}
	return &org, nil
}

// DeleteOrganization invalidates cache entries for an organization ID and slug.
func (c *Cache) DeleteOrganization(ctx context.Context, id, slug string) error {
	if !c.Available() {
		return nil
	}
	if id != "" {
		_ = c.core.Delete(ctx, orgIDKey(id))
	}
	if slug != "" {
		_ = c.core.Delete(ctx, orgSlugKey(slug))
	}
	return nil
}

// SetMembership caches a membership record.
func (c *Cache) SetMembership(ctx context.Context, m *store.Membership, ttl time.Duration) error {
	if !c.Available() || m == nil || ttl <= 0 {
		return nil
	}
	return c.core.Set(ctx, membershipKey(m.OrganizationID, m.UserID), m, ttl)
}

// GetMembership retrieves a membership from cache.
func (c *Cache) GetMembership(ctx context.Context, orgID, userID string) (*store.Membership, error) {
	if !c.Available() || orgID == "" || userID == "" {
		return nil, corecache.ErrMiss
	}
	var m store.Membership
	if err := c.core.Get(ctx, membershipKey(orgID, userID), &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// DeleteMembership invalidates cached membership for an organization member.
func (c *Cache) DeleteMembership(ctx context.Context, orgID, userID string) error {
	if !c.Available() || orgID == "" || userID == "" {
		return nil
	}
	return c.core.Delete(ctx, membershipKey(orgID, userID))
}
