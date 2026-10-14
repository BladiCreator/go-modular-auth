package phone

import (
	"context"
	"time"

	"github.com/BladiCreator/go-modular-auth/plugins/phone/cache"
	corecache "github.com/BladiCreator/go-modular-auth/cache"
)

// PhoneCache accelerates read queries for PhoneRecords with automatic invalidation.
type PhoneCache struct {
	cache corecache.Cache
	ttl   time.Duration
}

// NewPhoneCache creates a PhoneCache adapter.
func NewPhoneCache(c corecache.Cache, ttl time.Duration) *PhoneCache {
	return &PhoneCache{cache: c, ttl: ttl}
}

// GetByUserID retrieves a cached phone record by user ID.
func (c *PhoneCache) GetByUserID(ctx context.Context, userID string) (*PhoneRecord, error) {
	if c.cache == nil || c.ttl <= 0 {
		return nil, corecache.ErrMiss
	}
	key := corecache.Key("phone", "user", cache.HashIdentifier(userID))
	var p PhoneRecord
	if err := c.cache.Get(ctx, key, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// SetByUserID caches a phone record by user ID.
func (c *PhoneCache) SetByUserID(ctx context.Context, userID string, p *PhoneRecord) error {
	if c.cache == nil || c.ttl <= 0 || p == nil {
		return nil
	}
	key := corecache.Key("phone", "user", cache.HashIdentifier(userID))
	return c.cache.Set(ctx, key, *p, c.ttl)
}

// GetByNumber retrieves a cached phone record by phone number.
func (c *PhoneCache) GetByNumber(ctx context.Context, phone string) (*PhoneRecord, error) {
	if c.cache == nil || c.ttl <= 0 {
		return nil, corecache.ErrMiss
	}
	key := corecache.Key("phone", "num", cache.HashIdentifier(phone))
	var p PhoneRecord
	if err := c.cache.Get(ctx, key, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// SetByNumber caches a phone record by phone number.
func (c *PhoneCache) SetByNumber(ctx context.Context, phone string, p *PhoneRecord) error {
	if c.cache == nil || c.ttl <= 0 || p == nil {
		return nil
	}
	key := corecache.Key("phone", "num", cache.HashIdentifier(phone))
	return c.cache.Set(ctx, key, *p, c.ttl)
}

// Invalidate invalidates cached phone records for both user ID and phone number.
func (c *PhoneCache) Invalidate(ctx context.Context, userID, phone string) {
	if c.cache == nil {
		return
	}
	if userID != "" {
		_ = c.cache.Delete(ctx, corecache.Key("phone", "user", cache.HashIdentifier(userID)))
	}
	if phone != "" {
		_ = c.cache.Delete(ctx, corecache.Key("phone", "num", cache.HashIdentifier(phone)))
	}
}
