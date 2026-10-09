// Package cache provides caching support for high-frequency administrative queries.
package cache

import (
	"context"
	"errors"
	"time"

	corecache "github.com/BladiCreator/go-modular-auth/cache"
)

// DefaultTTL defines the default duration for caching administrative flags.
const DefaultTTL = 5 * time.Minute

// Cache defines the domain caching contract for administrative checks.
type Cache interface {
	GetDisabled(ctx context.Context, userID string) (bool, bool, error)
	SetDisabled(ctx context.Context, userID string, disabled bool, ttl time.Duration) error
	DeleteDisabled(ctx context.Context, userID string) error

	GetIsAdmin(ctx context.Context, userID string) (bool, bool, error)
	SetIsAdmin(ctx context.Context, userID string, isAdmin bool, ttl time.Duration) error
	DeleteIsAdmin(ctx context.Context, userID string) error
}

type adapter struct {
	core corecache.Cache
}

// New creates a new domain Cache wrapping a Core Cache adapter.
func New(c corecache.Cache) Cache {
	if c == nil {
		return nil
	}
	return &adapter{core: c}
}

func (a *adapter) GetDisabled(ctx context.Context, userID string) (bool, bool, error) {
	if a == nil || a.core == nil {
		return false, false, nil
	}
	var disabled bool
	key := corecache.Key("admin", "disabled", userID)
	err := a.core.Get(ctx, key, &disabled)
	if err != nil {
		if errors.Is(err, corecache.ErrMiss) {
			return false, false, nil
		}
		return false, false, err
	}
	return disabled, true, nil
}

func (a *adapter) SetDisabled(ctx context.Context, userID string, disabled bool, ttl time.Duration) error {
	if a == nil || a.core == nil {
		return nil
	}
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	key := corecache.Key("admin", "disabled", userID)
	return a.core.Set(ctx, key, disabled, ttl)
}

func (a *adapter) DeleteDisabled(ctx context.Context, userID string) error {
	if a == nil || a.core == nil {
		return nil
	}
	key := corecache.Key("admin", "disabled", userID)
	return a.core.Delete(ctx, key)
}

func (a *adapter) GetIsAdmin(ctx context.Context, userID string) (bool, bool, error) {
	if a == nil || a.core == nil {
		return false, false, nil
	}
	var isAdmin bool
	key := corecache.Key("admin", "is_admin", userID)
	err := a.core.Get(ctx, key, &isAdmin)
	if err != nil {
		if errors.Is(err, corecache.ErrMiss) {
			return false, false, nil
		}
		return false, false, err
	}
	return isAdmin, true, nil
}

func (a *adapter) SetIsAdmin(ctx context.Context, userID string, isAdmin bool, ttl time.Duration) error {
	if a == nil || a.core == nil {
		return nil
	}
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	key := corecache.Key("admin", "is_admin", userID)
	return a.core.Set(ctx, key, isAdmin, ttl)
}

func (a *adapter) DeleteIsAdmin(ctx context.Context, userID string) error {
	if a == nil || a.core == nil {
		return nil
	}
	key := corecache.Key("admin", "is_admin", userID)
	return a.core.Delete(ctx, key)
}
