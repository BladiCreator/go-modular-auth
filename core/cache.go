package auth

import (
	"context"
	"errors"

	"github.com/BladiCreator/go-modular-auth/cache"
	"github.com/BladiCreator/go-modular-auth/session"
	"github.com/BladiCreator/go-modular-auth/user"
)

// The helpers below implement the cache policy of the core:
//
//   - Read:  cache -> store on miss -> cache.Set (cache-aside).
//   - Write: store (commit) -> cache invalidation. Never inside a transaction.
//   - Failure: cache errors are logged and the core degrades to the Store.
//
// TTLs never exceed the semantic lifetime of the cached object.

func (a *Auth) cachedSession(ctx context.Context, tokenHash string) *session.Session {
	if a.sessionCache == nil {
		return nil
	}
	s, err := a.sessionCache.Get(ctx, tokenHash)
	if err != nil {
		if !errors.Is(err, cache.ErrMiss) {
			a.logger.WarnContext(ctx, "auth: session cache read failed, falling back to store", "error", err)
		}
		return nil
	}
	return s
}

func (a *Auth) cacheSession(ctx context.Context, s *session.Session) {
	if a.sessionCache == nil {
		return
	}
	ttl := min(a.cfg.Session.CacheTTL, s.ExpiresAt.Sub(a.Now()))
	if ttl <= 0 {
		return
	}
	if err := a.sessionCache.Set(ctx, s, ttl); err != nil {
		a.logger.WarnContext(ctx, "auth: session cache write failed", "error", err)
	}
}

// invalidateSessions deletes cache entries after a critical mutation. A
// failure is logged at error level: until CacheTTL elapses the stale entry
// may still be served, which is why Session.CacheTTL should stay short.
func (a *Auth) invalidateSessions(ctx context.Context, sessions ...*session.Session) {
	if a.sessionCache == nil {
		return
	}
	for _, s := range sessions {
		if err := a.sessionCache.Delete(ctx, s.TokenHash); err != nil {
			a.logger.ErrorContext(ctx, "auth: session cache invalidation failed", "session_id", s.ID, "error", err)
		}
	}
}

func (a *Auth) cachedUser(ctx context.Context, id string) *user.User {
	if a.userCache == nil {
		return nil
	}
	u, err := a.userCache.Get(ctx, id)
	if err != nil {
		if !errors.Is(err, cache.ErrMiss) {
			a.logger.WarnContext(ctx, "auth: user cache read failed, falling back to store", "error", err)
		}
		return nil
	}
	return u
}

func (a *Auth) cacheUser(ctx context.Context, u *user.User) {
	if a.userCache == nil {
		return
	}
	if err := a.userCache.Set(ctx, u, a.cfg.User.CacheTTL); err != nil {
		a.logger.WarnContext(ctx, "auth: user cache write failed", "error", err)
	}
}

func (a *Auth) invalidateUser(ctx context.Context, id string) {
	if a.userCache == nil {
		return
	}
	if err := a.userCache.Delete(ctx, id); err != nil {
		a.logger.ErrorContext(ctx, "auth: user cache invalidation failed", "user_id", id, "error", err)
	}
}
