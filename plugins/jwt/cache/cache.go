package cache

import (
	"context"
	"time"

	corecache "github.com/BladiCreator/go-modular-auth/cache"
)

// RevocationCache defines the contract for accelerating revocation checks.
// Cache is performance-oriented; Store remains the definitive source of truth.
type RevocationCache interface {
	IsTokenRevoked(ctx context.Context, jti string) (revoked bool, found bool)
	SetTokenRevoked(ctx context.Context, jti string, ttl time.Duration) error
	GetSubjectCutoff(ctx context.Context, subject string) (cutoff time.Time, found bool)
	SetSubjectCutoff(ctx context.Context, subject string, cutoff time.Time, ttl time.Duration) error
	DeleteTokenRevocation(ctx context.Context, jti string) error
}

type adapter struct {
	c corecache.Cache
}

// New wraps a core cache.Cache into a domain-specific RevocationCache.
func New(c corecache.Cache) RevocationCache {
	if c == nil {
		return nil
	}
	return &adapter{c: c}
}

func (a *adapter) tokenKey(jti string) string {
	return corecache.Key("jwt", "revocation", jti)
}

func (a *adapter) subjectKey(subject string) string {
	return corecache.Key("jwt", "subject_cutoff", subject)
}

func (a *adapter) IsTokenRevoked(ctx context.Context, jti string) (bool, bool) {
	if a == nil || a.c == nil || jti == "" {
		return false, false
	}
	var val bool
	err := a.c.Get(ctx, a.tokenKey(jti), &val)
	if err != nil {
		return false, false
	}
	return val, true
}

func (a *adapter) SetTokenRevoked(ctx context.Context, jti string, ttl time.Duration) error {
	if a == nil || a.c == nil || jti == "" || ttl <= 0 {
		return nil
	}
	val := true
	return a.c.Set(ctx, a.tokenKey(jti), &val, ttl)
}

func (a *adapter) GetSubjectCutoff(ctx context.Context, subject string) (time.Time, bool) {
	if a == nil || a.c == nil || subject == "" {
		return time.Time{}, false
	}
	var unixSec int64
	err := a.c.Get(ctx, a.subjectKey(subject), &unixSec)
	if err != nil {
		return time.Time{}, false
	}
	return time.Unix(unixSec, 0), true
}

func (a *adapter) SetSubjectCutoff(ctx context.Context, subject string, cutoff time.Time, ttl time.Duration) error {
	if a == nil || a.c == nil || subject == "" || ttl <= 0 {
		return nil
	}
	unixSec := cutoff.Unix()
	return a.c.Set(ctx, a.subjectKey(subject), &unixSec, ttl)
}

func (a *adapter) DeleteTokenRevocation(ctx context.Context, jti string) error {
	if a == nil || a.c == nil || jti == "" {
		return nil
	}
	return a.c.Delete(ctx, a.tokenKey(jti))
}
