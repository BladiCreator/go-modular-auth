package cache

import (
	"context"
	"time"

	"github.com/BladiCreator/go-modular-auth/session"
	"github.com/BladiCreator/go-modular-auth/user"
)

// SessionCache is the semantic cache for sessions, keyed by token hash.
// It keeps arbitrary keys out of the core.
type SessionCache interface {
	Get(ctx context.Context, tokenHash string) (*session.Session, error)
	Set(ctx context.Context, s *session.Session, ttl time.Duration) error
	Delete(ctx context.Context, tokenHash string) error
}

// UserCache is the semantic cache for users, keyed by user ID.
type UserCache interface {
	Get(ctx context.Context, id string) (*user.User, error)
	Set(ctx context.Context, u *user.User, ttl time.Duration) error
	Delete(ctx context.Context, id string) error
}

// NewSessionCache adapts a generic Cache into a SessionCache using keys
// "gomodularauth:session:<tokenHash>".
func NewSessionCache(c Cache) SessionCache { return sessionCache{c} }

// NewUserCache adapts a generic Cache into a UserCache using keys
// "gomodularauth:user:<id>".
func NewUserCache(c Cache) UserCache { return userCache{c} }

type sessionCache struct{ c Cache }

func (s sessionCache) Get(ctx context.Context, tokenHash string) (*session.Session, error) {
	var out session.Session
	if err := s.c.Get(ctx, Key("session", tokenHash), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (s sessionCache) Set(ctx context.Context, v *session.Session, ttl time.Duration) error {
	return s.c.Set(ctx, Key("session", v.TokenHash), v, ttl)
}

func (s sessionCache) Delete(ctx context.Context, tokenHash string) error {
	return s.c.Delete(ctx, Key("session", tokenHash))
}

type userCache struct{ c Cache }

func (u userCache) Get(ctx context.Context, id string) (*user.User, error) {
	var out user.User
	if err := u.c.Get(ctx, Key("user", id), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (u userCache) Set(ctx context.Context, v *user.User, ttl time.Duration) error {
	return u.c.Set(ctx, Key("user", v.ID), v, ttl)
}

func (u userCache) Delete(ctx context.Context, id string) error {
	return u.c.Delete(ctx, Key("user", id))
}
