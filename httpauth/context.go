package httpauth

import (
	"context"

	"github.com/BladiCreator/go-modular-auth/domain/dto"
	"github.com/BladiCreator/go-modular-auth/domain/entity"
)

type contextKey struct {
	name string
}

func (k *contextKey) String() string {
	return "httpauth context key: " + k.name
}

var (
	sessionContextKey = &contextKey{name: "session"}
	userContextKey    = &contextKey{name: "user"}
)

// WithSession stores an authenticated *entity.Session into the context using a private key.
func WithSession(ctx context.Context, session *entity.Session) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, sessionContextKey, session)
}

// SessionFromContext extracts the authenticated *entity.Session from the context.
// Returns (nil, false) if no session was stored or if the value is not a valid *entity.Session.
func SessionFromContext(ctx context.Context) (*entity.Session, bool) {
	if ctx == nil {
		return nil, false
	}
	session, ok := ctx.Value(sessionContextKey).(*entity.Session)
	return session, ok && session != nil
}

// WithUser stores an authenticated *entity.User into the context using a private key.
func WithUser(ctx context.Context, user *entity.User) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, userContextKey, user)
}

// UserFromContext extracts the authenticated *entity.User from the context.
// Returns (nil, false) if no user was stored or if the value is not a valid *entity.User.
func UserFromContext(ctx context.Context) (*entity.User, bool) {
	if ctx == nil {
		return nil, false
	}
	user, ok := ctx.Value(userContextKey).(*entity.User)
	return user, ok && user != nil
}

// WithSessionData injects both Session and User from a *dto.SessionData into the context.
func WithSessionData(ctx context.Context, data *dto.SessionData) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if data == nil {
		return ctx
	}
	if data.Session != nil {
		ctx = WithSession(ctx, data.Session)
	}
	if data.User != nil {
		ctx = WithUser(ctx, data.User)
	}
	return ctx
}

// SessionDataFromContext reconstructs a *dto.SessionData if either a session or user is present in the context.
// Returns (nil, false) if neither is found.
func SessionDataFromContext(ctx context.Context) (*dto.SessionData, bool) {
	sess, hasSess := SessionFromContext(ctx)
	user, hasUser := UserFromContext(ctx)
	if !hasSess && !hasUser {
		return nil, false
	}

	return &dto.SessionData{
		Session: sess,
		User:    user,
	}, true
}
