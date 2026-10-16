package auth

import (
	"context"
	"errors"

	"github.com/BladiCreator/go-modular-auth/store"
	"github.com/BladiCreator/go-modular-auth/user"
)

// GetUser returns the user with the given ID, or (nil, nil) when it does not exist.
func (a *Auth) GetUser(ctx context.Context, userID string) (*user.User, error) {
	if userID == "" {
		return nil, nil
	}
	if u := a.cachedUser(ctx, userID); u != nil {
		return u, nil
	}
	u, err := a.store.Users().GetByID(ctx, userID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	a.cacheUser(ctx, u)
	return u, nil
}

// RequireUser is like GetUser but returns ErrUserNotFound when the user does not exist.
func (a *Auth) RequireUser(ctx context.Context, userID string) (*user.User, error) {
	u, err := a.GetUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	if u == nil {
		return nil, ErrUserNotFound
	}
	return u, nil
}
