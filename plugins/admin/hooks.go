package admin

import (
	"context"
	"errors"

	auth "github.com/BladiCreator/go-modular-auth"
	"github.com/BladiCreator/go-modular-auth-admin/store"
	corestore "github.com/BladiCreator/go-modular-auth/store"
	"github.com/BladiCreator/go-modular-auth/user"
)

// registerHooks attaches administrative security and lifecycle hooks to GoModularAuth core.
func (s *service) registerHooks() {
	if s.ctx == nil || s.ctx.Hooks() == nil {
		return
	}

	hooks := s.ctx.Hooks()

	// BeforeSignIn: Intercept sign-in attempts to prevent disabled users from authenticating.
	hooks.BeforeSignIn(func(ctx context.Context, in *auth.SignInInput) error {
		if in == nil || in.Email == "" {
			return nil
		}

		email, err := user.NormalizeEmail(in.Email)
		if err != nil {
			return nil // Let Core handle invalid email formatting
		}

		// Check if user exists in core store
		u, err := s.ctx.Store().Users().GetByEmail(ctx, email)
		if err != nil {
			if errors.Is(err, corestore.ErrNotFound) {
				return nil // Non-existent user, let Core handle credential check timing
			}
			return err
		}

		// Check disabled status via cache-aside
		disabled, err := s.IsUserDisabled(ctx, u.ID)
		if err != nil {
			return err
		}

		if disabled {
			return ErrUserDisabled
		}

		return nil
	})

	// AfterUserCreate: Ensure every newly registered user is indexed in the administrative store.
	hooks.AfterUserCreate(func(ctx context.Context, u *user.User) {
		if u == nil || s.store == nil {
			return
		}

		_ = s.store.UpsertUser(ctx, &store.UserRecord{
			UserID:    u.ID,
			Email:     u.Email,
			Disabled:  false,
			CreatedAt: u.CreatedAt,
			UpdatedAt: u.UpdatedAt,
		})
	})
}
