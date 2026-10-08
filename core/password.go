package auth

import (
	"context"
	"errors"

	"github.com/BladiCreator/go-modular-auth/credential"
	"github.com/BladiCreator/go-modular-auth/internal/secure"
	"github.com/BladiCreator/go-modular-auth/session"
	"github.com/BladiCreator/go-modular-auth/store"
	"github.com/BladiCreator/go-modular-auth/user"
	"github.com/BladiCreator/go-modular-auth/verification"
)

// ChangePasswordInput changes the password of an authenticated user.
type ChangePasswordInput struct {
	UserID          string
	CurrentPassword string
	NewPassword     string
	// CurrentSessionID is kept alive; every other session is revoked unless
	// KeepOtherSessions is true.
	CurrentSessionID  string
	KeepOtherSessions bool
}

// RequestPasswordResetInput starts a password reset.
type RequestPasswordResetInput struct {
	Email string
}

// ResetPasswordInput completes a password reset.
type ResetPasswordInput struct {
	Token       string
	NewPassword string
}

// VerifyEmailInput completes an email verification.
type VerifyEmailInput struct {
	Token string
}

// ChangePassword verifies the current password and rotates the credential.
func (a *Auth) ChangePassword(ctx context.Context, in ChangePasswordInput) error {
	if err := a.checkPasswordPolicy(in.NewPassword); err != nil {
		return err
	}
	if err := a.verifyPassword(ctx, in.UserID, in.CurrentPassword); err != nil {
		return err
	}
	hash, err := a.hasher.Hash(ctx, in.NewPassword)
	if err != nil {
		return err
	}
	var revoked []*session.Session
	err = a.store.Transaction(ctx, func(ctx context.Context) error {
		if err := a.rotatePassword(ctx, in.UserID, hash); err != nil {
			return err
		}
		if in.KeepOtherSessions {
			return nil
		}
		var err error
		revoked, err = a.revokeUserSessions(ctx, in.UserID, in.CurrentSessionID)
		return err
	})
	if err != nil {
		return err
	}
	a.afterSessionsRevoked(ctx, revoked)
	a.publish(ctx, EventPasswordChanged, in.UserID, nil)
	return nil
}

// RequestPasswordReset emails a reset token. It returns nil when the email is
// unknown so the endpoint cannot be used to enumerate users.
func (a *Auth) RequestPasswordReset(ctx context.Context, in RequestPasswordResetInput) error {
	if a.email == nil {
		return ErrEmailNotConfigured
	}
	email, err := user.NormalizeEmail(in.Email)
	if err != nil {
		return ErrInvalidEmail
	}
	u, err := a.store.Users().GetByEmail(ctx, email)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if _, err := a.passwordCredential(ctx, u.ID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		return err
	}
	// Only the most recent reset token is valid.
	if err := a.RevokeTokens(ctx, verification.PurposePasswordReset, u.ID); err != nil {
		return err
	}
	token, err := a.IssueToken(ctx, verification.PurposePasswordReset, u.ID, a.cfg.PasswordReset.TokenTTL)
	if err != nil {
		return err
	}
	msg := a.cfg.Messages.PasswordReset(u, token)
	msg.To = u.Email
	return a.email.Send(ctx, msg)
}

// ResetPassword consumes a reset token, rotates the password credential and
// revokes every session of the user, atomically.
func (a *Auth) ResetPassword(ctx context.Context, in ResetPasswordInput) error {
	if err := a.checkPasswordPolicy(in.NewPassword); err != nil {
		return err
	}
	hash, err := a.hasher.Hash(ctx, in.NewPassword)
	if err != nil {
		return err
	}
	var (
		userID  string
		revoked []*session.Session
	)
	err = a.store.Transaction(ctx, func(ctx context.Context) error {
		t, err := a.ConsumeToken(ctx, verification.PurposePasswordReset, in.Token)
		if err != nil {
			return err
		}
		userID = t.Subject
		if err := a.rotatePassword(ctx, userID, hash); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return ErrInvalidToken
			}
			return err
		}
		revoked, err = a.revokeUserSessions(ctx, userID, "")
		return err
	})
	if err != nil {
		return err
	}
	a.afterSessionsRevoked(ctx, revoked)
	a.publish(ctx, EventPasswordChanged, userID, nil)
	return nil
}

// RequestEmailVerification emails a verification token to the user. It is a
// no-op for already verified users.
func (a *Auth) RequestEmailVerification(ctx context.Context, userID string) error {
	if a.email == nil {
		return ErrEmailNotConfigured
	}
	u, err := a.store.Users().GetByID(ctx, userID)
	if errors.Is(err, store.ErrNotFound) {
		return ErrUserNotFound
	}
	if err != nil {
		return err
	}
	return a.sendVerificationEmail(ctx, u)
}

func (a *Auth) sendVerificationEmail(ctx context.Context, u *user.User) error {
	if u.EmailVerified {
		return nil
	}
	if err := a.RevokeTokens(ctx, verification.PurposeEmailVerification, u.ID); err != nil {
		return err
	}
	token, err := a.IssueToken(ctx, verification.PurposeEmailVerification, u.ID, a.cfg.EmailVerification.TokenTTL)
	if err != nil {
		return err
	}
	msg := a.cfg.Messages.EmailVerification(u, token)
	msg.To = u.Email
	return a.email.Send(ctx, msg)
}

// VerifyEmail consumes a verification token and marks the email as verified.
func (a *Auth) VerifyEmail(ctx context.Context, in VerifyEmailInput) (*user.User, error) {
	var u *user.User
	err := a.store.Transaction(ctx, func(ctx context.Context) error {
		t, err := a.ConsumeToken(ctx, verification.PurposeEmailVerification, in.Token)
		if err != nil {
			return err
		}
		u, err = a.store.Users().GetByID(ctx, t.Subject)
		if errors.Is(err, store.ErrNotFound) {
			return ErrInvalidToken
		}
		if err != nil {
			return err
		}
		if u.EmailVerified {
			return nil
		}
		u.EmailVerified = true
		u.UpdatedAt = a.Now()
		return a.store.Users().Update(ctx, u)
	})
	if err != nil {
		return nil, err
	}
	a.invalidateUser(ctx, u.ID)
	a.publish(ctx, EventEmailVerified, u.ID, u)
	return u, nil
}

// rotatePassword revokes the active password credential and creates a new
// one, keeping an auditable history. Must run inside a transaction.
func (a *Auth) rotatePassword(ctx context.Context, userID, hash string) error {
	old, err := a.passwordCredential(ctx, userID)
	if err != nil {
		return err
	}
	now := a.Now()
	if err := a.store.Credentials().Revoke(ctx, old.ID, now); err != nil {
		return err
	}
	return a.store.Credentials().Create(ctx, &credential.Credential{
		ID: secure.NewID(), UserID: userID, AccountID: old.AccountID,
		Type: credential.TypePassword, Secret: hash,
		CreatedAt: now, UpdatedAt: now,
	})
}
