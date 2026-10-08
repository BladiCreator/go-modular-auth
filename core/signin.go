package auth

import (
	"context"
	"errors"

	"github.com/BladiCreator/go-modular-auth/account"
	"github.com/BladiCreator/go-modular-auth/credential"
	"github.com/BladiCreator/go-modular-auth/internal/secure"
	"github.com/BladiCreator/go-modular-auth/password"
	"github.com/BladiCreator/go-modular-auth/session"
	"github.com/BladiCreator/go-modular-auth/store"
	"github.com/BladiCreator/go-modular-auth/user"
)

// SignUpInput registers a user with email and password.
type SignUpInput struct {
	Email    string
	Password string
	Session  SessionOptions
}

// SignInInput authenticates a user with email and password.
type SignInInput struct {
	Email    string
	Password string
	Session  SessionOptions
}

// SignOutInput ends the session identified by Token.
type SignOutInput struct {
	Token string
}

// AuthResult is the outcome of SignUp/SignIn. Session and Token are empty
// when SignUp does not issue a session (email verification required).
type AuthResult struct {
	User    *user.User
	Session *session.Session
	Token   string
}

// Principal returns the authenticated identity.
func (r *AuthResult) Principal() Principal {
	return Principal{Subject: r.User.ID, Type: PrincipalUser}
}

// SignUp creates User + password Account + Credential (+ Session) in a single
// Store transaction. Cache population, events and After hooks run after commit.
func (a *Auth) SignUp(ctx context.Context, in SignUpInput) (*AuthResult, error) {
	if err := a.hooks.beforeSignUp.run(ctx, &in); err != nil {
		return nil, err
	}
	email, err := user.NormalizeEmail(in.Email)
	if err != nil {
		return nil, ErrInvalidEmail
	}
	if err := a.checkPasswordPolicy(in.Password); err != nil {
		return nil, err
	}
	// Hash outside the transaction: it is deliberately slow.
	hash, err := a.hasher.Hash(ctx, in.Password)
	if err != nil {
		return nil, err
	}

	now := a.Now()
	u := &user.User{ID: secure.NewID(), Email: email, CreatedAt: now, UpdatedAt: now}
	res := &AuthResult{User: u}
	err = a.store.Transaction(ctx, func(ctx context.Context) error {
		if _, err := a.store.Users().GetByEmail(ctx, email); err == nil {
			return ErrEmailAlreadyExists
		} else if !errors.Is(err, store.ErrNotFound) {
			return err
		}
		if err := a.hooks.beforeUserCreate.run(ctx, u); err != nil {
			return err
		}
		if err := a.store.Users().Create(ctx, u); err != nil {
			if errors.Is(err, store.ErrConflict) {
				return ErrEmailAlreadyExists
			}
			return err
		}
		acc := &account.Account{
			ID: secure.NewID(), UserID: u.ID,
			Provider: account.ProviderPassword, ProviderID: u.ID,
			CreatedAt: now, UpdatedAt: now,
		}
		if err := a.store.Accounts().Create(ctx, acc); err != nil {
			return err
		}
		if err := a.store.Credentials().Create(ctx, &credential.Credential{
			ID: secure.NewID(), UserID: u.ID, AccountID: acc.ID,
			Type: credential.TypePassword, Secret: hash,
			CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			return err
		}
		if a.cfg.EmailVerification.Required {
			return nil
		}
		issued, err := a.newSession(ctx, u.ID, in.Session)
		if err != nil {
			return err
		}
		res.Session, res.Token = issued.Session, issued.Token
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Post-commit side effects.
	a.cacheUser(ctx, u)
	a.publish(ctx, EventUserCreated, u.ID, u)
	a.hooks.afterUserCreate.run(ctx, u)
	if res.Session != nil {
		a.afterSessionCreated(ctx, res.Session)
	}
	if a.cfg.EmailVerification.SendOnSignUp {
		if err := a.sendVerificationEmail(ctx, u); err != nil {
			a.logger.ErrorContext(ctx, "auth: failed to send verification email on sign up", "user_id", u.ID, "error", err)
		}
	}
	a.hooks.afterSignUp.run(ctx, res)
	return res, nil
}

// SignIn verifies email and password and issues a session.
//
// Unknown email and wrong password both return ErrInvalidCredentials after
// a comparable amount of work, preventing user enumeration by timing.
func (a *Auth) SignIn(ctx context.Context, in SignInInput) (*AuthResult, error) {
	if err := a.hooks.beforeSignIn.run(ctx, &in); err != nil {
		return nil, err
	}
	email, err := user.NormalizeEmail(in.Email)
	if err != nil || len(in.Password) > a.cfg.Password.MaxLength {
		return nil, ErrInvalidCredentials
	}
	u, err := a.store.Users().GetByEmail(ctx, email)
	if errors.Is(err, store.ErrNotFound) {
		_ = a.hasher.Verify(ctx, a.dummyHash(), in.Password)
		return nil, ErrInvalidCredentials
	}
	if err != nil {
		return nil, err
	}
	if err := a.verifyPassword(ctx, u.ID, in.Password); err != nil {
		return nil, err
	}
	// Checked after the password so it does not leak account existence.
	if a.cfg.EmailVerification.Required && !u.EmailVerified {
		return nil, ErrEmailNotVerified
	}

	var issued *IssuedSession
	err = a.store.Transaction(ctx, func(ctx context.Context) error {
		var err error
		issued, err = a.newSession(ctx, u.ID, in.Session)
		return err
	})
	if err != nil {
		return nil, err
	}
	a.cacheUser(ctx, u)
	a.afterSessionCreated(ctx, issued.Session)
	res := &AuthResult{User: u, Session: issued.Session, Token: issued.Token}
	a.publish(ctx, EventUserSignedIn, u.ID, res.Session)
	a.hooks.afterSignIn.run(ctx, res)
	return res, nil
}

// SignOut revokes the session identified by the token. Unknown or already
// revoked tokens are a no-op, making SignOut idempotent.
func (a *Auth) SignOut(ctx context.Context, in SignOutInput) error {
	if err := a.hooks.beforeSignOut.run(ctx, &in); err != nil {
		return err
	}
	if in.Token == "" {
		return nil
	}
	s, err := a.store.Sessions().GetByTokenHash(ctx, secure.HashToken(in.Token))
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if s.Revoked() {
		a.invalidateSessions(ctx, s)
		return nil
	}
	now := a.Now()
	if err := a.store.Sessions().Revoke(ctx, s.ID, now); err != nil {
		return err
	}
	s.RevokedAt = &now
	a.invalidateSessions(ctx, s)
	a.publish(ctx, EventSessionRevoked, s.UserID, s)
	a.publish(ctx, EventUserSignedOut, s.UserID, s)
	a.hooks.afterSignOut.run(ctx, s)
	return nil
}

// passwordCredential loads the active password credential of a user.
func (a *Auth) passwordCredential(ctx context.Context, userID string) (*credential.Credential, error) {
	acc, err := a.store.Accounts().GetByProvider(ctx, account.ProviderPassword, userID)
	if err != nil {
		return nil, err
	}
	return a.store.Credentials().GetActiveByAccount(ctx, acc.ID, credential.TypePassword)
}

// verifyPassword checks a plaintext password against the user's credential.
func (a *Auth) verifyPassword(ctx context.Context, userID, plain string) error {
	cred, err := a.passwordCredential(ctx, userID)
	if errors.Is(err, store.ErrNotFound) {
		// e.g. OAuth-only user: keep timing comparable.
		_ = a.hasher.Verify(ctx, a.dummyHash(), plain)
		return ErrInvalidCredentials
	}
	if err != nil {
		return err
	}
	if err := a.hasher.Verify(ctx, cred.Secret, plain); err != nil {
		if errors.Is(err, password.ErrMismatch) {
			return ErrInvalidCredentials
		}
		return err
	}
	return nil
}

func (a *Auth) checkPasswordPolicy(p string) error {
	if len(p) < a.cfg.Password.MinLength || len(p) > a.cfg.Password.MaxLength {
		return ErrInvalidPassword
	}
	return nil
}
