package magiclink

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"

	auth "github.com/BladiCreator/go-modular-auth"
	"github.com/BladiCreator/go-modular-auth-magiclink/cache"
	"github.com/BladiCreator/go-modular-auth/account"
	"github.com/BladiCreator/go-modular-auth/email"
	sdk "github.com/BladiCreator/go-modular-auth/plugin-sdk"
	"github.com/BladiCreator/go-modular-auth/store"
	"github.com/BladiCreator/go-modular-auth/user"
)

type service struct {
	ctx     *sdk.Context
	cfg     Config
	sender  email.Sender
	limiter *cache.Limiter
	hooks   *Hooks
}

var _ MagicLink = (*service)(nil)

func newService(ctx *sdk.Context, cfg Config, sender email.Sender) *service {
	return &service{
		ctx:     ctx,
		cfg:     cfg,
		sender:  sender,
		limiter: cache.NewLimiter(ctx.Cache(), ctx.Now),
		hooks:   cfg.Hooks,
	}
}

// Request initiates passwordless authentication for the given email address.
func (s *service) Request(ctx context.Context, in RequestInput) error {
	if in.Email == "" {
		return ErrEmailRequired
	}

	normEmail, err := user.NormalizeEmail(in.Email)
	if err != nil {
		return ErrInvalidEmail
	}
	in.Email = normEmail

	if err := s.hooks.runBeforeRequest(ctx, &in); err != nil {
		return err
	}

	if s.cfg.RateLimit.Enabled {
		ok, err := s.limiter.CheckAndSetCooldown(ctx, normEmail, s.cfg.RateLimit.Cooldown)
		if err != nil {
			return err
		}
		if !ok {
			return ErrCooldownActive
		}

		ok, err = s.limiter.CheckRateLimit(ctx, normEmail, s.cfg.RateLimit.Max, s.cfg.RateLimit.Window)
		if err != nil {
			return err
		}
		if !ok {
			return ErrRateLimitExceeded
		}
	}

	u, err := s.ctx.Store().Users().GetByEmail(ctx, normEmail)
	if errors.Is(err, store.ErrNotFound) {
		if !s.cfg.AllowSignUp {
			// AVOID USER ENUMERATION:
			// Unknown email returns nil so callers cannot distinguish existing from non-existing accounts.
			return nil
		}

		// Auto sign-up allowed: issue token bound to the email address
		return s.sendToken(ctx, normEmail, normEmail)
	}
	if err != nil {
		return err
	}

	// User exists: issue token bound to the user's ID
	return s.sendToken(ctx, normEmail, u.ID)
}

func (s *service) sendToken(ctx context.Context, emailAddress, subject string) error {
	if s.cfg.RevokePreviousOnRequest {
		_ = s.ctx.Core().RevokeTokens(ctx, Purpose, subject)
	}

	rawToken, err := s.ctx.Core().IssueToken(ctx, Purpose, subject, s.cfg.TTL)
	if err != nil {
		return err
	}

	verificationURL := buildVerificationURL(s.cfg.BaseURL, rawToken)
	msg := s.cfg.MessageBuilder(emailAddress, rawToken, verificationURL)
	if err := s.sender.Send(ctx, msg); err != nil {
		return err
	}

	now := s.ctx.Now()
	s.ctx.Events().Publish(ctx, auth.Event{
		Name:    EventMagicLinkRequested,
		Time:    now,
		Subject: subject,
		Payload: MagicLinkRequestedPayload{
			Email:     emailAddress,
			Subject:   subject,
			ExpiresAt: now.Add(s.cfg.TTL),
		},
	})

	return nil
}

// Authenticate verifies and atomically consumes a magic link token, establishing a session.
func (s *service) Authenticate(ctx context.Context, in AuthenticateInput) (*auth.AuthResult, error) {
	if in.Token == "" {
		return nil, ErrTokenRequired
	}

	if err := s.hooks.runBeforeConsume(ctx, &in); err != nil {
		return nil, err
	}

	// Core ConsumeToken performs atomic verification and single-use consumption.
	tok, err := s.ctx.Core().ConsumeToken(ctx, Purpose, in.Token)
	if err != nil {
		return nil, ErrInvalidToken
	}

	// Resolve the user: subject could be User ID (existing user) or Email (signup flow).
	u, err := s.resolveUser(ctx, tok.Subject)
	if err != nil {
		return nil, err
	}

	// Ensure email is marked verified since possession of the email account was proven.
	if !u.EmailVerified {
		u.EmailVerified = true
		u.UpdatedAt = s.ctx.Now()
		_ = s.ctx.Store().Users().Update(ctx, u)
	}

	// Establish session through Core
	issued, err := s.ctx.Core().CreateSession(ctx, u.ID, in.Session)
	if err != nil {
		return nil, err
	}

	res := &auth.AuthResult{
		User:    u,
		Session: issued.Session,
		Token:   issued.Token,
	}

	s.ctx.Events().Publish(ctx, auth.Event{
		Name:    EventMagicLinkConsumed,
		Time:    s.ctx.Now(),
		Subject: u.ID,
		Payload: MagicLinkConsumedPayload{
			UserID:     u.ID,
			Email:      u.Email,
			SessionID:  issued.Session.ID,
			ConsumedAt: s.ctx.Now(),
		},
	})

	return res, nil
}

func (s *service) resolveUser(ctx context.Context, subject string) (*user.User, error) {
	// First check by ID
	u, err := s.ctx.Store().Users().GetByID(ctx, subject)
	if err == nil {
		return u, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}

	// Subject was an email (signup flow)
	u, err = s.ctx.Store().Users().GetByEmail(ctx, subject)
	if err == nil {
		return u, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}

	// User not found: check if sign up is permitted
	if !s.cfg.AllowSignUp {
		return nil, ErrSignUpDisabled
	}

	// Create user atomically
	var newUser *user.User
	now := s.ctx.Now()
	err = s.ctx.Store().Transaction(ctx, func(txCtx context.Context) error {
		uID := newID()
		newUser = &user.User{
			ID:            uID,
			Email:         subject,
			EmailVerified: true,
			CreatedAt:     now,
			UpdatedAt:     now,
		}
		if err := s.ctx.Store().Users().Create(txCtx, newUser); err != nil {
			return err
		}

		acc := &account.Account{
			ID:         newID(),
			UserID:     newUser.ID,
			Provider:   AccountProvider,
			ProviderID: newUser.ID,
			CreatedAt:  now,
			UpdatedAt:  now,
		}
		return s.ctx.Store().Accounts().Create(txCtx, acc)
	})
	if err != nil {
		return nil, err
	}

	s.ctx.Events().Publish(ctx, auth.Event{
		Name:    auth.EventUserCreated,
		Time:    now,
		Subject: newUser.ID,
		Payload: newUser,
	})

	return newUser, nil
}

// Revoke deletes all active magic link tokens for the given email address.
func (s *service) Revoke(ctx context.Context, email string) error {
	normEmail, err := user.NormalizeEmail(email)
	if err != nil {
		return ErrInvalidEmail
	}

	// Revoke tokens issued with email as subject
	_ = s.ctx.Core().RevokeTokens(ctx, Purpose, normEmail)

	// If a user exists with this email, also revoke tokens issued with User ID
	if u, err := s.ctx.Store().Users().GetByEmail(ctx, normEmail); err == nil {
		_ = s.ctx.Core().RevokeTokens(ctx, Purpose, u.ID)
	}

	return nil
}

func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
