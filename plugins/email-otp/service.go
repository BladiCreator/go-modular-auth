package emailotp

import (
	"context"
	"errors"

	auth "github.com/BladiCreator/go-modular-auth"
	"github.com/BladiCreator/go-modular-auth/account"
	"github.com/BladiCreator/go-modular-auth/adapter"
	"github.com/BladiCreator/go-modular-auth/plugins/email-otp/cache"
	"github.com/BladiCreator/go-modular-auth/email"
	sdk "github.com/BladiCreator/go-modular-auth/plugin-sdk"
	"github.com/BladiCreator/go-modular-auth/store"
	"github.com/BladiCreator/go-modular-auth/user"
)

type service struct {
	ctx     *sdk.Context
	cfg     Config
	otps    *sdk.Repository[OTPRecord]
	sender  email.Sender
	limiter *cache.Limiter
	hooks   *Hooks
}

var _ EmailOTP = (*service)(nil)

func newService(ctx *sdk.Context, cfg Config, sender email.Sender) *service {
	return &service{
		ctx:     ctx,
		cfg:     cfg,
		otps:    sdk.Model[OTPRecord](ctx, ModelEmailOTPs),
		sender:  sender,
		limiter: cache.NewLimiter(ctx.Cache(), cfg.RateLimit.FailurePolicy, ctx.Now),
		hooks:   cfg.Hooks,
	}
}

// Request generates and delivers an OTP code to the provided email address.
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
			if s.cfg.RateLimit.FailurePolicy == cache.FailClosed {
				return ErrCacheFailure
			}
		} else if !ok {
			return ErrCooldownActive
		}

		ok, err = s.limiter.CheckRateLimit(ctx, normEmail, s.cfg.RateLimit.Max, s.cfg.RateLimit.Window)
		if err != nil {
			if s.cfg.RateLimit.FailurePolicy == cache.FailClosed {
				return ErrCacheFailure
			}
		} else if !ok {
			return ErrRateLimitExceeded
		}
	}

	u, err := s.ctx.Store().Users().GetByEmail(ctx, normEmail)
	if errors.Is(err, store.ErrNotFound) {
		if !s.cfg.AllowSignUp {
			// PREVENT USER ENUMERATION:
			// Unknown email returns nil so callers cannot deduce whether the user exists.
			return nil
		}
		// Auto sign-up allowed: issue token bound to the email address
		return s.dispatchOTP(ctx, normEmail, normEmail)
	}
	if err != nil {
		return err
	}

	// User exists: issue token bound to user ID
	return s.dispatchOTP(ctx, normEmail, u.ID)
}

func (s *service) dispatchOTP(ctx context.Context, emailAddress, subject string) error {
	if s.cfg.RevokePreviousOnRequest {
		_ = s.Revoke(ctx, emailAddress)
	}

	code, err := GenerateCode(s.cfg.OTPLength)
	if err != nil {
		return err
	}

	salt, err := GenerateSalt()
	if err != nil {
		return err
	}

	id, err := GenerateID()
	if err != nil {
		return err
	}

	now := s.ctx.Now()
	rec := &OTPRecord{
		ID:          id,
		Email:       emailAddress,
		Subject:     subject,
		Purpose:     string(Purpose),
		OTPHash:     HashOTP(code, salt),
		Salt:        salt,
		ExpiresAt:   now.Add(s.cfg.TTL),
		MaxAttempts: s.cfg.MaxAttempts,
		Attempts:    0,
		CreatedAt:   now,
	}

	if err := s.otps.Create(ctx, rec); err != nil {
		return err
	}

	msg := s.cfg.MessageBuilder(emailAddress, code, s.cfg.TTL)
	if err := s.sender.Send(ctx, msg); err != nil {
		return err
	}

	s.ctx.Events().Publish(ctx, auth.Event{
		Name:    EventOTPRequested,
		Time:    now,
		Subject: subject,
		Payload: OTPRequestedPayload{
			Email:     emailAddress,
			Subject:   subject,
			ExpiresAt: rec.ExpiresAt,
		},
	})

	return nil
}

// Verify validates and atomically consumes the single-use OTP code.
func (s *service) Verify(ctx context.Context, in VerifyInput) (*auth.AuthResult, error) {
	if in.Email == "" {
		return nil, ErrEmailRequired
	}
	if in.Code == "" {
		return nil, ErrCodeRequired
	}

	normEmail, err := user.NormalizeEmail(in.Email)
	if err != nil {
		return nil, ErrInvalidEmail
	}
	in.Email = normEmail

	if err := s.hooks.runBeforeVerify(ctx, &in); err != nil {
		return nil, err
	}

	now := s.ctx.Now()
	recs, err := s.otps.FindMany(ctx, adapter.Query{
		Where: []adapter.Condition{
			adapter.Eq("email", normEmail),
			adapter.IsNull("used_at"),
		},
		SortBy: "created_at",
		Desc:   true,
		Limit:  1,
	})
	if err != nil {
		return nil, err
	}
	if len(recs) == 0 {
		s.publishRejected(ctx, normEmail, "not_found", 0)
		return nil, ErrInvalidCode
	}
	rec := &recs[0]

	if rec.Expired(now) {
		s.publishRejected(ctx, normEmail, "expired", rec.Attempts)
		return nil, ErrCodeExpired
	}

	if rec.Locked() {
		s.publishRejected(ctx, normEmail, "max_attempts_exceeded", rec.Attempts)
		return nil, ErrMaxAttemptsExceeded
	}

	// Constant-time comparison
	if !CompareOTP(in.Code, rec.OTPHash, rec.Salt) {
		newAttempts := rec.Attempts + 1
		_, incErr := s.otps.Update(ctx, []adapter.Condition{adapter.Eq("id", rec.ID)}, map[string]any{"attempts": newAttempts})
		if incErr != nil {
			return nil, incErr
		}

		if newAttempts >= rec.MaxAttempts {
			s.publishRejected(ctx, normEmail, "max_attempts_exceeded", newAttempts)
			return nil, &VerificationError{
				Reason:   "max_attempts_exceeded",
				Attempts: newAttempts,
				Err:      ErrMaxAttemptsExceeded,
			}
		}

		s.publishRejected(ctx, normEmail, "invalid_code", newAttempts)
		return nil, &VerificationError{
			Reason:   "invalid_code",
			Attempts: newAttempts,
			Err:      ErrInvalidCode,
		}
	}

	// Atomic consumption: single-use guarantee and race-condition prevention
	affected, err := s.otps.Update(ctx, []adapter.Condition{
		adapter.Eq("id", rec.ID),
		adapter.IsNull("used_at"),
	}, map[string]any{"used_at": now})
	if err != nil {
		return nil, err
	}
	if affected == 0 {
		s.publishRejected(ctx, normEmail, "already_used", rec.Attempts)
		return nil, ErrCodeAlreadyUsed
	}

	u, err := s.resolveUser(ctx, rec.Subject)
	if err != nil {
		return nil, err
	}

	if !u.EmailVerified {
		u.EmailVerified = true
		u.UpdatedAt = now
		_ = s.ctx.Store().Users().Update(ctx, u)
	}

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
		Name:    EventOTPVerified,
		Time:    now,
		Subject: u.ID,
		Payload: OTPVerifiedPayload{
			UserID:     u.ID,
			Email:      u.Email,
			SessionID:  issued.Session.ID,
			VerifiedAt: now,
		},
	})

	return res, nil
}

func (s *service) publishRejected(ctx context.Context, email, reason string, attempts int) {
	s.ctx.Events().Publish(ctx, auth.Event{
		Name:    EventOTPRejected,
		Time:    s.ctx.Now(),
		Subject: email,
		Payload: OTPRejectedPayload{
			Email:    email,
			Reason:   reason,
			Attempts: attempts,
			Time:     s.ctx.Now(),
		},
	})
}

func (s *service) resolveUser(ctx context.Context, subject string) (*user.User, error) {
	u, err := s.ctx.Store().Users().GetByID(ctx, subject)
	if err == nil {
		return u, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}

	u, err = s.ctx.Store().Users().GetByEmail(ctx, subject)
	if err == nil {
		return u, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}

	if !s.cfg.AllowSignUp {
		return nil, ErrSignUpDisabled
	}

	var newUser *user.User
	now := s.ctx.Now()
	err = s.ctx.Store().Transaction(ctx, func(txCtx context.Context) error {
		uID, err := GenerateID()
		if err != nil {
			return err
		}
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

		accID, err := GenerateID()
		if err != nil {
			return err
		}
		acc := &account.Account{
			ID:         accID,
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

// Revoke invalidates any outstanding OTP codes issued for the email address.
func (s *service) Revoke(ctx context.Context, email string) error {
	normEmail, err := user.NormalizeEmail(email)
	if err != nil {
		return ErrInvalidEmail
	}

	now := s.ctx.Now()
	_, err = s.otps.Update(ctx, []adapter.Condition{
		adapter.Eq("email", normEmail),
		adapter.IsNull("used_at"),
	}, map[string]any{"used_at": now})
	return err
}
