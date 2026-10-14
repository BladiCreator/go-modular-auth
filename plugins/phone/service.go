package phone

import (
	"context"
	"errors"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	"github.com/BladiCreator/go-modular-auth-phone/cache"
	"github.com/BladiCreator/go-modular-auth/account"
	"github.com/BladiCreator/go-modular-auth/adapter"
	sdk "github.com/BladiCreator/go-modular-auth/plugin-sdk"
	"github.com/BladiCreator/go-modular-auth/store"
	"github.com/BladiCreator/go-modular-auth/user"
)

type service struct {
	ctx      *sdk.Context
	cfg      Config
	provider PhoneProvider
	limiter  *cache.Limiter
	cache    *PhoneCache
	hooks    *Hooks
}

var _ Phone = (*service)(nil)

func newService(ctx *sdk.Context, cfg Config) *service {
	return &service{
		ctx:      ctx,
		cfg:      cfg,
		provider: cfg.Provider,
		limiter:  cache.NewLimiter(ctx.Cache(), cfg.RateLimit.FailurePolicy, ctx.Now),
		cache:    NewPhoneCache(ctx.Cache(), cfg.CacheTTL),
		hooks:    cfg.Hooks,
	}
}

// Normalize transforms a raw phone string into canonical E.164 format.
func (s *service) Normalize(raw string) (string, error) {
	return s.cfg.Normalizer(raw)
}

// Validate checks whether a normalized phone number complies with ITU-T E.164.
func (s *service) Validate(normalized string) error {
	return s.cfg.Validator(normalized)
}

// RequestOTP dispatches an authentication OTP code to the provided phone number.
func (s *service) RequestOTP(ctx context.Context, in RequestOTPInput) error {
	if in.PhoneNumber == "" {
		return ErrPhoneRequired
	}

	normPhone, err := s.Normalize(in.PhoneNumber)
	if err != nil {
		return ErrInvalidPhone
	}
	if err := s.Validate(normPhone); err != nil {
		return err
	}
	in.PhoneNumber = normPhone

	if err := s.hooks.runBeforeRequestOTP(ctx, &in); err != nil {
		return err
	}

	if s.cfg.RateLimit.Enabled {
		ok, err := s.limiter.CheckAndSetCooldown(ctx, normPhone, s.cfg.RateLimit.Cooldown)
		if err != nil {
			if s.cfg.RateLimit.FailurePolicy == cache.FailClosed {
				return ErrCacheFailure
			}
		} else if !ok {
			return ErrCooldownActive
		}

		ok, err = s.limiter.CheckRateLimit(ctx, normPhone, s.cfg.RateLimit.Max, s.cfg.RateLimit.Window)
		if err != nil {
			if s.cfg.RateLimit.FailurePolicy == cache.FailClosed {
				return ErrCacheFailure
			}
		} else if !ok {
			return ErrRateLimitExceeded
		}
	}

	existing, err := s.getPhoneByNumber(ctx, normPhone)
	if errors.Is(err, ErrPhoneNotFound) {
		if !s.cfg.AllowSignUp {
			// ENUMERATION PROTECTION:
			// Unknown phone returns nil so callers cannot deduce whether the phone exists.
			return nil
		}
		return s.dispatchOTP(ctx, normPhone, normPhone, PurposeAuthenticate, in.Metadata)
	}
	if err != nil {
		return err
	}

	return s.dispatchOTP(ctx, normPhone, existing.UserID, PurposeAuthenticate, in.Metadata)
}

// VerifyOTP validates and atomically consumes the single-use OTP code, establishing a session.
func (s *service) VerifyOTP(ctx context.Context, in VerifyOTPInput) (*auth.AuthResult, error) {
	if in.PhoneNumber == "" {
		return nil, ErrPhoneRequired
	}
	if in.Code == "" {
		return nil, ErrCodeRequired
	}

	normPhone, err := s.Normalize(in.PhoneNumber)
	if err != nil {
		return nil, ErrInvalidPhone
	}
	in.PhoneNumber = normPhone

	if err := s.hooks.runBeforeVerifyOTP(ctx, &in); err != nil {
		return nil, err
	}

	now := s.ctx.Now()
	rec, err := s.getActiveOTP(ctx, normPhone, PurposeAuthenticate, now)
	if errors.Is(err, adapter.ErrNotFound) {
		s.publishRejected(ctx, normPhone, "not_found", 0)
		return nil, ErrInvalidCode
	}
	if err != nil {
		return nil, err
	}

	if rec.Used() {
		s.publishRejected(ctx, normPhone, "already_used", rec.Attempts)
		return nil, ErrCodeAlreadyUsed
	}

	if rec.Expired(now) {
		s.publishRejected(ctx, normPhone, "expired", rec.Attempts)
		return nil, ErrCodeExpired
	}

	if rec.Locked() {
		s.publishRejected(ctx, normPhone, "max_attempts_exceeded", rec.Attempts)
		return nil, ErrMaxAttemptsExceeded
	}

	// Constant-time hash verification
	if !CompareOTP(in.Code, rec.OTPHash, rec.Salt) {
		attempts, incErr := s.incrementOTPAttempts(ctx, rec.ID)
		if incErr != nil {
			return nil, incErr
		}

		if attempts >= rec.MaxAttempts {
			s.publishRejected(ctx, normPhone, "max_attempts_exceeded", attempts)
			return nil, &VerificationError{
				Reason:   "max_attempts_exceeded",
				Attempts: attempts,
				Err:      ErrMaxAttemptsExceeded,
			}
		}

		s.publishRejected(ctx, normPhone, "invalid_code", attempts)
		return nil, &VerificationError{
			Reason:   "invalid_code",
			Attempts: attempts,
			Err:      ErrInvalidCode,
		}
	}

	// Atomic consumption preventing replay and concurrency races
	if err := s.markOTPUsed(ctx, rec.ID, now); err != nil {
		if errors.Is(err, adapter.ErrConflict) {
			s.publishRejected(ctx, normPhone, "already_used", rec.Attempts)
			return nil, ErrCodeAlreadyUsed
		}
		return nil, err
	}

	u, err := s.resolveUser(ctx, normPhone, rec.Subject, in.Email)
	if err != nil {
		return nil, err
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
		Name:    EventPhoneOTPVerified,
		Time:    now,
		Subject: normPhone,
		Payload: OTPVerifiedPayload{
			UserID:      u.ID,
			PhoneNumber: normPhone,
			SessionID:   issued.Session.ID,
			VerifiedAt:  now,
		},
	})

	return res, nil
}

// RequestVerification dispatches an OTP to verify a user's ownership of a phone number.
func (s *service) RequestVerification(ctx context.Context, in RequestVerificationInput) error {
	if in.UserID == "" {
		return ErrUserNotFound
	}
	if in.PhoneNumber == "" {
		return ErrPhoneRequired
	}

	normPhone, err := s.Normalize(in.PhoneNumber)
	if err != nil {
		return ErrInvalidPhone
	}
	if err := s.Validate(normPhone); err != nil {
		return err
	}
	in.PhoneNumber = normPhone

	if _, err := s.ctx.Core().RequireUser(ctx, in.UserID); err != nil {
		return ErrUserNotFound
	}

	existing, err := s.getPhoneByNumber(ctx, normPhone)
	if err == nil && existing.UserID != in.UserID {
		return ErrPhoneAlreadyExists
	}
	if err != nil && !errors.Is(err, ErrPhoneNotFound) {
		return err
	}

	now := s.ctx.Now()
	userPhone, err := s.getPhoneByUserID(ctx, in.UserID)
	if errors.Is(err, ErrPhoneNotFound) {
		id, err := GenerateID()
		if err != nil {
			return err
		}
		p := &PhoneRecord{
			ID:          id,
			UserID:      in.UserID,
			PhoneNumber: normPhone,
			Verified:    false,
			CreatedAt:   now,
			UpdatedAt:   now,
		}
		if err := s.createPhone(ctx, p); err != nil {
			return err
		}
	} else if err != nil {
		return err
	} else if userPhone.PhoneNumber != normPhone {
		userPhone.PhoneNumber = normPhone
		userPhone.Verified = false
		userPhone.VerifiedAt = nil
		userPhone.UpdatedAt = now
		if err := s.updatePhone(ctx, userPhone); err != nil {
			return err
		}
		s.cache.Invalidate(ctx, in.UserID, normPhone)
	}

	return s.dispatchOTP(ctx, normPhone, in.UserID, PurposeVerify, in.Metadata)
}

// ConfirmVerification validates the OTP and marks the user's phone record as verified.
func (s *service) ConfirmVerification(ctx context.Context, in ConfirmVerificationInput) (*Record, error) {
	if in.UserID == "" {
		return nil, ErrUserNotFound
	}
	if in.PhoneNumber == "" {
		return nil, ErrPhoneRequired
	}
	if in.Code == "" {
		return nil, ErrCodeRequired
	}

	normPhone, err := s.Normalize(in.PhoneNumber)
	if err != nil {
		return nil, ErrInvalidPhone
	}

	now := s.ctx.Now()
	rec, err := s.getActiveOTP(ctx, normPhone, PurposeVerify, now)
	if errors.Is(err, adapter.ErrNotFound) {
		s.publishRejected(ctx, normPhone, "not_found", 0)
		return nil, ErrInvalidCode
	}
	if err != nil {
		return nil, err
	}

	if rec.Used() {
		s.publishRejected(ctx, normPhone, "already_used", rec.Attempts)
		return nil, ErrCodeAlreadyUsed
	}

	if rec.Expired(now) {
		s.publishRejected(ctx, normPhone, "expired", rec.Attempts)
		return nil, ErrCodeExpired
	}

	if rec.Locked() {
		s.publishRejected(ctx, normPhone, "max_attempts_exceeded", rec.Attempts)
		return nil, ErrMaxAttemptsExceeded
	}

	if !CompareOTP(in.Code, rec.OTPHash, rec.Salt) {
		attempts, incErr := s.incrementOTPAttempts(ctx, rec.ID)
		if incErr != nil {
			return nil, incErr
		}
		if attempts >= rec.MaxAttempts {
			s.publishRejected(ctx, normPhone, "max_attempts_exceeded", attempts)
			return nil, &VerificationError{Reason: "max_attempts_exceeded", Attempts: attempts, Err: ErrMaxAttemptsExceeded}
		}
		s.publishRejected(ctx, normPhone, "invalid_code", attempts)
		return nil, &VerificationError{Reason: "invalid_code", Attempts: attempts, Err: ErrInvalidCode}
	}

	if err := s.markOTPUsed(ctx, rec.ID, now); err != nil {
		if errors.Is(err, adapter.ErrConflict) {
			s.publishRejected(ctx, normPhone, "already_used", rec.Attempts)
			return nil, ErrCodeAlreadyUsed
		}
		return nil, err
	}

	userPhone, err := s.getPhoneByUserID(ctx, in.UserID)
	if err != nil {
		if errors.Is(err, ErrPhoneNotFound) {
			return nil, ErrPhoneNotFound
		}
		return nil, err
	}

	userPhone.Verified = true
	userPhone.VerifiedAt = &now
	userPhone.UpdatedAt = now

	if err := s.updatePhone(ctx, userPhone); err != nil {
		return nil, err
	}

	// Link Account in Core if not already linked
	_, err = s.ctx.Store().Accounts().GetByProvider(ctx, AccountProvider, normPhone)
	if errors.Is(err, store.ErrNotFound) {
		accID, _ := GenerateID()
		_ = s.ctx.Store().Accounts().Create(ctx, &account.Account{
			ID:         accID,
			UserID:     in.UserID,
			Provider:   AccountProvider,
			ProviderID: normPhone,
			CreatedAt:  now,
			UpdatedAt:  now,
		})
	}

	s.cache.Invalidate(ctx, in.UserID, normPhone)

	s.ctx.Events().Publish(ctx, auth.Event{
		Name:    EventPhoneVerified,
		Time:    now,
		Subject: in.UserID,
		Payload: PhoneVerifiedPayload{
			UserID:      in.UserID,
			PhoneNumber: normPhone,
			VerifiedAt:  now,
		},
	})

	return userPhone, nil
}

// RequestChange dispatches an OTP to a new phone number to begin changing the user's phone number.
func (s *service) RequestChange(ctx context.Context, in RequestChangeInput) error {
	if in.UserID == "" {
		return ErrUserNotFound
	}
	if in.NewPhoneNumber == "" {
		return ErrPhoneRequired
	}

	normNew, err := s.Normalize(in.NewPhoneNumber)
	if err != nil {
		return ErrInvalidPhone
	}
	if err := s.Validate(normNew); err != nil {
		return err
	}
	in.NewPhoneNumber = normNew

	if err := s.hooks.runBeforeChange(ctx, &in); err != nil {
		return err
	}

	if _, err := s.ctx.Core().RequireUser(ctx, in.UserID); err != nil {
		return ErrUserNotFound
	}

	current, err := s.getPhoneByUserID(ctx, in.UserID)
	if err != nil {
		if errors.Is(err, ErrPhoneNotFound) {
			return ErrPhoneNotFound
		}
		return err
	}

	if current.PhoneNumber == normNew {
		// New number is already current number
		return nil
	}

	other, err := s.getPhoneByNumber(ctx, normNew)
	if err == nil && other.UserID != in.UserID {
		return ErrPhoneAlreadyExists
	}
	if err != nil && !errors.Is(err, ErrPhoneNotFound) {
		return err
	}

	subject := in.UserID + ":" + normNew
	return s.dispatchOTP(ctx, normNew, subject, PurposeChange, in.Metadata)
}

// ConfirmChange validates the OTP sent to the new phone and atomically updates the user's phone number.
func (s *service) ConfirmChange(ctx context.Context, in ConfirmChangeInput) (*Record, error) {
	if in.UserID == "" {
		return nil, ErrUserNotFound
	}
	if in.NewPhoneNumber == "" {
		return nil, ErrPhoneRequired
	}
	if in.Code == "" {
		return nil, ErrCodeRequired
	}

	normNew, err := s.Normalize(in.NewPhoneNumber)
	if err != nil {
		return nil, ErrInvalidPhone
	}

	now := s.ctx.Now()
	rec, err := s.getActiveOTP(ctx, normNew, PurposeChange, now)
	if errors.Is(err, adapter.ErrNotFound) {
		s.publishRejected(ctx, normNew, "not_found", 0)
		return nil, ErrInvalidCode
	}
	if err != nil {
		return nil, err
	}

	if rec.Used() {
		s.publishRejected(ctx, normNew, "already_used", rec.Attempts)
		return nil, ErrCodeAlreadyUsed
	}

	if rec.Expired(now) {
		s.publishRejected(ctx, normNew, "expired", rec.Attempts)
		return nil, ErrCodeExpired
	}

	if rec.Locked() {
		s.publishRejected(ctx, normNew, "max_attempts_exceeded", rec.Attempts)
		return nil, ErrMaxAttemptsExceeded
	}

	if !CompareOTP(in.Code, rec.OTPHash, rec.Salt) {
		attempts, incErr := s.incrementOTPAttempts(ctx, rec.ID)
		if incErr != nil {
			return nil, incErr
		}
		if attempts >= rec.MaxAttempts {
			s.publishRejected(ctx, normNew, "max_attempts_exceeded", attempts)
			return nil, &VerificationError{Reason: "max_attempts_exceeded", Attempts: attempts, Err: ErrMaxAttemptsExceeded}
		}
		s.publishRejected(ctx, normNew, "invalid_code", attempts)
		return nil, &VerificationError{Reason: "invalid_code", Attempts: attempts, Err: ErrInvalidCode}
	}

	if err := s.markOTPUsed(ctx, rec.ID, now); err != nil {
		if errors.Is(err, adapter.ErrConflict) {
			s.publishRejected(ctx, normNew, "already_used", rec.Attempts)
			return nil, ErrCodeAlreadyUsed
		}
		return nil, err
	}

	current, err := s.getPhoneByUserID(ctx, in.UserID)
	if err != nil {
		if errors.Is(err, ErrPhoneNotFound) {
			return nil, ErrPhoneNotFound
		}
		return nil, err
	}

	oldPhone := current.PhoneNumber
	current.PhoneNumber = normNew
	current.Verified = true
	current.VerifiedAt = &now
	current.UpdatedAt = now

	if err := s.updatePhone(ctx, current); err != nil {
		return nil, err
	}

	// Update or create Core account mapping
	acc, err := s.ctx.Store().Accounts().GetByProvider(ctx, AccountProvider, oldPhone)
	if err == nil {
		_ = s.ctx.Store().Accounts().Delete(ctx, acc.ID)
	}
	newAccID, _ := GenerateID()
	_ = s.ctx.Store().Accounts().Create(ctx, &account.Account{
		ID:         newAccID,
		UserID:     in.UserID,
		Provider:   AccountProvider,
		ProviderID: normNew,
		CreatedAt:  now,
		UpdatedAt:  now,
	})

	s.cache.Invalidate(ctx, in.UserID, oldPhone)
	s.cache.Invalidate(ctx, in.UserID, normNew)

	s.ctx.Events().Publish(ctx, auth.Event{
		Name:    EventPhoneChanged,
		Time:    now,
		Subject: in.UserID,
		Payload: PhoneChangedPayload{
			UserID:    in.UserID,
			OldPhone:  oldPhone,
			NewPhone:  normNew,
			ChangedAt: now,
		},
	})

	return current, nil
}

// Remove unlinks and removes the phone record for the specified user.
func (s *service) Remove(ctx context.Context, in RemoveInput) error {
	if in.UserID == "" {
		return ErrUserNotFound
	}

	if err := s.hooks.runBeforeRemove(ctx, &in); err != nil {
		return err
	}

	current, err := s.getPhoneByUserID(ctx, in.UserID)
	if err != nil {
		if errors.Is(err, ErrPhoneNotFound) {
			return ErrPhoneNotFound
		}
		return err
	}

	phoneNum := current.PhoneNumber
	if err := s.deletePhone(ctx, in.UserID); err != nil {
		return err
	}

	// Clean up Core account if present
	acc, err := s.ctx.Store().Accounts().GetByProvider(ctx, AccountProvider, phoneNum)
	if err == nil {
		_ = s.ctx.Store().Accounts().Delete(ctx, acc.ID)
	}

	s.cache.Invalidate(ctx, in.UserID, phoneNum)

	s.ctx.Events().Publish(ctx, auth.Event{
		Name:    EventPhoneRemoved,
		Time:    s.ctx.Now(),
		Subject: in.UserID,
		Payload: PhoneRemovedPayload{
			UserID:      in.UserID,
			PhoneNumber: phoneNum,
			RemovedAt:   s.ctx.Now(),
		},
	})

	return nil
}

// GetByUserID retrieves the phone record associated with a Core user ID.
func (s *service) GetByUserID(ctx context.Context, userID string) (*Record, error) {
	if userID == "" {
		return nil, ErrUserNotFound
	}

	if cached, err := s.cache.GetByUserID(ctx, userID); err == nil && cached != nil {
		return cached, nil
	}

	rec, err := s.getPhoneByUserID(ctx, userID)
	if errors.Is(err, ErrPhoneNotFound) {
		return nil, ErrPhoneNotFound
	}
	if err != nil {
		return nil, err
	}

	_ = s.cache.SetByUserID(ctx, userID, rec)
	return rec, nil
}

// GetByPhone retrieves the phone record associated with a normalized phone number.
func (s *service) GetByPhone(ctx context.Context, phoneNumber string) (*Record, error) {
	norm, err := s.Normalize(phoneNumber)
	if err != nil {
		return nil, ErrInvalidPhone
	}

	if cached, err := s.cache.GetByNumber(ctx, norm); err == nil && cached != nil {
		return cached, nil
	}

	rec, err := s.getPhoneByNumber(ctx, norm)
	if errors.Is(err, ErrPhoneNotFound) {
		return nil, ErrPhoneNotFound
	}
	if err != nil {
		return nil, err
	}

	_ = s.cache.SetByNumber(ctx, norm, rec)
	return rec, nil
}

func (s *service) dispatchOTP(ctx context.Context, phone, subject, purpose string, metadata map[string]string) error {
	if s.cfg.RevokePreviousOnRequest {
		_ = s.revokeOTPsByPhone(ctx, phone, purpose)
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
		PhoneNumber: phone,
		Subject:     subject,
		Purpose:     purpose,
		OTPHash:     HashOTP(code, salt),
		Salt:        salt,
		ExpiresAt:   now.Add(s.cfg.TTL),
		MaxAttempts: s.cfg.MaxAttempts,
		Attempts:    0,
		CreatedAt:   now,
	}

	if err := s.createOTP(ctx, rec); err != nil {
		return err
	}

	msg := s.cfg.MessageBuilder(phone, code, purpose, s.cfg.TTL)
	if metadata != nil {
		msg.Metadata = metadata
	}

	if err := s.provider.Send(ctx, msg); err != nil {
		return err
	}

	s.ctx.Events().Publish(ctx, auth.Event{
		Name:    EventPhoneOTPRequested,
		Time:    now,
		Subject: subject,
		Payload: OTPRequestedPayload{
			PhoneNumber: phone,
			Subject:     subject,
			Purpose:     purpose,
			ExpiresAt:   rec.ExpiresAt,
		},
	})

	return nil
}

func (s *service) publishRejected(ctx context.Context, phone, reason string, attempts int) {
	now := s.ctx.Now()
	s.ctx.Events().Publish(ctx, auth.Event{
		Name:    EventPhoneOTPRejected,
		Time:    now,
		Subject: phone,
		Payload: OTPRejectedPayload{
			PhoneNumber: phone,
			Reason:      reason,
			Attempts:    attempts,
			Time:        now,
		},
	})
}

func (s *service) resolveUser(ctx context.Context, normPhone, subject, optionalEmail string) (*user.User, error) {
	now := s.ctx.Now()

	phoneRec, err := s.getPhoneByNumber(ctx, normPhone)
	if err == nil {
		u, err := s.ctx.Store().Users().GetByID(ctx, phoneRec.UserID)
		if err != nil {
			return nil, err
		}
		if !phoneRec.Verified {
			phoneRec.Verified = true
			phoneRec.VerifiedAt = &now
			phoneRec.UpdatedAt = now
			_ = s.updatePhone(ctx, phoneRec)
			s.cache.Invalidate(ctx, u.ID, normPhone)
			s.ctx.Events().Publish(ctx, auth.Event{
				Name:    EventPhoneVerified,
				Time:    now,
				Subject: u.ID,
				Payload: PhoneVerifiedPayload{
					UserID:      u.ID,
					PhoneNumber: normPhone,
					VerifiedAt:  now,
				},
			})
		}
		return u, nil
	}
	if !errors.Is(err, ErrPhoneNotFound) {
		return nil, err
	}

	// Unregistered phone: create user if AllowSignUp is true
	if !s.cfg.AllowSignUp {
		return nil, ErrSignUpDisabled
	}

	return s.findOrCreateUserByPhone(ctx, normPhone, optionalEmail, now)
}

func (s *service) findOrCreateUserByPhone(ctx context.Context, normPhone, optionalEmail string, now time.Time) (*user.User, error) {
	var newUser *user.User

	createFn := func(txCtx context.Context) error {
		uID, err := GenerateID()
		if err != nil {
			return err
		}

		email := optionalEmail
		if email != "" {
			normEmail, normErr := user.NormalizeEmail(email)
			if normErr == nil {
				email = normEmail
			}
		} else {
			email = uID + "@phone.local"
		}

		newUser = &user.User{
			ID:            uID,
			Email:         email,
			EmailVerified: false,
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
			ProviderID: normPhone,
			CreatedAt:  now,
			UpdatedAt:  now,
		}
		if err := s.ctx.Store().Accounts().Create(txCtx, acc); err != nil {
			return err
		}

		pID, err := GenerateID()
		if err != nil {
			return err
		}
		newPhoneRec := &PhoneRecord{
			ID:          pID,
			UserID:      newUser.ID,
			PhoneNumber: normPhone,
			Verified:    true,
			VerifiedAt:  &now,
			CreatedAt:   now,
			UpdatedAt:   now,
		}
		return s.createPhone(txCtx, newPhoneRec)
	}

	var err error
	if s.ctx.Adapter() != nil {
		err = s.ctx.Adapter().Transaction(ctx, func(txCtx context.Context, _ adapter.Adapter) error {
			return createFn(txCtx)
		})
	} else {
		err = s.ctx.Store().Transaction(ctx, createFn)
	}

	if err != nil {
		return nil, err
	}

	s.ctx.Events().Publish(ctx, auth.Event{
		Name:    auth.EventUserCreated,
		Time:    now,
		Subject: newUser.ID,
		Payload: newUser,
	})

	s.ctx.Events().Publish(ctx, auth.Event{
		Name:    EventPhoneVerified,
		Time:    now,
		Subject: newUser.ID,
		Payload: PhoneVerifiedPayload{
			UserID:      newUser.ID,
			PhoneNumber: normPhone,
			VerifiedAt:  now,
		},
	})

	return newUser, nil
}

func (s *service) getPhoneByNumber(ctx context.Context, phone string) (*PhoneRecord, error) {
	repo := sdk.Model[PhoneRecord](s.ctx, ModelPhones)
	p, err := repo.FindOne(ctx, adapter.Eq("phone_number", phone))
	if err != nil {
		if errors.Is(err, adapter.ErrNotFound) {
			return nil, ErrPhoneNotFound
		}
		return nil, err
	}
	return p, nil
}

func (s *service) getPhoneByUserID(ctx context.Context, userID string) (*PhoneRecord, error) {
	repo := sdk.Model[PhoneRecord](s.ctx, ModelPhones)
	p, err := repo.FindOne(ctx, adapter.Eq("user_id", userID))
	if err != nil {
		if errors.Is(err, adapter.ErrNotFound) {
			return nil, ErrPhoneNotFound
		}
		return nil, err
	}
	return p, nil
}

func (s *service) createPhone(ctx context.Context, p *PhoneRecord) error {
	repo := sdk.Model[PhoneRecord](s.ctx, ModelPhones)
	err := repo.Create(ctx, p)
	if err != nil {
		if errors.Is(err, adapter.ErrConflict) {
			return ErrPhoneAlreadyExists
		}
		return err
	}
	return nil
}

func (s *service) updatePhone(ctx context.Context, p *PhoneRecord) error {
	repo := sdk.Model[PhoneRecord](s.ctx, ModelPhones)
	count, err := repo.Update(ctx, []adapter.Condition{adapter.Eq("id", p.ID)}, map[string]any{
		"phone_number": p.PhoneNumber,
		"verified":     p.Verified,
		"verified_at":  p.VerifiedAt,
		"updated_at":   p.UpdatedAt,
	})
	if err != nil {
		if errors.Is(err, adapter.ErrConflict) {
			return ErrPhoneAlreadyExists
		}
		return err
	}
	if count == 0 {
		return ErrPhoneNotFound
	}
	return nil
}

func (s *service) deletePhone(ctx context.Context, userID string) error {
	repo := sdk.Model[PhoneRecord](s.ctx, ModelPhones)
	_, err := repo.Delete(ctx, adapter.Eq("user_id", userID))
	return err
}

func (s *service) createOTP(ctx context.Context, rec *OTPRecord) error {
	repo := sdk.Model[OTPRecord](s.ctx, ModelPhoneOTPs)
	return repo.Create(ctx, rec)
}

func (s *service) getActiveOTP(ctx context.Context, phone, purpose string, now time.Time) (*OTPRecord, error) {
	repo := sdk.Model[OTPRecord](s.ctx, ModelPhoneOTPs)
	otps, err := repo.FindMany(ctx, adapter.Query{
		Where: []adapter.Condition{
			adapter.Eq("phone_number", phone),
			adapter.Eq("purpose", purpose),
		},
		SortBy: "created_at",
		Desc:   true,
		Limit:  1,
	})
	if err != nil {
		return nil, err
	}
	if len(otps) == 0 {
		return nil, adapter.ErrNotFound
	}
	return &otps[0], nil
}

func (s *service) incrementOTPAttempts(ctx context.Context, id string) (int, error) {
	repo := sdk.Model[OTPRecord](s.ctx, ModelPhoneOTPs)
	rec, err := repo.FindOne(ctx, adapter.Eq("id", id))
	if err != nil {
		return 0, err
	}
	newAttempts := rec.Attempts + 1
	_, err = repo.Update(ctx, []adapter.Condition{adapter.Eq("id", id)}, map[string]any{
		"attempts": newAttempts,
	})
	if err != nil {
		return 0, err
	}
	return newAttempts, nil
}

func (s *service) markOTPUsed(ctx context.Context, id string, at time.Time) error {
	repo := sdk.Model[OTPRecord](s.ctx, ModelPhoneOTPs)
	count, err := repo.Update(ctx, []adapter.Condition{
		adapter.Eq("id", id),
		adapter.IsNull("used_at"),
	}, map[string]any{
		"used_at": at,
	})
	if err != nil {
		return err
	}
	if count == 0 {
		return adapter.ErrConflict
	}
	return nil
}

func (s *service) revokeOTPsByPhone(ctx context.Context, phone, purpose string) error {
	repo := sdk.Model[OTPRecord](s.ctx, ModelPhoneOTPs)
	now := s.ctx.Now()
	_, err := repo.Update(ctx, []adapter.Condition{
		adapter.Eq("phone_number", phone),
		adapter.Eq("purpose", purpose),
		adapter.IsNull("used_at"),
	}, map[string]any{
		"used_at": now,
	})
	return err
}
