package phone

import (
	"context"
	"errors"

	"github.com/BladiCreator/go-modular-auth-phone/cache"
	phonestore "github.com/BladiCreator/go-modular-auth-phone/store"
	"github.com/BladiCreator/go-modular-auth/account"
	auth "github.com/BladiCreator/go-modular-auth"
	"github.com/BladiCreator/go-modular-auth/store"
	"github.com/BladiCreator/go-modular-auth/user"
)

type service struct {
	host     *auth.Host
	cfg      Config
	store    phonestore.Store
	provider PhoneProvider
	limiter  *cache.Limiter
	cache    *cache.PhoneCache
	hooks    *Hooks
}

var _ Phone = (*service)(nil)

func newService(h *auth.Host, cfg Config) *service {
	return &service{
		host:     h,
		cfg:      cfg,
		store:    cfg.Store,
		provider: cfg.Provider,
		limiter:  cache.NewLimiter(h.Cache(), cfg.RateLimit.FailurePolicy, h.Now),
		cache:    cache.NewPhoneCache(h.Cache(), cfg.CacheTTL),
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

	existing, err := s.store.GetPhoneByNumber(ctx, normPhone)
	if errors.Is(err, phonestore.ErrNotFound) {
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

	now := s.host.Now()
	rec, err := s.store.GetActiveOTP(ctx, normPhone, PurposeAuthenticate, now)
	if errors.Is(err, phonestore.ErrNotFound) {
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
		attempts, incErr := s.store.IncrementOTPAttempts(ctx, rec.ID)
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
	if err := s.store.MarkOTPUsed(ctx, rec.ID, now); err != nil {
		if errors.Is(err, phonestore.ErrConflict) {
			s.publishRejected(ctx, normPhone, "already_used", rec.Attempts)
			return nil, ErrCodeAlreadyUsed
		}
		return nil, err
	}

	u, err := s.resolveUser(ctx, normPhone, rec.Subject, in.Email)
	if err != nil {
		return nil, err
	}

	issued, err := s.host.Auth().CreateSession(ctx, u.ID, in.Session)
	if err != nil {
		return nil, err
	}

	res := &auth.AuthResult{
		User:    u,
		Session: issued.Session,
		Token:   issued.Token,
	}

	s.host.Events().Publish(ctx, auth.Event{
		Name:    EventPhoneOTPVerified,
		Time:    now,
		Subject: u.ID,
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

	if _, err := s.host.Auth().RequireUser(ctx, in.UserID); err != nil {
		return ErrUserNotFound
	}

	existing, err := s.store.GetPhoneByNumber(ctx, normPhone)
	if err == nil && existing.UserID != in.UserID {
		return ErrPhoneAlreadyExists
	}
	if err != nil && !errors.Is(err, phonestore.ErrNotFound) {
		return err
	}

	now := s.host.Now()
	userPhone, err := s.store.GetPhoneByUserID(ctx, in.UserID)
	if errors.Is(err, phonestore.ErrNotFound) {
		id, err := GenerateID()
		if err != nil {
			return err
		}
		p := &phonestore.PhoneRecord{
			ID:          id,
			UserID:      in.UserID,
			PhoneNumber: normPhone,
			Verified:    false,
			CreatedAt:   now,
			UpdatedAt:   now,
		}
		if err := s.store.CreatePhone(ctx, p); err != nil {
			return err
		}
	} else if err != nil {
		return err
	} else if userPhone.PhoneNumber != normPhone {
		userPhone.PhoneNumber = normPhone
		userPhone.Verified = false
		userPhone.VerifiedAt = nil
		userPhone.UpdatedAt = now
		if err := s.store.UpdatePhone(ctx, userPhone); err != nil {
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

	now := s.host.Now()
	rec, err := s.store.GetActiveOTP(ctx, normPhone, PurposeVerify, now)
	if errors.Is(err, phonestore.ErrNotFound) {
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
		attempts, incErr := s.store.IncrementOTPAttempts(ctx, rec.ID)
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

	if err := s.store.MarkOTPUsed(ctx, rec.ID, now); err != nil {
		if errors.Is(err, phonestore.ErrConflict) {
			s.publishRejected(ctx, normPhone, "already_used", rec.Attempts)
			return nil, ErrCodeAlreadyUsed
		}
		return nil, err
	}

	userPhone, err := s.store.GetPhoneByUserID(ctx, in.UserID)
	if err != nil {
		if errors.Is(err, phonestore.ErrNotFound) {
			return nil, ErrPhoneNotFound
		}
		return nil, err
	}

	userPhone.Verified = true
	userPhone.VerifiedAt = &now
	userPhone.UpdatedAt = now

	if err := s.store.UpdatePhone(ctx, userPhone); err != nil {
		return nil, err
	}

	// Link Account in Core if not already linked
	_, err = s.host.Store().Accounts().GetByProvider(ctx, AccountProvider, normPhone)
	if errors.Is(err, store.ErrNotFound) {
		accID, _ := GenerateID()
		_ = s.host.Store().Accounts().Create(ctx, &account.Account{
			ID:         accID,
			UserID:     in.UserID,
			Provider:   AccountProvider,
			ProviderID: normPhone,
			CreatedAt:  now,
			UpdatedAt:  now,
		})
	}

	s.cache.Invalidate(ctx, in.UserID, normPhone)

	s.host.Events().Publish(ctx, auth.Event{
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

	if _, err := s.host.Auth().RequireUser(ctx, in.UserID); err != nil {
		return ErrUserNotFound
	}

	current, err := s.store.GetPhoneByUserID(ctx, in.UserID)
	if err != nil {
		if errors.Is(err, phonestore.ErrNotFound) {
			return ErrPhoneNotFound
		}
		return err
	}

	if current.PhoneNumber == normNew {
		// New number is already current number
		return nil
	}

	other, err := s.store.GetPhoneByNumber(ctx, normNew)
	if err == nil && other.UserID != in.UserID {
		return ErrPhoneAlreadyExists
	}
	if err != nil && !errors.Is(err, phonestore.ErrNotFound) {
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

	now := s.host.Now()
	rec, err := s.store.GetActiveOTP(ctx, normNew, PurposeChange, now)
	if errors.Is(err, phonestore.ErrNotFound) {
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
		attempts, incErr := s.store.IncrementOTPAttempts(ctx, rec.ID)
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

	if err := s.store.MarkOTPUsed(ctx, rec.ID, now); err != nil {
		if errors.Is(err, phonestore.ErrConflict) {
			s.publishRejected(ctx, normNew, "already_used", rec.Attempts)
			return nil, ErrCodeAlreadyUsed
		}
		return nil, err
	}

	current, err := s.store.GetPhoneByUserID(ctx, in.UserID)
	if err != nil {
		if errors.Is(err, phonestore.ErrNotFound) {
			return nil, ErrPhoneNotFound
		}
		return nil, err
	}

	oldPhone := current.PhoneNumber
	current.PhoneNumber = normNew
	current.Verified = true
	current.VerifiedAt = &now
	current.UpdatedAt = now

	if err := s.store.UpdatePhone(ctx, current); err != nil {
		return nil, err
	}

	// Update or create Core account mapping
	acc, err := s.host.Store().Accounts().GetByProvider(ctx, AccountProvider, oldPhone)
	if err == nil {
		_ = s.host.Store().Accounts().Delete(ctx, acc.ID)
	}
	newAccID, _ := GenerateID()
	_ = s.host.Store().Accounts().Create(ctx, &account.Account{
		ID:         newAccID,
		UserID:     in.UserID,
		Provider:   AccountProvider,
		ProviderID: normNew,
		CreatedAt:  now,
		UpdatedAt:  now,
	})

	s.cache.Invalidate(ctx, in.UserID, oldPhone)
	s.cache.Invalidate(ctx, in.UserID, normNew)

	s.host.Events().Publish(ctx, auth.Event{
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

	current, err := s.store.GetPhoneByUserID(ctx, in.UserID)
	if err != nil {
		if errors.Is(err, phonestore.ErrNotFound) {
			return ErrPhoneNotFound
		}
		return err
	}

	phoneNum := current.PhoneNumber
	if err := s.store.DeletePhone(ctx, in.UserID); err != nil {
		return err
	}

	// Clean up Core account if present
	acc, err := s.host.Store().Accounts().GetByProvider(ctx, AccountProvider, phoneNum)
	if err == nil {
		_ = s.host.Store().Accounts().Delete(ctx, acc.ID)
	}

	s.cache.Invalidate(ctx, in.UserID, phoneNum)

	s.host.Events().Publish(ctx, auth.Event{
		Name:    EventPhoneRemoved,
		Time:    s.host.Now(),
		Subject: in.UserID,
		Payload: PhoneRemovedPayload{
			UserID:      in.UserID,
			PhoneNumber: phoneNum,
			RemovedAt:   s.host.Now(),
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

	rec, err := s.store.GetPhoneByUserID(ctx, userID)
	if errors.Is(err, phonestore.ErrNotFound) {
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

	rec, err := s.store.GetPhoneByNumber(ctx, norm)
	if errors.Is(err, phonestore.ErrNotFound) {
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
		_ = s.store.RevokeOTPsByPhone(ctx, phone, purpose)
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

	now := s.host.Now()
	rec := &phonestore.OTPRecord{
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

	if err := s.store.CreateOTP(ctx, rec); err != nil {
		return err
	}

	msg := s.cfg.MessageBuilder(phone, code, purpose, s.cfg.TTL)
	if metadata != nil {
		msg.Metadata = metadata
	}

	if err := s.provider.Send(ctx, msg); err != nil {
		return err
	}

	s.host.Events().Publish(ctx, auth.Event{
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
	now := s.host.Now()
	s.host.Events().Publish(ctx, auth.Event{
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
	now := s.host.Now()

	phoneRec, err := s.store.GetPhoneByNumber(ctx, normPhone)
	if err == nil {
		u, err := s.host.Store().Users().GetByID(ctx, phoneRec.UserID)
		if err != nil {
			return nil, err
		}
		if !phoneRec.Verified {
			phoneRec.Verified = true
			phoneRec.VerifiedAt = &now
			phoneRec.UpdatedAt = now
			_ = s.store.UpdatePhone(ctx, phoneRec)
			s.cache.Invalidate(ctx, u.ID, normPhone)
			s.host.Events().Publish(ctx, auth.Event{
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
	if !errors.Is(err, phonestore.ErrNotFound) {
		return nil, err
	}

	// Unregistered phone: create user if AllowSignUp is true
	if !s.cfg.AllowSignUp {
		return nil, ErrSignUpDisabled
	}

	var newUser *user.User
	err = s.host.Store().Transaction(ctx, func(txCtx context.Context) error {
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
		if err := s.host.Store().Users().Create(txCtx, newUser); err != nil {
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
		if err := s.host.Store().Accounts().Create(txCtx, acc); err != nil {
			return err
		}

		pID, err := GenerateID()
		if err != nil {
			return err
		}
		newPhoneRec := &phonestore.PhoneRecord{
			ID:          pID,
			UserID:      newUser.ID,
			PhoneNumber: normPhone,
			Verified:    true,
			VerifiedAt:  &now,
			CreatedAt:   now,
			UpdatedAt:   now,
		}
		return s.store.CreatePhone(txCtx, newPhoneRec)
	})
	if err != nil {
		return nil, err
	}

	s.host.Events().Publish(ctx, auth.Event{
		Name:    auth.EventUserCreated,
		Time:    now,
		Subject: newUser.ID,
		Payload: newUser,
	})

	s.host.Events().Publish(ctx, auth.Event{
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
