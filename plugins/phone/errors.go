package phone

import (
	"errors"
	"fmt"
)

var (
	// ErrPhoneRequired is returned when a phone number input is empty.
	ErrPhoneRequired = errors.New("phone: phone number is required")

	// ErrInvalidPhone is returned when a phone number fails E.164 normalization or validation.
	ErrInvalidPhone = errors.New("phone: invalid phone number format (must be E.164, e.g. +12025550123)")

	// ErrPhoneAlreadyExists is returned when trying to assign a phone number that is already linked to another account.
	ErrPhoneAlreadyExists = errors.New("phone: phone number is already registered to an account")

	// ErrPhoneNotFound is returned when no phone record exists for the given user.
	ErrPhoneNotFound = errors.New("phone: phone record not found")

	// ErrCodeRequired is returned when an OTP code is empty.
	ErrCodeRequired = errors.New("phone: verification code is required")

	// ErrInvalidCode is returned when the provided OTP code does not match the stored hash.
	ErrInvalidCode = errors.New("phone: invalid verification code")

	// ErrCodeExpired is returned when the OTP code has surpassed its time-to-live.
	ErrCodeExpired = errors.New("phone: verification code has expired")

	// ErrCodeAlreadyUsed is returned when the OTP code was already consumed.
	ErrCodeAlreadyUsed = errors.New("phone: verification code has already been consumed")

	// ErrMaxAttemptsExceeded is returned when failed verification attempts exceed the allowed threshold.
	ErrMaxAttemptsExceeded = errors.New("phone: maximum verification attempts exceeded")

	// ErrCooldownActive is returned when a new OTP request is made before the cooldown duration has elapsed.
	ErrCooldownActive = errors.New("phone: cooldown period active, please wait before requesting another code")

	// ErrRateLimitExceeded is returned when too many OTP requests are made within the rate limit window.
	ErrRateLimitExceeded = errors.New("phone: rate limit exceeded, please try again later")

	// ErrProviderRequired is returned when no PhoneProvider is configured on the module or host.
	ErrProviderRequired = errors.New("phone: a PhoneProvider must be configured")

	// ErrSignUpDisabled is returned when an unregistered phone number attempts authentication while AllowSignUp is false.
	ErrSignUpDisabled = errors.New("phone: automatic sign-up is disabled for unregistered phone numbers")

	// ErrUserNotFound is returned when the referenced Core user does not exist.
	ErrUserNotFound = errors.New("phone: user not found")

	// ErrCacheFailure is returned when cache operations fail under a FailClosed policy.
	ErrCacheFailure = errors.New("phone: cache operation failed")
)

// VerificationError is a typed error detailing verification failure status and attempt counts.
type VerificationError struct {
	Reason   string
	Attempts int
	Err      error
}

func (e *VerificationError) Error() string {
	return fmt.Sprintf("phone verification error: %s (attempts: %d): %v", e.Reason, e.Attempts, e.Err)
}

// Unwrap exposes the underlying sentinel error for errors.Is checks.
func (e *VerificationError) Unwrap() error {
	return e.Err
}
