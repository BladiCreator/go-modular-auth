package emailotp

import (
	"errors"
	"fmt"
)

var (
	// ErrEmailRequired indicates that no email address was provided in the request.
	ErrEmailRequired = errors.New("email-otp: email is required")

	// ErrInvalidEmail indicates that the provided email address failed normalization or syntax checks.
	ErrInvalidEmail = errors.New("email-otp: invalid email address")

	// ErrCodeRequired indicates that no OTP code was supplied for verification.
	ErrCodeRequired = errors.New("email-otp: verification code is required")

	// ErrInvalidCode indicates that the supplied code does not match the active OTP.
	ErrInvalidCode = errors.New("email-otp: invalid verification code")

	// ErrCodeExpired indicates that the OTP code has expired.
	ErrCodeExpired = errors.New("email-otp: verification code has expired")

	// ErrCodeAlreadyUsed indicates that the OTP code has already been consumed (replay prevention).
	ErrCodeAlreadyUsed = errors.New("email-otp: verification code has already been used")

	// ErrMaxAttemptsExceeded indicates that the maximum verification attempts have been reached.
	ErrMaxAttemptsExceeded = errors.New("email-otp: maximum verification attempts exceeded")

	// ErrCooldownActive indicates that a new code cannot be requested until the cooldown elapses.
	ErrCooldownActive = errors.New("email-otp: request cooldown active, please wait before requesting another code")

	// ErrRateLimitExceeded indicates that too many requests were made within the rate limit window.
	ErrRateLimitExceeded = errors.New("email-otp: rate limit exceeded")

	// ErrEmailSenderRequired indicates that no email.Sender was configured on Host or Config.
	ErrEmailSenderRequired = errors.New("email-otp: email sender required but none provided")

	// ErrSignUpDisabled indicates that an unknown email requested authentication when AllowSignUp is false.
	ErrSignUpDisabled = errors.New("email-otp: sign up is not allowed")

	// ErrCacheFailure indicates that a security cache operation failed when fail-closed policy is active.
	ErrCacheFailure = errors.New("email-otp: cache security check failed")
)

// VerificationError is a typed error providing domain context around a verification failure.
type VerificationError struct {
	Reason   string
	Attempts int
	Err      error
}

// Error returns the string representation of the verification error.
func (e *VerificationError) Error() string {
	return fmt.Sprintf("email-otp: verification failed (%s): %v", e.Reason, e.Err)
}

// Unwrap exposes the underlying sentinel error for errors.Is checking.
func (e *VerificationError) Unwrap() error {
	return e.Err
}
