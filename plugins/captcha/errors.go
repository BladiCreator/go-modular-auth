package captcha

import (
	"errors"
)

var (
	// ErrMissingSecretKey is returned when the SecretKey option is not configured.
	ErrMissingSecretKey = errors.New("captcha: missing secret key")

	// ErrMissingCaptchaResponse is returned when incoming request lacks the x-captcha-response header.
	ErrMissingCaptchaResponse = errors.New("captcha: missing captcha response header")

	// ErrVerificationFailed is returned when the captcha provider rejects the token.
	ErrVerificationFailed = errors.New("captcha: verification failed")

	// ErrServiceUnavailable is returned when outgoing request to provider fails or times out.
	ErrServiceUnavailable = errors.New("captcha: service unavailable or timeout")

	// ErrInvalidProvider is returned when an unsupported captcha provider is specified.
	ErrInvalidProvider = errors.New("captcha: unsupported captcha provider")

	// ErrScoreTooLow is returned when reCAPTCHA v3 score is lower than MinScore threshold.
	ErrScoreTooLow = errors.New("captcha: recaptcha score below required minimum")

	// ErrActionMismatch is returned when returned captcha action does not match ExpectedAction.
	ErrActionMismatch = errors.New("captcha: action does not match expected action")

	// ErrHostnameMismatch is returned when returned captcha hostname is not in AllowedHostnames.
	ErrHostnameMismatch = errors.New("captcha: hostname not in allowed list")
)
