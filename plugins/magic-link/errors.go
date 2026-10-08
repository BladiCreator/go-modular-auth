package magiclink

import "errors"

// Sentinel errors returned by the magic link plugin operations.
var (
	// ErrEmailRequired is returned when an email is empty.
	ErrEmailRequired = errors.New("magiclink: email is required")

	// ErrInvalidEmail is returned when an email address is malformed.
	ErrInvalidEmail = errors.New("magiclink: invalid email address")

	// ErrTokenRequired is returned when attempting authentication with an empty token.
	ErrTokenRequired = errors.New("magiclink: token is required")

	// ErrInvalidToken is returned when a token is invalid, expired, already consumed, or revoked.
	// Deliberately coarse to avoid oracle attacks.
	ErrInvalidToken = errors.New("magiclink: invalid or expired token")

	// ErrUserNotFound is returned when the user associated with a token does not exist.
	ErrUserNotFound = errors.New("magiclink: user not found")

	// ErrEmailSenderRequired is returned when neither the plugin nor the host has an email sender configured.
	ErrEmailSenderRequired = errors.New("magiclink: email sender not configured")

	// ErrRateLimitExceeded is returned when the maximum number of requests for a window is exceeded.
	ErrRateLimitExceeded = errors.New("magiclink: rate limit exceeded")

	// ErrCooldownActive is returned when requesting a magic link too quickly after a previous request.
	ErrCooldownActive = errors.New("magiclink: cooldown active, please wait before requesting another link")

	// ErrSignUpDisabled is returned when attempting to consume a signup token while AllowSignUp is disabled.
	ErrSignUpDisabled = errors.New("magiclink: user sign-up is not permitted")
)
