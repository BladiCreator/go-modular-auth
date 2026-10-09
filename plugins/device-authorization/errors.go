package deviceauth

import (
	"errors"
)

// RFC 8628 Standard Device Authorization Error Codes
const (
	// OAuthErrAuthorizationPending indicates the user has not yet completed the authorization flow.
	OAuthErrAuthorizationPending = "authorization_pending"

	// OAuthErrSlowDown indicates the client is polling too frequently; interval must be increased by 5s.
	OAuthErrSlowDown = "slow_down"

	// OAuthErrAccessDenied indicates the user explicitly denied the authorization request.
	OAuthErrAccessDenied = "access_denied"

	// OAuthErrExpiredToken indicates the device code or user code has expired.
	OAuthErrExpiredToken = "expired_token"

	// OAuthErrInvalidGrant indicates the device code is invalid, revoked, or already consumed.
	OAuthErrInvalidGrant = "invalid_grant"
)

var (
	// ErrAuthorizationPending indicates the authorization request is pending user approval.
	ErrAuthorizationPending = errors.New(OAuthErrAuthorizationPending)

	// ErrSlowDown indicates the client polled before the allowed interval; interval increases by 5 seconds.
	ErrSlowDown = errors.New(OAuthErrSlowDown)

	// ErrAccessDenied indicates the user explicitly denied the authorization request.
	ErrAccessDenied = errors.New(OAuthErrAccessDenied)

	// ErrExpiredToken indicates the device authorization request has expired.
	ErrExpiredToken = errors.New(OAuthErrExpiredToken)

	// ErrInvalidGrant indicates the device code is invalid or has already been consumed (replay prevented).
	ErrInvalidGrant = errors.New(OAuthErrInvalidGrant)

	// ErrInvalidUserCode indicates the user-entered verification code was not found or is invalid.
	ErrInvalidUserCode = errors.New("device auth: invalid or unknown user code")

	// ErrMaxAttemptsExceeded indicates too many failed attempts were made against a user code.
	ErrMaxAttemptsExceeded = errors.New("device auth: maximum verification attempts exceeded")

	// ErrAlreadyAuthorized indicates the user code was already approved.
	ErrAlreadyAuthorized = errors.New("device auth: request is already authorized")

	// ErrAlreadyDenied indicates the user code was already denied.
	ErrAlreadyDenied = errors.New("device auth: request is already denied")

	// ErrAlreadyConsumed indicates the grant has already been exchanged for tokens.
	ErrAlreadyConsumed = errors.New("device auth: request has already been consumed")

	// ErrRateLimited indicates request rate limit has been exceeded.
	ErrRateLimited = errors.New("device auth: rate limit exceeded")

	// ErrInvalidClient indicates the client ID is missing or does not match the initiated grant.
	ErrInvalidClient = errors.New("device auth: invalid client")

	// ErrInvalidInput indicates missing or invalid request parameters.
	ErrInvalidInput = errors.New("device auth: invalid input parameters")

	// ErrStoreRequired indicates that a persistent store was not configured.
	ErrStoreRequired = errors.New("device auth: store is required")
)
