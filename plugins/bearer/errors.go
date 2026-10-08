// Package bearer provides transport-independent Bearer token authentication for GoModularAuth.
package bearer

import "errors"

var (
	// ErrInvalidToken is returned when a bearer token is empty, malformed, or does not match any record.
	// To prevent credential enumeration and token leakage, detailed failure reasons are omitted.
	ErrInvalidToken = errors.New("bearer: invalid token")

	// ErrTokenExpired is returned when the bearer token has passed its expiration time.
	ErrTokenExpired = errors.New("bearer: token expired")

	// ErrTokenRevoked is returned when the bearer token has been explicitly revoked.
	ErrTokenRevoked = errors.New("bearer: token revoked")

	// ErrInsufficientScope is returned when the bearer token does not grant all required scopes.
	ErrInsufficientScope = errors.New("bearer: insufficient scope")

	// ErrTokenNotFound is returned when querying metadata for a non-existent token ID.
	ErrTokenNotFound = errors.New("bearer: token not found")

	// ErrInvalidInput is returned when required parameters (e.g., subject or ID) are missing or invalid.
	ErrInvalidInput = errors.New("bearer: invalid input")

	// ErrMissingBearerToken is returned by transport adapters when no Authorization Bearer header or credential is provided.
	ErrMissingBearerToken = errors.New("bearer: missing bearer token")

	// ErrMalformedBearerHeader is returned by transport adapters when the Authorization header is malformed.
	ErrMalformedBearerHeader = errors.New("bearer: malformed bearer authorization header")
)
