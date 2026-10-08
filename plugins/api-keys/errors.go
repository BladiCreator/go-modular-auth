package apikeys

import "errors"

var (
	// ErrInvalidKey is returned when the provided API key token is malformed, unrecognized, or fails verification.
	ErrInvalidKey = errors.New("apikeys: invalid API key")

	// ErrKeyNotFound is returned when the requested API key ID does not exist.
	ErrKeyNotFound = errors.New("apikeys: API key not found")

	// ErrKeyRevoked is returned when attempting to authenticate or use an API key that has been revoked.
	ErrKeyRevoked = errors.New("apikeys: API key has been revoked")

	// ErrKeyExpired is returned when an API key has passed its expiration timestamp.
	ErrKeyExpired = errors.New("apikeys: API key has expired")

	// ErrInsufficientScope is returned when an authenticated API key lacks one or more required scopes.
	ErrInsufficientScope = errors.New("apikeys: insufficient scope")

	// ErrInsufficientPermission is returned when an authenticated API key lacks one or more required permissions.
	ErrInsufficientPermission = errors.New("apikeys: insufficient permission")

	// ErrRateLimited is returned when API key verification attempts exceed rate limits (brute-force defense).
	ErrRateLimited = errors.New("apikeys: rate limit exceeded, authentication throttled")

	// ErrInvalidInput is returned when creation, rotation, or update arguments fail domain validation.
	ErrInvalidInput = errors.New("apikeys: invalid input")

	// ErrConflict is returned when an API key constraint is violated (e.g. duplicate key ID).
	ErrConflict = errors.New("apikeys: API key conflict")

	// ErrStoreRequired is returned during plugin initialization when no Store adapter is configured.
	ErrStoreRequired = errors.New("apikeys: store adapter is required")
)
