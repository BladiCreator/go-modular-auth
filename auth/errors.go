package auth

import "errors"

// Sentinel errors returned by core operations. Compare with errors.Is.
//
// Credential and token errors are deliberately coarse (ErrInvalidCredentials,
// ErrInvalidToken) so callers cannot be used as user/token existence oracles.
var (
	ErrStoreRequired      = errors.New("auth: store is required")
	ErrInvalidEmail       = errors.New("auth: invalid email")
	ErrInvalidPassword    = errors.New("auth: password does not satisfy the policy")
	ErrEmailAlreadyExists = errors.New("auth: email already registered")
	ErrInvalidCredentials = errors.New("auth: invalid credentials")
	ErrEmailNotVerified   = errors.New("auth: email not verified")
	ErrUnauthenticated    = errors.New("auth: unauthenticated")
	ErrUserNotFound       = errors.New("auth: user not found")
	ErrInvalidToken       = errors.New("auth: invalid or expired token")
	ErrEmailNotConfigured = errors.New("auth: email sender not configured")
	ErrPluginDependency   = errors.New("auth: plugin dependency not satisfied")
)
