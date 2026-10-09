package passkey

import (
	"errors"
	"fmt"
)

var (
	// ErrRPIDRequired indicates that relying party ID was not provided.
	ErrRPIDRequired = errors.New("passkey: relying party ID is required")

	// ErrRPDisplayNameRequired indicates that relying party display name was not provided.
	ErrRPDisplayNameRequired = errors.New("passkey: relying party display name is required")

	// ErrRPOriginsRequired indicates that at least one relying party origin is required.
	ErrRPOriginsRequired = errors.New("passkey: at least one relying party origin is required")

	// ErrInvalidRPID indicates that relying party ID contains an invalid scheme, port, or path.
	ErrInvalidRPID = errors.New("passkey: relying party ID must not contain schemes, ports, or paths")

	// ErrInvalidRPOrigin indicates that an origin URL is invalid or malformed.
	ErrInvalidRPOrigin = errors.New("passkey: relying party origin must be a valid URL with scheme")

	// ErrUserIDRequired indicates that a user ID was not supplied when required.
	ErrUserIDRequired = errors.New("passkey: user ID is required")

	// ErrCredentialIDRequired indicates that a credential ID was not provided.
	ErrCredentialIDRequired = errors.New("passkey: credential ID is required")

	// ErrSessionIDRequired indicates that a ceremony session ID was not provided.
	ErrSessionIDRequired = errors.New("passkey: ceremony session ID is required")

	// ErrChallengeNotFound indicates that the ceremony challenge does not exist.
	ErrChallengeNotFound = errors.New("passkey: ceremony challenge not found")

	// ErrChallengeExpired indicates that the ceremony challenge has expired.
	ErrChallengeExpired = errors.New("passkey: ceremony challenge has expired")

	// ErrChallengeAlreadyUsed indicates that the ceremony challenge was already consumed (replay prevention).
	ErrChallengeAlreadyUsed = errors.New("passkey: ceremony challenge has already been consumed")

	// ErrChallengeTypeMismatch indicates that the ceremony challenge type does not match the attempted operation.
	ErrChallengeTypeMismatch = errors.New("passkey: ceremony challenge type mismatch")

	// ErrInvalidClientResponse indicates that the browser client response was missing or malformed.
	ErrInvalidClientResponse = errors.New("passkey: invalid webauthn client response data")

	// ErrRegistrationFailed indicates that WebAuthn registration verification failed.
	ErrRegistrationFailed = errors.New("passkey: credential registration verification failed")

	// ErrAuthenticationFailed indicates that WebAuthn authentication verification failed.
	ErrAuthenticationFailed = errors.New("passkey: credential authentication verification failed")

	// ErrCredentialNotFound indicates that the requested passkey credential does not exist.
	ErrCredentialNotFound = errors.New("passkey: credential not found")

	// ErrCredentialAlreadyExists indicates that the credential ID is already registered.
	ErrCredentialAlreadyExists = errors.New("passkey: credential already registered")

	// ErrSignCounterInvalid indicates that the authenticator sign counter did not increment properly.
	ErrSignCounterInvalid = errors.New("passkey: sign counter invalid, potential replay or cloned authenticator")

	// ErrAuthenticatorCloned indicates that an authenticator clone was flagged during assertion verification.
	ErrAuthenticatorCloned = errors.New("passkey: authenticator clone detected")

	// ErrUserNotFound indicates that the user associated with the credential was not found in the core store.
	ErrUserNotFound = errors.New("passkey: user not found")

	// ErrUnauthorized indicates that the caller does not have permission to manage the credential.
	ErrUnauthorized = errors.New("passkey: unauthorized access to credential")
)

// CeremonyError provides rich contextual error details around WebAuthn failures.
type CeremonyError struct {
	Op         string
	Reason     string
	Underlying error
}

// Error returns the string representation of CeremonyError.
func (e *CeremonyError) Error() string {
	if e.Underlying != nil {
		return fmt.Sprintf("passkey: %s failed (%s): %v", e.Op, e.Reason, e.Underlying)
	}
	return fmt.Sprintf("passkey: %s failed: %s", e.Op, e.Reason)
}

// Unwrap returns the underlying error.
func (e *CeremonyError) Unwrap() error {
	return e.Underlying
}
