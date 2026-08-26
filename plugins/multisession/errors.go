package multisession

import "errors"

var (
	// ErrInvalidSessionToken indicates that the provided session token or cookie signature is invalid.
	ErrInvalidSessionToken = errors.New("multisession: invalid session token")

	// ErrSessionNotFound indicates that the requested session does not exist or has expired.
	ErrSessionNotFound = errors.New("multisession: session not found")

	// ErrSecretRequired indicates that a cryptographic secret is required to sign or verify cookies.
	ErrSecretRequired = errors.New("multisession: secret key is required")

	// ErrInvalidSignature indicates an invalid or forged HMAC signature on a multi-session cookie.
	ErrInvalidSignature = errors.New("multisession: invalid cookie signature")
)
