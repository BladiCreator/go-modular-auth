package jwt

import "errors"

var (
	// ErrInvalidToken is returned when a JWT is malformed, structurally invalid, or fails JSON parsing.
	ErrInvalidToken = errors.New("jwt: invalid or malformed token")

	// ErrTokenExpired is returned when a token's exp claim is in the past.
	ErrTokenExpired = errors.New("jwt: token has expired")

	// ErrTokenNotYetValid is returned when a token's nbf claim is in the future.
	ErrTokenNotYetValid = errors.New("jwt: token is not yet valid (nbf)")

	// ErrInvalidIssuer is returned when a token's iss claim does not match the expected issuer.
	ErrInvalidIssuer = errors.New("jwt: token issuer does not match expectation")

	// ErrInvalidAudience is returned when a token's aud claim does not include the expected audience.
	ErrInvalidAudience = errors.New("jwt: token audience does not match expectation")

	// ErrInvalidSubject is returned when a token's sub claim does not match the expected subject.
	ErrInvalidSubject = errors.New("jwt: token subject does not match expectation")

	// ErrAlgorithmMismatch is returned when a token header's alg differs from the key's declared algorithm,
	// preventing algorithm substitution attacks.
	ErrAlgorithmMismatch = errors.New("jwt: algorithm mismatch between token header and key specification")

	// ErrAlgorithmNotAllowed is returned when a token's algorithm is not among the configured allowed algorithms.
	ErrAlgorithmNotAllowed = errors.New("jwt: signing algorithm is not allowed")

	// ErrUnsignedTokenNotAllowed is returned when a token uses alg: 'none' or lacks a signature.
	ErrUnsignedTokenNotAllowed = errors.New("jwt: unsigned tokens (alg 'none') are strictly forbidden")

	// ErrInvalidSignature is returned when the cryptographic signature verification fails.
	ErrInvalidSignature = errors.New("jwt: cryptographic signature verification failed")

	// ErrKeyNotFound is returned when the key referenced by kid is not present in the KeyManager.
	ErrKeyNotFound = errors.New("jwt: signing key not found for specified kid")

	// ErrKeyIDRequired is returned when multiple keys are loaded but the token lacks a kid header.
	ErrKeyIDRequired = errors.New("jwt: kid header is required when multiple verification keys exist")

	// ErrInvalidKey is returned when the supplied cryptographic key is invalid, corrupt, or of wrong type.
	ErrInvalidKey = errors.New("jwt: invalid cryptographic key")

	// ErrNoActiveSigningKey is returned when issuing tokens without any active signing key configured.
	ErrNoActiveSigningKey = errors.New("jwt: no active signing key configured for token issuance")

	// ErrTokenRevoked is returned when the token has been explicitly invalidated in the revocation store.
	ErrTokenRevoked = errors.New("jwt: token has been revoked")

	// ErrMissingRequiredClaim is returned when a required claim is missing from the payload.
	ErrMissingRequiredClaim = errors.New("jwt: missing required claim")
)
