package bearer

import (
	"errors"

	"github.com/BladiCreator/go-modular-auth/domain/repository"
)

var (
	// ErrInvalidTokenFormat is returned when a signed token string does not adhere to the "<token>.<signature>" format.
	ErrInvalidTokenFormat = errors.New("bearer: invalid token format")

	// ErrInvalidSignature is returned when the cryptographic HMAC-SHA256 signature verification fails.
	ErrInvalidSignature = errors.New("bearer: signature verification failed")

	// ErrTokenEmpty is returned when an empty token string or header is provided.
	ErrTokenEmpty = errors.New("bearer: token is empty")

	// ErrInvalidHeader is returned when an authorization header does not start with the required "Bearer " prefix.
	ErrInvalidHeader = errors.New("bearer: invalid authorization header scheme")

	// ErrSecretRequired is returned when signing or verifying tokens without a configured Secret key.
	ErrSecretRequired = errors.New("bearer: secret key is required for token signing and verification")

	// ErrSessionNotFound is returned when a verified token does not match any active session in the database.
	ErrSessionNotFound = errors.New("bearer: session not found")

	// ErrSessionExpired is returned when a retrieved session has exceeded its validity timestamp.
	ErrSessionExpired = errors.New("bearer: session has expired")
)

// Repository defines the persistent storage contract required by the Bearer plugin to look up active sessions.
type Repository interface {
	repository.SessionRepository
}

