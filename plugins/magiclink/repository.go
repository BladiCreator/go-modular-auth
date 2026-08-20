package magiclink

import (
	"context"
	"errors"
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/entity"
)

// Sentinel errors for the Magic Link plugin.
var (
	// ErrInvalidEmail is returned when an email format validation fails or is empty.
	ErrInvalidEmail = errors.New("magiclink: invalid email address")

	// ErrInvalidToken is returned when the provided magic link token is incorrect or invalid.
	ErrInvalidToken = errors.New("magiclink: invalid verification token")

	// ErrTokenExpired is returned when attempting to verify a token that has passed its expiration time.
	ErrTokenExpired = errors.New("magiclink: verification token has expired")

	// ErrUserNotFound is returned when no user matches the queried email address.
	ErrUserNotFound = errors.New("magiclink: user not found")

	// ErrSignUpDisabled is returned when attempting to sign up a new user via magic link when DisableSignUp is true.
	ErrSignUpDisabled = errors.New("magiclink: user sign-up is disabled")

	// ErrSendCallbackMissing is returned when attempting to dispatch a magic link without a registered SendMagicLink callback.
	ErrSendCallbackMissing = errors.New("magiclink: SendMagicLink callback is not configured")

	// ErrCannotRetrieveHashed is returned when attempting to inspect a hashed token in plain text.
	ErrCannotRetrieveHashed = errors.New("magiclink: token is hashed, cannot return plain text token")

	// ErrInvalidParameter is returned when a required request parameter is missing or invalid.
	ErrInvalidParameter = errors.New("magiclink: required parameter is missing or invalid")
)

// VerificationRecord represents the persistent storage entity for a magic link token.
type VerificationRecord struct {
	// ID is the unique database record identifier.
	ID string `json:"id"`

	// Identifier is the composite lookup key (e.g. "magic-link-token-user@example.com").
	Identifier string `json:"identifier"`

	// Value stores the token value (or hashed/encrypted token) along with metadata payload.
	Value string `json:"value"`

	// ExpiresAt specifies the exact timestamp after which this token is invalid.
	ExpiresAt time.Time `json:"expires_at"`

	// CreatedAt records when the token record was initialized.
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt records when the token record was last modified.
	UpdatedAt time.Time `json:"updated_at"`
}

// Repository defines the persistent storage contract required by the Magic Link plugin.
type Repository interface {
	// CreateVerificationValue creates a new verification record in persistent storage.
	CreateVerificationValue(ctx context.Context, record *VerificationRecord) error

	// FindVerificationValue retrieves an active verification record matching the given identifier.
	FindVerificationValue(ctx context.Context, identifier string) (*VerificationRecord, error)

	// ConsumeVerificationValue atomically retrieves and removes/invalidates a verification record by identifier.
	// This operation MUST be single-use to protect against race conditions and token replay attacks.
	ConsumeVerificationValue(ctx context.Context, identifier string) (*VerificationRecord, error)

	// DeleteVerificationValue removes a verification record from persistent storage.
	DeleteVerificationValue(ctx context.Context, identifier string) error

	// FindUserByEmail retrieves a user by their email address.
	FindUserByEmail(ctx context.Context, email string) (*entity.User, error)

	// CreateUser persists a new user entity in storage.
	CreateUser(ctx context.Context, user *entity.User) (*entity.User, error)

	// UpdateEmailVerified updates the email verification status for a specific user.
	UpdateEmailVerified(ctx context.Context, userID string, verified bool) error

	// CreateSession initializes and persists an active user session.
	CreateSession(ctx context.Context, session *entity.Session) (*entity.Session, error)
}
