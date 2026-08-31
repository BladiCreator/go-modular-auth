package magiclink

import (
	"context"
	"errors"
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/entity"
	"github.com/BladiCreator/go-modular-auth/domain/repository"
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

	// ErrInvalidParameter is returned when required parameters (e.g. email, callback URL) are missing.
	ErrInvalidParameter = errors.New("magiclink: required parameter is missing or invalid")
)

// VerificationRecord represents the persistent storage entity for a magic link token.
type VerificationRecord struct {
	// ID is the unique database record identifier.
	ID string `json:"id"`

	// Identifier is the lookup key (e.g. "magic-link:<email>").
	Identifier string `json:"identifier"`

	// Value stores the hashed verification token string.
	Value string `json:"value"`

	// ExpiresAt specifies the timestamp when this verification token becomes invalid.
	ExpiresAt time.Time `json:"expires_at"`

	// CreatedAt records when the token record was created.
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt records when the token record was last updated.
	UpdatedAt time.Time `json:"updated_at"`
}

// Repository defines the persistent storage interface contract required by the Magic Link plugin.
// Implement this interface on your custom database adapter (e.g. PostgreSQL, MySQL, SQLite, MongoDB, GORM).
type Repository interface {
	repository.SessionRepository

	// CreateVerificationValue stores a new magic link verification record in storage.
	CreateVerificationValue(ctx context.Context, record *VerificationRecord) error

	// FindVerificationValue retrieves a verification record matching the given identifier key.
	FindVerificationValue(ctx context.Context, identifier string) (*VerificationRecord, error)

	// ConsumeVerificationValue atomically retrieves and deletes a verification record by identifier key.
	ConsumeVerificationValue(ctx context.Context, identifier string) (*VerificationRecord, error)

	// DeleteVerificationValue removes a verification token record by identifier key.
	DeleteVerificationValue(ctx context.Context, identifier string) error

	// FindUserByEmail retrieves a user entity matching the specified email address.
	FindUserByEmail(ctx context.Context, email string) (*entity.User, error)

	// CreateUser persists a new user entity in storage.
	CreateUser(ctx context.Context, user *entity.User) (*entity.User, error)

	// UpdateEmailVerified updates the email verification status flag for a user.
	UpdateEmailVerified(ctx context.Context, userID string, verified bool) error
}
