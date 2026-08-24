package ott

import (
	"context"
	"errors"
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/entity"
)

// Sentinel errors for the One-Time Token (OTT) plugin.
var (
	// ErrInvalidToken is returned when the provided OTT verification token is incorrect or not found.
	ErrInvalidToken = errors.New("ott: invalid verification token")

	// ErrTokenExpired is returned when attempting to verify an OTT token that has passed its validity lifetime.
	ErrTokenExpired = errors.New("ott: verification token has expired")

	// ErrSessionNotFound is returned when the session token referenced by the OTT token does not exist.
	ErrSessionNotFound = errors.New("ott: session not found")

	// ErrSessionExpired is returned when the underlying session associated with the OTT token has expired.
	ErrSessionExpired = errors.New("ott: session has expired")

	// ErrUserNotFound is returned when the user associated with the session cannot be found.
	ErrUserNotFound = errors.New("ott: user not found")

	// ErrClientRequestDisabled is returned when a client attempts to generate an OTT token while DisableClientRequest is true.
	ErrClientRequestDisabled = errors.New("ott: client token generation request is disabled")

	// ErrInvalidParameter is returned when a required input parameter is missing or empty.
	ErrInvalidParameter = errors.New("ott: required parameter is missing or invalid")
)

// VerificationRecord represents the persistent storage entity for an OTT verification token.
type VerificationRecord struct {
	// ID is the unique database record identifier.
	ID string `json:"id"`

	// Identifier is the lookup key (e.g. "one-time-token:<stored_token>").
	Identifier string `json:"identifier"`

	// Value stores the target session token string.
	Value string `json:"value"`

	// ExpiresAt specifies the exact timestamp after which this token record is invalid.
	ExpiresAt time.Time `json:"expires_at"`

	// CreatedAt records when the token record was created.
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt records when the token record was last updated.
	UpdatedAt time.Time `json:"updated_at"`
}

// Repository defines the persistent storage interface contract required by the OTT plugin.
type Repository interface {
	// CreateVerificationValue stores a new OTT verification record in storage.
	CreateVerificationValue(ctx context.Context, record *VerificationRecord) error

	// ConsumeVerificationValue atomically retrieves and deletes an OTT verification record by identifier.
	// This operation MUST be atomic to protect against replay attacks and race conditions.
	ConsumeVerificationValue(ctx context.Context, identifier string) (*VerificationRecord, error)

	// GetSessionByToken retrieves an active session entity matching the specified session token string.
	GetSessionByToken(ctx context.Context, token string) (*entity.Session, error)

	// GetUserByID retrieves a user entity matching the specified user identifier.
	GetUserByID(ctx context.Context, userID string) (*entity.User, error)
}
