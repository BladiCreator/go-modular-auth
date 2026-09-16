package ott

import (
	"context"
	"errors"

	"github.com/BladiCreator/go-modular-auth/domain/entity"
	"github.com/BladiCreator/go-modular-auth/domain/repository"
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

// Repository defines the persistent storage interface contract required by the OTT plugin.
// Implement this interface on your custom database adapter (e.g. PostgreSQL, MySQL, SQLite, MongoDB, GORM).
type Repository interface {
	// VerificationRepository provides centralized ephemeral OTT verification operations.
	repository.VerificationRepository

	// GetUserByID retrieves a user entity matching the specified user identifier.
	GetUserByID(ctx context.Context, userID string) (*entity.User, error)

	// SessionRepository provides session lookup operations.
	repository.SessionRepository
}
