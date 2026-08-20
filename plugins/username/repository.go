package username

import (
	"context"
	"errors"

	"github.com/BladiCreator/go-modular-auth/domain/dto"
	"github.com/BladiCreator/go-modular-auth/domain/entity"
)

// Sentinel errors for the Username plugin.
var (
	// ErrInvalidUsernameOrPassword is returned when login credentials (username + password) do not match.
	ErrInvalidUsernameOrPassword = errors.New("username: invalid username or password")

	// ErrEmailNotVerified is returned when password sign-in is attempted with an unverified email address.
	ErrEmailNotVerified = errors.New("username: email not verified")

	// ErrUsernameAlreadyTaken is returned when attempting to claim a username that is already in use.
	ErrUsernameAlreadyTaken = errors.New("username: username is already taken")

	// ErrUsernameTooShort is returned when a username does not satisfy the minimum length requirement.
	ErrUsernameTooShort = errors.New("username: username is too short")

	// ErrUsernameTooLong is returned when a username exceeds the maximum allowed length.
	ErrUsernameTooLong = errors.New("username: username is too long")

	// ErrInvalidUsername is returned when a username fails character set regex validation.
	ErrInvalidUsername = errors.New("username: invalid username format")

	// ErrInvalidDisplayUsername is returned when a display username fails format requirements.
	ErrInvalidDisplayUsername = errors.New("username: invalid display username format")

	// ErrUserNotFound is returned when no user matches the queried username or ID.
	ErrUserNotFound = errors.New("username: user not found")

	// ErrCredentialAccountNotFound is returned when credential provider credentials are missing for a user.
	ErrCredentialAccountNotFound = errors.New("username: credential account not found")

	// ErrInvalidParameter is returned when a required parameter is missing or invalid.
	ErrInvalidParameter = errors.New("username: required parameter is missing or invalid")
)

// Repository defines the persistent storage contract required by the Username plugin.
type Repository interface {
	// GetUserByUsername retrieves a user entity matching the provided username.
	GetUserByUsername(ctx context.Context, username string) (*entity.User, error)

	// GetUserByID retrieves a user entity matching the provided unique identifier.
	GetUserByID(ctx context.Context, userID string) (*entity.User, error)

	// IsUsernameAvailable checks if a given username is unregistered and available for use.
	IsUsernameAvailable(ctx context.Context, username string) (bool, error)

	// UpdateUsername updates the username and display_username fields for a user.
	UpdateUsername(ctx context.Context, userID, username, displayUsername string) error

	// GetAccountByUserIDAndProvider retrieves provider credentials matching a user ID and provider ("credential").
	GetAccountByUserIDAndProvider(ctx context.Context, userID, providerID string) (*entity.Account, error)

	// CreateSession persists a new active user session in storage.
	CreateSession(ctx context.Context, params *dto.CreateSessionParams) (*entity.Session, error)
}
