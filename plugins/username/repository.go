package username

import (
	"context"
	"errors"

	"github.com/BladiCreator/go-modular-auth/domain/entity"
	"github.com/BladiCreator/go-modular-auth/domain/repository"
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
// Implement this interface on your custom database adapter (e.g. PostgreSQL, MySQL, SQLite, MongoDB, GORM).
//
// # Implementation Example (GORM / database/sql):
//
//	type GormUsernameRepository struct {
//		db *gorm.DB
//	}
//
//	func (r *GormUsernameRepository) GetUserByUsername(ctx context.Context, username string) (*entity.User, error) {
//		var u entity.User
//		if err := r.db.WithContext(ctx).Where("LOWER(username) = LOWER(?)", username).First(&u).Error; err != nil {
//			if errors.Is(err, gorm.ErrRecordNotFound) {
//				return nil, username.ErrUserNotFound
//			}
//			return nil, err
//		}
//		return &u, nil
//	}
type Repository interface {
	// GetUserByUsername retrieves a user entity matching the provided username.
	//
	// Function:
	//   Used during username + password sign-in to locate the target user.
	//
	// Storage:
	//   Database (GORM / SQL) - Query user by case-insensitive username index.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - username: Username string.
	//
	// Returns:
	//   - *entity.User: Matching user entity if found.
	//   - error: ErrUserNotFound if missing, or database error.
	//
	// Example SQL:
	//   SELECT id, username, display_username, email, name, email_verified, created_at, updated_at FROM users WHERE LOWER(username) = LOWER($1) LIMIT 1;
	GetUserByUsername(ctx context.Context, username string) (*entity.User, error)

	// GetUserByID retrieves a user entity matching the provided unique identifier.
	//
	// Function:
	//   Used when retrieving user details during username updates or profile management.
	//
	// Storage:
	//   Database (GORM / SQL) - User primary key lookup.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - userID: Target user primary key ID.
	//
	// Returns:
	//   - *entity.User: Matching user entity if found.
	//   - error: ErrUserNotFound if missing.
	//
	// Example SQL:
	//   SELECT id, username, display_username, email, name, email_verified, created_at, updated_at FROM users WHERE id = $1 LIMIT 1;
	GetUserByID(ctx context.Context, userID string) (*entity.User, error)

	// IsUsernameAvailable checks if a given username is unregistered and available for use.
	//
	// Function:
	//   Called prior to assigning or changing a username to prevent duplicate username claims.
	//
	// Storage:
	//   Database (GORM / SQL) - Unique username count check.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - username: Proposed username string.
	//
	// Returns:
	//   - bool: True if available (unclaimed), false if already taken.
	//   - error: Nil on success, or database error.
	//
	// Example SQL:
	//   SELECT COUNT(*) FROM users WHERE LOWER(username) = LOWER($1);
	IsUsernameAvailable(ctx context.Context, username string) (bool, error)

	// UpdateUsername updates the username and display_username fields for a user.
	//
	// Function:
	//   Called when a user modifies their handle or display username.
	//
	// Storage:
	//   Database (GORM / SQL) - User handle update.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - userID: Target user ID.
	//   - username: Normalized lowercase username.
	//   - displayUsername: Original casing display username.
	//
	// Returns:
	//   - error: ErrUsernameAlreadyTaken on constraint conflict.
	//
	// Example SQL:
	//   UPDATE users SET username = $1, display_username = $2, updated_at = $3 WHERE id = $4;
	UpdateUsername(ctx context.Context, userID, username, displayUsername string) error

	// GetAccountByUserIDAndProvider retrieves provider credentials matching a user ID and provider ("credential").
	//
	// Function:
	//   Used during username sign-in to fetch stored password hash for verification.
	//
	// Storage:
	//   Database (GORM / SQL) - Credentials record lookup.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - userID: User ID.
	//   - providerID: Provider string ("credential").
	//
	// Returns:
	//   - *entity.Account: Account entity containing PasswordHash.
	//   - error: ErrCredentialAccountNotFound if missing.
	//
	// Example SQL:
	//   SELECT id, user_id, provider, password_hash FROM accounts WHERE user_id = $1 AND provider = $2 LIMIT 1;
	GetAccountByUserIDAndProvider(ctx context.Context, userID, providerID string) (*entity.Account, error)

	// SessionRepository provides session creation operations.
	repository.SessionRepository
}
