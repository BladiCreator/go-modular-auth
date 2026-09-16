package emailotp

import (
	"context"
	"errors"

	"github.com/BladiCreator/go-modular-auth/domain/dto"
	"github.com/BladiCreator/go-modular-auth/domain/entity"
	"github.com/BladiCreator/go-modular-auth/domain/repository"
)

// Sentinel errors for the Email OTP plugin.
var (
	// ErrInvalidEmail is returned when an email format validation fails or is empty.
	ErrInvalidEmail = errors.New("emailotp: invalid email address")

	// ErrInvalidOTPType is returned when an unsupported OTP operation type is supplied.
	ErrInvalidOTPType = errors.New("emailotp: invalid OTP type")

	// ErrInvalidOTP is returned when the provided OTP code is incorrect or has already been consumed.
	ErrInvalidOTP = errors.New("emailotp: invalid OTP")

	// ErrOTPExpired is returned when attempting to verify an OTP that has passed its expiration time.
	ErrOTPExpired = errors.New("emailotp: OTP expired")

	// ErrTooManyAttempts is returned when the maximum number of failed attempts on an active OTP has been exceeded.
	ErrTooManyAttempts = errors.New("emailotp: maximum attempt limit reached")

	// ErrUserNotFound is returned when no user matches the queried identifier or email address.
	ErrUserNotFound = errors.New("emailotp: user not found")

	// ErrEmailAlreadyInUse is returned when attempting to assign an email that already belongs to another user.
	ErrEmailAlreadyInUse = errors.New("emailotp: email already in use")

	// ErrChangeEmailDisabled is returned when attempting an email change operation while the feature is disabled.
	ErrChangeEmailDisabled = errors.New("emailotp: change email with OTP is disabled")

	// ErrSameEmail is returned when attempting to change an email to the exact same current address.
	ErrSameEmail = errors.New("emailotp: new email must be different from current email")

	// ErrCurrentEmailNotVerified is returned when verifying the current email OTP is required before requesting change.
	ErrCurrentEmailNotVerified = errors.New("emailotp: OTP is required to verify current email")

	// ErrSendCallbackMissing is returned when attempting to dispatch an OTP without a registered SendVerificationOTP callback.
	ErrSendCallbackMissing = errors.New("emailotp: send verification OTP callback is not configured")

	// ErrCannotRetrieveHashed is returned when trying to read plain text OTP while hashed storage mode is active.
	ErrCannotRetrieveHashed = errors.New("emailotp: OTP is hashed, cannot return plain text OTP")

	// ErrPasswordTooShort is returned when a reset password does not satisfy the minimum length requirement.
	ErrPasswordTooShort = errors.New("emailotp: password is too short")

	// ErrPasswordTooLong is returned when a reset password exceeds the maximum allowed length.
	ErrPasswordTooLong = errors.New("emailotp: password is too long")

	// ErrAccountNotFound is returned when credentials for the requested provider are missing in storage.
	ErrAccountNotFound = errors.New("emailotp: credential account not found")

	// ErrInvalidParameter is returned when a required argument or parameter is missing or malformed.
	ErrInvalidParameter = errors.New("emailotp: required parameter is missing or invalid")
)

// Repository defines the persistent storage contract required by the Email OTP plugin.
// Implement this interface on your custom database adapter (e.g. PostgreSQL, MySQL, SQLite, MongoDB, GORM).
type Repository interface {
	// VerificationRepository provides centralized ephemeral OTP verification storage operations.
	repository.VerificationRepository

	// GetUserByEmail retrieves a user entity matching the provided email address.
	//
	// Function:
	//   Used during sign-in or signup to check existing user accounts.
	//
	// Storage:
	//   Database (GORM / SQL) - Relational user entity query.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - email: The normalized email address to query.
	//
	// Returns:
	//   - *entity.User: The matching user entity if found.
	//   - error: ErrUserNotFound if no record matches, or database error.
	//
	// Example SQL:
	//   SELECT id, name, email, email_verified, role, banned, created_at, updated_at FROM users WHERE LOWER(email) = LOWER($1) LIMIT 1;
	GetUserByEmail(ctx context.Context, email string) (*entity.User, error)

	// GetUserByID retrieves a user entity matching the provided unique identifier.
	//
	// Function:
	//   Used to load user details by primary key ID.
	//
	// Storage:
	//   Database (GORM / SQL) - User primary key lookup.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - id: The user's primary key ID.
	//
	// Returns:
	//   - *entity.User: The matching user entity if found.
	//   - error: ErrUserNotFound if no record matches, or database error.
	//
	// Example SQL:
	//   SELECT id, name, email, email_verified, role, banned, created_at, updated_at FROM users WHERE id = $1 LIMIT 1;
	GetUserByID(ctx context.Context, id string) (*entity.User, error)

	// CreateUser persists a newly registered user in storage.
	//
	// Function:
	//   Called when a new user completes email OTP registration.
	//
	// Storage:
	//   Database (GORM / SQL) - Relational insert of new User domain entity.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - params: Parameters containing name, email, and metadata.
	//
	// Returns:
	//   - *entity.User: The created user entity.
	//   - error: Nil on success, or database error.
	//
	// Example SQL:
	//   INSERT INTO users (id, name, email, email_verified, role, created_at, updated_at)
	//   VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, name, email, email_verified, created_at, updated_at;
	CreateUser(ctx context.Context, params *dto.CreateUserParams) (*entity.User, error)

	// UpdateUser updates modified fields of an existing user profile (e.g. Email, EmailVerified).
	//
	// Function:
	//   Called when updating user attributes or setting EmailVerified to true.
	//
	// Storage:
	//   Database (GORM / SQL) - Relational update.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - user: The modified user entity.
	//
	// Returns:
	//   - error: Nil on success, or database error.
	//
	// Example SQL:
	//   UPDATE users SET email = $1, email_verified = $2, updated_at = $3 WHERE id = $4;
	UpdateUser(ctx context.Context, user *entity.User) error

	// GetAccountByUserIDAndProvider retrieves an account matching a given user and authentication provider.
	//
	// Function:
	//   Used to locate provider credentials for a user.
	//
	// Storage:
	//   Database (GORM / SQL) - Account credentials record lookup.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - userID: The target user's ID.
	//   - providerID: The provider identifier (e.g. "credential").
	//
	// Returns:
	//   - *entity.Account: The matching account if found.
	//   - error: ErrAccountNotFound if missing, or database error.
	//
	// Example SQL:
	//   SELECT id, user_id, provider, created_at, updated_at FROM accounts WHERE user_id = $1 AND provider = $2 LIMIT 1;
	GetAccountByUserIDAndProvider(ctx context.Context, userID, providerID string) (*entity.Account, error)

	// CreateAccount associates a new provider authentication account with a user.
	//
	// Function:
	//   Persists account credential linking record.
	//
	// Storage:
	//   Database (GORM / SQL) - Account entity creation.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - account: The Account entity to persist.
	//
	// Returns:
	//   - error: Nil on success, or database error.
	//
	// Example SQL:
	//   INSERT INTO accounts (id, user_id, provider, created_at, updated_at) VALUES ($1, $2, $3, $4, $5);
	CreateAccount(ctx context.Context, account *entity.Account) error

	// UpdateAccountPassword updates the password hash on a user's credential account.
	//
	// Function:
	//   Called during password reset or credential update.
	//
	// Storage:
	//   Database (GORM / SQL) - Account password hash update.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - userID: The target user's ID.
	//   - passwordHash: The newly calculated password hash string.
	//
	// Returns:
	//   - error: Nil on success, or database error.
	//
	// Example SQL:
	//   UPDATE accounts SET password = $1, updated_at = $2 WHERE user_id = $3 AND provider = 'credential';
	UpdateAccountPassword(ctx context.Context, userID, passwordHash string) error

	// DeleteCredentialAccount removes the credential account for a user adopted via passwordless OTP.
	//
	// Function:
	//   Unlinks password credential account.
	//
	// Storage:
	//   Database (GORM / SQL) - Record deletion.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - userID: The target user's ID.
	//
	// Returns:
	//   - error: Nil on success, or database error.
	//
	// Example SQL:
	//   DELETE FROM accounts WHERE user_id = $1 AND provider = 'credential';
	DeleteCredentialAccount(ctx context.Context, userID string) error

	// SessionRepository provides session creation and invalidation operations.
	repository.SessionRepository
}
