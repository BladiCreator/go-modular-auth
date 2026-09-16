package phonenumber

import (
	"context"
	"errors"

	"github.com/BladiCreator/go-modular-auth/domain/dto"
	"github.com/BladiCreator/go-modular-auth/domain/entity"
	"github.com/BladiCreator/go-modular-auth/domain/repository"
)

// Sentinel errors for the Phone Number plugin.
var (
	// ErrInvalidPhoneNumber is returned when a phone number format validation fails or is empty.
	ErrInvalidPhoneNumber = errors.New("phonenumber: invalid phone number")

	// ErrPhoneNumberAlreadyExists is returned when attempting to assign a phone number that already belongs to another user.
	ErrPhoneNumberAlreadyExists = errors.New("phonenumber: phone number already in use by another user")

	// ErrPhoneNumberNotRegistered is returned when attempting to sign in with a phone number that does not exist in storage and auto-signup is disabled.
	ErrPhoneNumberNotRegistered = errors.New("phonenumber: phone number is not registered")

	// ErrInvalidPhoneNumberOrPassword is returned when phone + password login credentials do not match.
	ErrInvalidPhoneNumberOrPassword = errors.New("phonenumber: invalid phone number or password")

	// ErrPhoneNumberNotVerified is returned when attempting password sign-in with an unverified phone number while RequireVerification is enabled.
	ErrPhoneNumberNotVerified = errors.New("phonenumber: phone number is not verified")

	// ErrPhoneNumberCannotBeUpdated is returned when direct phone mutation is disallowed without prior verification.
	ErrPhoneNumberCannotBeUpdated = errors.New("phonenumber: phone number cannot be updated directly without verification")

	// ErrSendOTPNotImplemented is returned when attempting to dispatch an OTP without a configured SendOTP callback.
	ErrSendOTPNotImplemented = errors.New("phonenumber: send OTP callback is not configured")

	// ErrOTPNotFound is returned when no active OTP record exists for the given phone number identifier.
	ErrOTPNotFound = errors.New("phonenumber: OTP not found or already consumed")

	// ErrOTPExpired is returned when attempting to verify an OTP that has passed its expiration duration.
	ErrOTPExpired = errors.New("phonenumber: OTP expired")

	// ErrInvalidOTP is returned when the provided OTP code does not match the stored code or hash.
	ErrInvalidOTP = errors.New("phonenumber: invalid OTP")

	// ErrTooManyAttempts is returned when the maximum number of failed verification attempts on an active OTP has been exhausted.
	ErrTooManyAttempts = errors.New("phonenumber: maximum verification attempt limit reached")

	// ErrPasswordTooShort is returned when a new password does not satisfy the minimum length requirement.
	ErrPasswordTooShort = errors.New("phonenumber: password is too short")

	// ErrPasswordTooLong is returned when a new password exceeds the maximum allowed length.
	ErrPasswordTooLong = errors.New("phonenumber: password is too long")

	// ErrUserNotFound is returned when no user matches the queried ID or phone number.
	ErrUserNotFound = errors.New("phonenumber: user not found")

	// ErrCredentialAccountNotFound is returned when credential provider credentials are missing for the user.
	ErrCredentialAccountNotFound = errors.New("phonenumber: credential account not found")

	// ErrCannotRetrieveHashed is returned when attempting to inspect a plain text OTP while hashed storage mode is active.
	ErrCannotRetrieveHashed = errors.New("phonenumber: OTP is hashed, cannot retrieve plain text")

	// ErrInvalidStoredFormat is returned when a stored OTP record does not conform to the expected format.
	ErrInvalidStoredFormat = errors.New("phonenumber: invalid stored OTP record format")
)

// Repository defines the persistent storage contract required by the Phone Number plugin.
// Implement this interface on your custom database adapter (e.g. PostgreSQL, MySQL, SQLite, MongoDB, GORM).
type Repository interface {
	// VerificationRepository provides centralized ephemeral SMS OTP verification storage operations.
	repository.VerificationRepository

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
	//   - userID: The user's primary key ID.
	//
	// Returns:
	//   - *entity.User: The matching user entity if found.
	//   - error: ErrUserNotFound if missing, or database error.
	//
	// Example SQL:
	//   SELECT id, name, email, phone_number, phone_number_verified, created_at, updated_at FROM users WHERE id = $1 LIMIT 1;
	GetUserByID(ctx context.Context, userID string) (*entity.User, error)

	// GetUserByPhoneNumber retrieves a user entity matching the provided phone number.
	//
	// Function:
	//   Used during SMS OTP sign-in or signup to locate user account.
	//
	// Storage:
	//   Database (GORM / SQL) - Phone number index query.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - phoneNumber: The normalized phone number to query.
	//
	// Returns:
	//   - *entity.User: The matching user entity if found.
	//   - error: ErrUserNotFound if missing, or database error.
	//
	// Example SQL:
	//   SELECT id, name, email, phone_number, phone_number_verified, created_at, updated_at FROM users WHERE phone_number = $1 LIMIT 1;
	GetUserByPhoneNumber(ctx context.Context, phoneNumber string) (*entity.User, error)

	// CreateUser persists a newly registered user in storage.
	//
	// Function:
	//   Called when a new user registers via phone number OTP.
	//
	// Storage:
	//   Database (GORM / SQL) - Relational insert of new User entity.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - params: Parameters containing name, email, phone number, and metadata.
	//
	// Returns:
	//   - *entity.User: The created user entity.
	//   - error: Nil on success, or database error.
	//
	// Example SQL:
	//   INSERT INTO users (id, name, email, phone_number, phone_number_verified, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7);
	CreateUser(ctx context.Context, params *dto.CreateUserParams) (*entity.User, error)

	// UpdateUser updates modified fields of an existing user profile (e.g. PhoneNumber, PhoneNumberVerified).
	//
	// Function:
	//   Called when updating user attributes or setting PhoneNumberVerified to true.
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
	//   UPDATE users SET phone_number = $1, phone_number_verified = $2, updated_at = $3 WHERE id = $4;
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
	//   - error: ErrCredentialAccountNotFound if missing, or database error.
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
}
