package phonenumber

import (
	"context"
	"errors"
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/dto"
	"github.com/BladiCreator/go-modular-auth/domain/entity"
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

// VerificationRecord represents the persistent storage entity for an OTP verification value.
type VerificationRecord struct {
	// ID is the unique database record identifier.
	ID string `json:"id"`

	// Identifier is the composite lookup key (e.g. "phone-verification-otp-+1234567890").
	Identifier string `json:"identifier"`

	// Value stores the code and attempt counter formatted as "<stored_otp>:<attempts>".
	Value string `json:"value"`

	// ExpiresAt specifies the exact timestamp after which this verification value is invalid.
	ExpiresAt time.Time `json:"expires_at"`

	// CreatedAt records when the verification record was initialized.
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt records when the verification record was last modified.
	UpdatedAt time.Time `json:"updated_at"`
}

// Repository defines the persistent storage contract required by the Phone Number plugin.
// Implement this interface on your custom database adapter (e.g. PostgreSQL, MySQL, SQLite, MongoDB, GORM).
type Repository interface {
	// FindVerificationValue retrieves an active verification record matching the given identifier.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - identifier: The composite OTP key (e.g. "phone-verification-otp-+1234567890").
	//
	// Returns:
	//   - *VerificationRecord: The matching record if found.
	//   - error: Nil on success, or database error.
	FindVerificationValue(ctx context.Context, identifier string) (*VerificationRecord, error)

	// CreateVerificationValue creates or replaces a verification record in storage.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - record: The VerificationRecord entity to persist.
	//
	// Returns:
	//   - error: Nil on success, or database error.
	CreateVerificationValue(ctx context.Context, record *VerificationRecord) error

	// UpdateVerificationValue updates the value and expiry of an existing verification record.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - identifier: The composite OTP key.
	//   - value: The updated value payload (e.g. "<stored_otp>:<attempts>").
	//   - expiresAt: The updated expiration timestamp.
	//
	// Returns:
	//   - error: Nil on success, or database error.
	UpdateVerificationValue(ctx context.Context, identifier, value string, expiresAt time.Time) error

	// DeleteVerificationValue removes a verification record from storage by identifier.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - identifier: The composite OTP key.
	//
	// Returns:
	//   - error: Nil on success, or database error.
	DeleteVerificationValue(ctx context.Context, identifier string) error

	// ConsumeVerificationValue atomically retrieves and deletes a verification record in a single operation.
	// This ensures strictly single-use anti-replay protection under high concurrency.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - identifier: The composite OTP key.
	//
	// Returns:
	//   - *VerificationRecord: The consumed record if it existed and was not expired.
	//   - error: Nil on success, or database error if not found.
	ConsumeVerificationValue(ctx context.Context, identifier string) (*VerificationRecord, error)

	// GetUserByID retrieves a user entity matching the provided unique identifier.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - userID: The user's primary key ID.
	//
	// Returns:
	//   - *entity.User: The matching user entity if found.
	//   - error: ErrUserNotFound if missing, or database error.
	GetUserByID(ctx context.Context, userID string) (*entity.User, error)

	// GetUserByPhoneNumber retrieves a user entity matching the provided phone number.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - phoneNumber: The normalized phone number to query.
	//
	// Returns:
	//   - *entity.User: The matching user entity if found.
	//   - error: ErrUserNotFound if missing, or database error.
	GetUserByPhoneNumber(ctx context.Context, phoneNumber string) (*entity.User, error)

	// CreateUser persists a newly registered user in storage.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - params: Parameters containing name, email, phone number, and metadata.
	//
	// Returns:
	//   - *entity.User: The created user entity.
	//   - error: Nil on success, or database error.
	CreateUser(ctx context.Context, params *dto.CreateUserParams) (*entity.User, error)

	// UpdateUser updates modified fields of an existing user profile (e.g. PhoneNumber, PhoneNumberVerified).
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - user: The modified user entity.
	//
	// Returns:
	//   - error: Nil on success, or database error.
	UpdateUser(ctx context.Context, user *entity.User) error

	// GetAccountByUserIDAndProvider retrieves an account matching a given user and authentication provider.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - userID: The target user's ID.
	//   - providerID: The provider identifier (e.g. "credential").
	//
	// Returns:
	//   - *entity.Account: The matching account if found.
	//   - error: ErrCredentialAccountNotFound if missing, or database error.
	GetAccountByUserIDAndProvider(ctx context.Context, userID, providerID string) (*entity.Account, error)

	// CreateAccount associates a new provider authentication account with a user.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - account: The Account entity to persist.
	//
	// Returns:
	//   - error: Nil on success, or database error.
	CreateAccount(ctx context.Context, account *entity.Account) error

	// UpdateAccountPassword updates the password hash on a user's credential account.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - userID: The target user's ID.
	//   - passwordHash: The newly calculated password hash string.
	//
	// Returns:
	//   - error: Nil on success, or database error.
	UpdateAccountPassword(ctx context.Context, userID, passwordHash string) error

	// CreateSession persists a new active user session in storage.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - params: Parameters containing userID, token, expiration, and metadata.
	//
	// Returns:
	//   - *entity.Session: The created session entity.
	//   - error: Nil on success, or database error.
	CreateSession(ctx context.Context, params *dto.CreateSessionParams) (*entity.Session, error)

	// DeleteSessionsByUserID invalidates all active sessions for a user (used upon password reset).
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - userID: The target user's ID.
	//
	// Returns:
	//   - error: Nil on success, or database error.
	DeleteSessionsByUserID(ctx context.Context, userID string) error
}
