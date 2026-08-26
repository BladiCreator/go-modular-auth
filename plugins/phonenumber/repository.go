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
//
// # Implementation Example (GORM / database/sql):
//
//	type GormPhoneNumberRepository struct {
//		db *gorm.DB
//	}
//
//	func (r *GormPhoneNumberRepository) FindVerificationValue(ctx context.Context, identifier string) (*phonenumber.VerificationRecord, error) {
//		var rec phonenumber.VerificationRecord
//		if err := r.db.WithContext(ctx).Where("identifier = ?", identifier).First(&rec).Error; err != nil {
//			if errors.Is(err, gorm.ErrRecordNotFound) {
//				return nil, nil
//			}
//			return nil, err
//		}
//		return &rec, nil
//	}
//
// # Storage and Caching Recommendation (Redis TTL Storage):
//
// SMS OTP codes (`VerificationRecord`) are short-lived, single-use credentials. Storing them in Redis
// with automatic key expiration (TTL) guarantees auto-cleanup without periodic DB purges:
//
//	type RedisPhoneNumberRepository struct {
//		redis *redis.Client
//	}
//
//	func (r *RedisPhoneNumberRepository) CreateVerificationValue(ctx context.Context, record *phonenumber.VerificationRecord) error {
//		bytes, _ := json.Marshal(record)
//		ttl := time.Until(record.ExpiresAt)
//		return r.redis.Set(ctx, "phoneotp:"+record.Identifier, bytes, ttl).Err()
//	}
//
//	func (r *RedisPhoneNumberRepository) ConsumeVerificationValue(ctx context.Context, identifier string) (*phonenumber.VerificationRecord, error) {
//		key := "phoneotp:" + identifier
//		val, err := r.redis.GetDel(ctx, key).Bytes() // Atomic single-use retrieval & deletion
//		if err != nil {
//			return nil, phonenumber.ErrOTPNotFound
//		}
//		var rec phonenumber.VerificationRecord
//		_ = json.Unmarshal(val, &rec)
//		return &rec, nil
//	}
type Repository interface {
	// FindVerificationValue retrieves an active verification record matching the given identifier.
	//
	// Function:
	//   Queries storage for an active SMS OTP verification record.
	//
	// Storage:
	//   Cache (Redis / In-Memory TTL) - Ephemeral short-lived SMS OTP token data.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - identifier: The composite OTP key (e.g. "phone-verification-otp-+1234567890").
	//
	// Returns:
	//   - *VerificationRecord: The matching record if found.
	//   - error: Nil on success, or database error.
	//
	// Example SQL:
	//   SELECT id, identifier, value, expires_at, created_at, updated_at FROM verification_tokens WHERE identifier = $1 LIMIT 1;
	//
	// Example Cache (Redis):
	//   val, err := rdb.Get(ctx, "phoneotp:" + identifier).Bytes()
	FindVerificationValue(ctx context.Context, identifier string) (*VerificationRecord, error)

	// CreateVerificationValue creates or replaces a verification record in storage.
	//
	// Function:
	//   Persists a newly generated SMS OTP verification record.
	//
	// Storage:
	//   Cache (Redis / In-Memory TTL) - Short-lived key-value with TTL equal to token validity.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - record: The VerificationRecord entity to persist.
	//
	// Returns:
	//   - error: Nil on success, or database error.
	//
	// Example SQL:
	//   INSERT INTO verification_tokens (id, identifier, value, expires_at, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6);
	//
	// Example Cache (Redis):
	//   err := rdb.Set(ctx, "phoneotp:" + record.Identifier, bytes, ttl).Err()
	CreateVerificationValue(ctx context.Context, record *VerificationRecord) error

	// UpdateVerificationValue updates the value and expiry of an existing verification record.
	//
	// Function:
	//   Updates attempts counter or regenerates SMS OTP code.
	//
	// Storage:
	//   Cache (Redis / In-Memory TTL) - Key update with adjusted TTL.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - identifier: The composite OTP key.
	//   - value: The updated value payload (e.g. "<stored_otp>:<attempts>").
	//   - expiresAt: The updated expiration timestamp.
	//
	// Returns:
	//   - error: Nil on success, or database error.
	//
	// Example SQL:
	//   UPDATE verification_tokens SET value = $1, expires_at = $2, updated_at = $3 WHERE identifier = $4;
	//
	// Example Cache (Redis):
	//   err := rdb.Set(ctx, "phoneotp:" + identifier, bytes, ttl).Err()
	UpdateVerificationValue(ctx context.Context, identifier, value string, expiresAt time.Time) error

	// DeleteVerificationValue removes a verification record from storage by identifier.
	//
	// Function:
	//   Explicit removal of an SMS OTP record upon invalidation.
	//
	// Storage:
	//   Cache (Redis / In-Memory TTL) - Key eviction from memory/Redis.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - identifier: The composite OTP key.
	//
	// Returns:
	//   - error: Nil on success, or database error.
	//
	// Example SQL:
	//   DELETE FROM verification_tokens WHERE identifier = $1;
	//
	// Example Cache (Redis):
	//   err := rdb.Del(ctx, "phoneotp:" + identifier).Err()
	DeleteVerificationValue(ctx context.Context, identifier string) error

	// ConsumeVerificationValue atomically retrieves and deletes a verification record in a single operation.
	// This ensures strictly single-use anti-replay protection under high concurrency.
	//
	// Function:
	//   Single-use SMS OTP verification and atomic consumption.
	//
	// Storage:
	//   Cache (Redis GETDEL / Memory) - Atomic read-and-delete operation.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - identifier: The composite OTP key.
	//
	// Returns:
	//   - *VerificationRecord: The consumed record if it existed and was not expired.
	//   - error: Nil on success, or database error if not found.
	//
	// Example SQL:
	//   DELETE FROM verification_tokens WHERE identifier = $1 AND expires_at > $2 RETURNING id, identifier, value, expires_at, created_at, updated_at;
	//
	// Example Cache (Redis):
	//   val, err := rdb.GetDel(ctx, "phoneotp:" + identifier).Bytes()
	ConsumeVerificationValue(ctx context.Context, identifier string) (*VerificationRecord, error)

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

	// CreateSession persists a new active user session in storage.
	//
	// Function:
	//   Creates a new active session upon successful SMS OTP verification.
	//
	// Storage:
	//   Database (GORM / SQL) - Active session creation.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - params: Parameters containing userID, token, expiration, and metadata.
	//
	// Returns:
	//   - *entity.Session: The created session entity.
	//   - error: Nil on success, or database error.
	//
	// Example SQL:
	//   INSERT INTO sessions (id, user_id, token, expires_at, ip_address, user_agent, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8);
	CreateSession(ctx context.Context, params *dto.CreateSessionParams) (*entity.Session, error)

	// DeleteSessionsByUserID invalidates all active sessions for a user (used upon password reset).
	//
	// Function:
	//   Bulk invalidation of user sessions.
	//
	// Storage:
	//   Database (GORM / SQL) - Bulk session removal.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - userID: The target user's ID.
	//
	// Returns:
	//   - error: Nil on success, or database error.
	//
	// Example SQL:
	//   DELETE FROM sessions WHERE user_id = $1;
	DeleteSessionsByUserID(ctx context.Context, userID string) error
}
