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
// Implement this interface on your custom database adapter (e.g. PostgreSQL, MySQL, SQLite, MongoDB, GORM).
//
// # Implementation Example (GORM / database/sql):
//
//	type GormMagicLinkRepository struct {
//		db *gorm.DB
//	}
//
//	func (r *GormMagicLinkRepository) FindVerificationValue(ctx context.Context, identifier string) (*magiclink.VerificationRecord, error) {
//		var rec magiclink.VerificationRecord
//		if err := r.db.WithContext(ctx).Where("identifier = ?", identifier).First(&rec).Error; err != nil {
//			if errors.Is(err, gorm.ErrRecordNotFound) {
//				return nil, magiclink.ErrInvalidToken
//			}
//			return nil, err
//		}
//		return &rec, nil
//	}
//
// # Storage and Caching Recommendation (Redis TTL Storage):
//
// Magic Link tokens (`VerificationRecord`) are ephemeral single-use tokens. Using Redis with automatic
// key TTL expiration ensures zero storage bloat and instantaneous token retrieval:
//
//	type RedisMagicLinkRepository struct {
//		redis *redis.Client
//	}
//
//	func (r *RedisMagicLinkRepository) CreateVerificationValue(ctx context.Context, record *magiclink.VerificationRecord) error {
//		bytes, _ := json.Marshal(record)
//		ttl := time.Until(record.ExpiresAt)
//		return r.redis.Set(ctx, "magiclink:"+record.Identifier, bytes, ttl).Err()
//	}
//
//	func (r *RedisMagicLinkRepository) ConsumeVerificationValue(ctx context.Context, identifier string) (*magiclink.VerificationRecord, error) {
//		key := "magiclink:" + identifier
//		val, err := r.redis.GetDel(ctx, key).Bytes()
//		if err != nil {
//			return nil, magiclink.ErrInvalidToken
//		}
//		var rec magiclink.VerificationRecord
//		_ = json.Unmarshal(val, &rec)
//		return &rec, nil
//	}
type Repository interface {
	// CreateVerificationValue creates a new verification record in persistent storage.
	//
	// Function:
	//   Called when generating and dispatching a new magic link verification token.
	//
	// Storage:
	//   Cache (Redis / In-Memory TTL) - Short-lived single-use magic link token.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - record: VerificationRecord containing identifier key, raw/hashed token, and expiration timestamp.
	//
	// Returns:
	//   - error: Nil on success, or database error.
	//
	// Example SQL:
	//   INSERT INTO verification_tokens (id, identifier, value, expires_at, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6);
	//
	// Example Cache (Redis):
	//   err := rdb.Set(ctx, "magiclink:" + record.Identifier, bytes, ttl).Err()
	CreateVerificationValue(ctx context.Context, record *VerificationRecord) error

	// FindVerificationValue retrieves an active verification record matching the given identifier.
	//
	// Function:
	//   Used to inspect token validity without consuming it.
	//
	// Storage:
	//   Cache (Redis / In-Memory TTL) - Ephemeral token lookup.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - identifier: Composite token key (e.g. "magic-link-token:<hash>").
	//
	// Returns:
	//   - *VerificationRecord: Matching token record if found.
	//   - error: ErrInvalidToken if missing, or database error.
	//
	// Example SQL:
	//   SELECT id, identifier, value, expires_at, created_at, updated_at FROM verification_tokens WHERE identifier = $1 LIMIT 1;
	//
	// Example Cache (Redis):
	//   val, err := rdb.Get(ctx, "magiclink:" + identifier).Bytes()
	FindVerificationValue(ctx context.Context, identifier string) (*VerificationRecord, error)

	// ConsumeVerificationValue atomically retrieves and removes/invalidates a verification record by identifier.
	// This operation MUST be single-use to protect against race conditions and token replay attacks.
	//
	// Function:
	//   Called during magic link verification endpoint to authenticate the user and consume the token.
	//
	// Storage:
	//   Cache (Redis GETDEL / Memory) - Atomic read-and-delete single-use token consumption.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - identifier: Composite token key.
	//
	// Returns:
	//   - *VerificationRecord: Consumed record if found and not expired.
	//   - error: ErrInvalidToken if missing, or ErrTokenExpired if passed expiry duration.
	//
	// Example SQL:
	//   DELETE FROM verification_tokens WHERE identifier = $1 AND expires_at > $2 RETURNING id, identifier, value, expires_at, created_at, updated_at;
	//
	// Example Cache (Redis):
	//   val, err := rdb.GetDel(ctx, "magiclink:" + identifier).Bytes()
	ConsumeVerificationValue(ctx context.Context, identifier string) (*VerificationRecord, error)

	// DeleteVerificationValue removes a verification record from persistent storage.
	//
	// Function:
	//   Called during cleanup or explicit revocation.
	//
	// Storage:
	//   Cache (Redis / In-Memory TTL) - Token key deletion.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - identifier: Token identifier key.
	//
	// Returns:
	//   - error: Nil on success.
	//
	// Example SQL:
	//   DELETE FROM verification_tokens WHERE identifier = $1;
	//
	// Example Cache (Redis):
	//   err := rdb.Del(ctx, "magiclink:" + identifier).Err()
	DeleteVerificationValue(ctx context.Context, identifier string) error

	// FindUserByEmail retrieves a user by their email address.
	//
	// Function:
	//   Called during magic link verification to find the target user.
	//
	// Storage:
	//   Database (GORM / SQL) - Relational user entity query.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - email: Recipient email address.
	//
	// Returns:
	//   - *entity.User: Matching user profile if found.
	//   - error: ErrUserNotFound if missing.
	//
	// Example SQL:
	//   SELECT id, email, name, email_verified, created_at, updated_at FROM users WHERE email = $1 LIMIT 1;
	FindUserByEmail(ctx context.Context, email string) (*entity.User, error)

	// CreateUser persists a new user entity in storage.
	//
	// Function:
	//   Called during magic link verification when sign-up is allowed for new email addresses.
	//
	// Storage:
	//   Database (GORM / SQL) - User entity insertion.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - user: User entity to persist.
	//
	// Returns:
	//   - *entity.User: Newly created user record.
	//   - error: Nil on success, or database error.
	//
	// Example SQL:
	//   INSERT INTO users (id, email, name, email_verified, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6);
	CreateUser(ctx context.Context, user *entity.User) (*entity.User, error)

	// UpdateEmailVerified updates the email verification status for a specific user.
	//
	// Function:
	//   Called after verifying a magic link to set email_verified = true.
	//
	// Storage:
	//   Database (GORM / SQL) - User table update.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - userID: Target user ID.
	//   - verified: Boolean state.
	//
	// Returns:
	//   - error: Nil on success.
	//
	// Example SQL:
	//   UPDATE users SET email_verified = $1, updated_at = $2 WHERE id = $3;
	UpdateEmailVerified(ctx context.Context, userID string, verified bool) error

	// CreateSession initializes and persists an active user session.
	//
	// Function:
	//   Called after successful magic link verification to authenticate the user.
	//
	// Storage:
	//   Database (GORM / SQL) - Active session creation.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - session: Active session entity.
	//
	// Returns:
	//   - *entity.Session: Active session record.
	//   - error: Nil on success.
	//
	// Example SQL:
	//   INSERT INTO sessions (id, user_id, token, expires_at, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6);
	CreateSession(ctx context.Context, session *entity.Session) (*entity.Session, error)
}
