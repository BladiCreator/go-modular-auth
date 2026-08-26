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
// Implement this interface on your custom database adapter (e.g. PostgreSQL, MySQL, SQLite, MongoDB, GORM).
//
// # Implementation Example (GORM / database/sql):
//
//	type GormOttRepository struct {
//		db *gorm.DB
//	}
//
//	func (r *GormOttRepository) ConsumeVerificationValue(ctx context.Context, identifier string) (*ott.VerificationRecord, error) {
//		var rec ott.VerificationRecord
//		err := r.db.WithContext(ctx).Where("identifier = ? AND expires_at > ?", identifier, time.Now()).First(&rec).Error
//		if err != nil {
//			if errors.Is(err, gorm.ErrRecordNotFound) {
//				return nil, ott.ErrInvalidToken
//			}
//			return nil, err
//		}
//		_ = r.db.WithContext(ctx).Delete(&rec).Error
//		return &rec, nil
//	}
//
// # Storage and Caching Recommendation (Atomic Redis Ephemeral Storage):
//
// One-Time Tokens (OTT) are high-concurrency, short-lived tokens. Utilizing Redis `GETDEL` provides
// single-use atomic consumption that inherently prevents race conditions and replay attacks:
//
//	type RedisOttRepository struct {
//		redis *redis.Client
//	}
//
//	func (r *RedisOttRepository) CreateVerificationValue(ctx context.Context, record *ott.VerificationRecord) error {
//		bytes, _ := json.Marshal(record)
//		ttl := time.Until(record.ExpiresAt)
//		return r.redis.Set(ctx, "ott:"+record.Identifier, bytes, ttl).Err()
//	}
//
//	func (r *RedisOttRepository) ConsumeVerificationValue(ctx context.Context, identifier string) (*ott.VerificationRecord, error) {
//		key := "ott:" + identifier
//		val, err := r.redis.GetDel(ctx, key).Bytes()
//		if err != nil {
//			return nil, ott.ErrInvalidToken
//		}
//		var rec ott.VerificationRecord
//		_ = json.Unmarshal(val, &rec)
//		return &rec, nil
//	}
type Repository interface {
	// CreateVerificationValue stores a new OTT verification record in storage.
	//
	// Function:
	//   Called when generating a single-use One-Time Token (OTT).
	//
	// Storage:
	//   Cache (Redis / In-Memory TTL) - Short-lived single-use OTT token.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - record: VerificationRecord entity containing token identifier, session token value payload, and expiration timestamp.
	//
	// Returns:
	//   - error: Nil on success, or database error.
	//
	// Example SQL:
	//   INSERT INTO verification_tokens (id, identifier, value, expires_at, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6);
	//
	// Example Cache (Redis):
	//   err := rdb.Set(ctx, "ott:" + record.Identifier, bytes, ttl).Err()
	CreateVerificationValue(ctx context.Context, record *VerificationRecord) error

	// ConsumeVerificationValue atomically retrieves and deletes an OTT verification record by identifier.
	// This operation MUST be atomic to protect against replay attacks and race conditions.
	//
	// Function:
	//   Called during OTT exchange endpoint to authenticate and consume the one-time token.
	//
	// Storage:
	//   Cache (Redis GETDEL / Memory) - Atomic read-and-delete single-use token consumption.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - identifier: Composite token identifier key.
	//
	// Returns:
	//   - *VerificationRecord: Consumed record if found and not expired.
	//   - error: ErrInvalidToken if missing, or ErrTokenExpired if passed validity duration.
	//
	// Example SQL:
	//   DELETE FROM verification_tokens WHERE identifier = $1 AND expires_at > $2 RETURNING id, identifier, value, expires_at, created_at, updated_at;
	//
	// Example Cache (Redis):
	//   val, err := rdb.GetDel(ctx, "ott:" + identifier).Bytes()
	ConsumeVerificationValue(ctx context.Context, identifier string) (*VerificationRecord, error)

	// GetSessionByToken retrieves an active session entity matching the specified session token string.
	//
	// Function:
	//   Used after consuming an OTT token to verify and load the target session entity.
	//
	// Storage:
	//   Both (Cache-Aside Strategy) - Fast session retrieval by raw token string.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - token: Raw session token string stored in OTT value.
	//
	// Returns:
	//   - *entity.Session: Active session entity if found.
	//   - error: ErrSessionNotFound if missing, or ErrSessionExpired if expired.
	//
	// Example SQL:
	//   SELECT id, user_id, token, expires_at, created_at, updated_at FROM sessions WHERE token = $1 LIMIT 1;
	//
	// Example Cache (Redis):
	//   val, err := rdb.Get(ctx, "session:" + token).Bytes()
	GetSessionByToken(ctx context.Context, token string) (*entity.Session, error)

	// GetUserByID retrieves a user entity matching the specified user identifier.
	//
	// Function:
	//   Used to verify user existence and populate user context after consuming an OTT.
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
	//   SELECT id, email, name, email_verified, created_at, updated_at FROM users WHERE id = $1 LIMIT 1;
	GetUserByID(ctx context.Context, userID string) (*entity.User, error)
}
