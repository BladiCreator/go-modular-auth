package passkey

import (
	"context"
	"errors"
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/entity"
	"github.com/BladiCreator/go-modular-auth/domain/repository"
)

// Sentinel errors for the Passkey plugin.
var (
	// ErrPasskeyNotFound is returned when no registered passkey credential matches the query.
	ErrPasskeyNotFound = errors.New("passkey: passkey not found")

	// ErrPasskeyAlreadyExists is returned when attempting to register a credential that is already bound to an account.
	ErrPasskeyAlreadyExists = errors.New("passkey: passkey credential already registered")

	// ErrChallengeNotFound is returned when a WebAuthn ceremony challenge token is missing or invalid.
	ErrChallengeNotFound = errors.New("passkey: challenge not found or expired")

	// ErrChallengeExpired is returned when a submitted WebAuthn challenge has passed its expiration time.
	ErrChallengeExpired = errors.New("passkey: challenge has expired")

	// ErrInvalidCeremonyType is returned when a challenge issued for registration is used for authentication or vice-versa.
	ErrInvalidCeremonyType = errors.New("passkey: invalid ceremony type for this challenge")

	// ErrUnauthorized is returned when an unauthenticated session attempts to register a passkey without authorization.
	ErrUnauthorized = errors.New("passkey: unauthorized to perform this operation")

	// ErrVerificationFailed is returned when WebAuthn cryptographic assertion/attestation verification fails.
	ErrVerificationFailed = errors.New("passkey: failed to verify webauthn ceremony response")

	// ErrCounterNotIncremented is returned when an authenticator signature counter does not increment, indicating potential cloning.
	ErrCounterNotIncremented = errors.New("passkey: signature counter did not increment (possible authenticator clone)")

	// ErrUserNotFound is returned when the target user record cannot be found.
	ErrUserNotFound = errors.New("passkey: user not found")

	// ErrSessionRequired is returned when passkey registration is attempted without an active session while requireSession is true.
	ErrSessionRequired = errors.New("passkey: passkey registration requires an authenticated session")

	// ErrResolveUserRequired is returned when requireSession is false but no resolveUser callback is configured.
	ErrResolveUserRequired = errors.New("passkey: resolveUser callback is required when requireSession is false and no session exists")

	// ErrInvalidResolvedUser is returned when a custom resolveUser callback returns a nil user entity.
	ErrInvalidResolvedUser = errors.New("passkey: resolved user is invalid")

	// ErrOriginMissing is returned when RP origin cannot be resolved from the HTTP request context.
	ErrOriginMissing = errors.New("passkey: origin is missing in request context")

	// ErrInvalidParameter is returned when a required input parameter is missing or malformed.
	ErrInvalidParameter = errors.New("passkey: invalid parameter provided")

	// ErrUnableToCreateSession is returned when creating a user session fails after successful WebAuthn authentication.
	ErrUnableToCreateSession = errors.New("passkey: unable to create user session")

	// ErrFailedToUpdatePasskey is returned when updating passkey metadata or counter fails.
	ErrFailedToUpdatePasskey = errors.New("passkey: failed to update passkey")
)

// CeremonyType defines the type of WebAuthn ceremony.
type CeremonyType string

const (
	CeremonyRegistration   CeremonyType = "registration"
	CeremonyAuthentication CeremonyType = "authentication"
)

// PasskeyChallenge represents the ephemeral state of an in-flight WebAuthn challenge.
type PasskeyChallenge struct {
	Token       string       `json:"token"`
	Type        CeremonyType `json:"type"`
	Challenge   string       `json:"challenge"`
	UserID      *string      `json:"userId,omitempty"`
	UserName    *string      `json:"userName,omitempty"`
	DisplayName *string      `json:"displayName,omitempty"`
	Context     *string      `json:"context,omitempty"`
	SessionData string       `json:"sessionData"` // Serialized JSON of webauthn.SessionData
	ExpiresAt   time.Time    `json:"expiresAt"`
	CreatedAt   time.Time    `json:"createdAt"`
}

// Repository defines the storage contract required by the Passkey authentication plugin.
// Implement this interface on your custom database adapter (e.g. PostgreSQL, MySQL, SQLite, MongoDB, GORM).
//
// # Implementation Example (GORM / database/sql):
//
//	type GormPasskeyRepository struct {
//		db *gorm.DB
//	}
//
//	func (r *GormPasskeyRepository) GetPasskeyByCredentialID(ctx context.Context, credentialID string) (*entity.Passkey, error) {
//		var pk entity.Passkey
//		if err := r.db.WithContext(ctx).Where("credential_id = ?", credentialID).First(&pk).Error; err != nil {
//			if errors.Is(err, gorm.ErrRecordNotFound) {
//				return nil, passkey.ErrPasskeyNotFound
//			}
//			return nil, err
//		}
//		return &pk, nil
//	}
//
// # Storage and Caching Recommendation (Ephemeral Challenge Caching):
//
// In-flight WebAuthn challenges (`PasskeyChallenge`) are short-lived (e.g. 2-5 minutes) and single-use.
// Storing challenges in Redis or an in-memory key-value cache prevents unnecessary DB table writes:
//
//	type RedisPasskeyChallengeStore struct {
//		redis *redis.Client
//	}
//
//	func (r *RedisPasskeyChallengeStore) SavePasskeyChallenge(ctx context.Context, ch *passkey.PasskeyChallenge) error {
//		bytes, _ := json.Marshal(ch)
//		ttl := time.Until(ch.ExpiresAt)
//		return r.redis.Set(ctx, "webauthn:challenge:"+ch.Token, bytes, ttl).Err()
//	}
//
//	func (r *RedisPasskeyChallengeStore) ConsumePasskeyChallenge(ctx context.Context, token string) (*passkey.PasskeyChallenge, error) {
//		key := "webauthn:challenge:" + token
//		val, err := r.redis.GetDel(ctx, key).Bytes()
//		if err != nil {
//			return nil, passkey.ErrChallengeNotFound
//		}
//		var ch passkey.PasskeyChallenge
//		_ = json.Unmarshal(val, &ch)
//		return &ch, nil
//	}
type Repository interface {
	// CreatePasskey persists a new WebAuthn passkey credential record.
	//
	// Function:
	//   Called upon completing a WebAuthn registration ceremony to store public key credentials.
	//
	// Storage:
	//   Database (GORM / SQL) - Persistent storage for WebAuthn public keys.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - passkey: The Passkey entity containing credential ID, public key, counter, and transports.
	//
	// Returns:
	//   - error: Nil on success, or database error.
	//
	// Example SQL:
	//   INSERT INTO passkeys (id, user_id, credential_id, public_key, counter, aaguid, name, created_at, updated_at)
	//   VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);
	CreatePasskey(ctx context.Context, passkey *entity.Passkey) error

	// GetPasskeyByID retrieves a passkey credential by its primary key ID.
	//
	// Function:
	//   Used during passkey management (viewing or renaming passkeys).
	//
	// Storage:
	//   Database (GORM / SQL) - Passkey record lookup by ID.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - id: Unique passkey record identifier.
	//
	// Returns:
	//   - *entity.Passkey: Matching passkey entity if found.
	//   - error: ErrPasskeyNotFound if missing, or database error.
	//
	// Example SQL:
	//   SELECT id, user_id, credential_id, public_key, counter, aaguid, name, created_at, updated_at FROM passkeys WHERE id = $1 LIMIT 1;
	GetPasskeyByID(ctx context.Context, id string) (*entity.Passkey, error)

	// GetPasskeyByCredentialID retrieves a passkey credential by its raw WebAuthn credential ID.
	//
	// Function:
	//   Used during authentication ceremony verification to locate the matching public key.
	//
	// Storage:
	//   Database (GORM / SQL) - Query by unique credential ID string.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - credentialID: Base64URL encoded credential ID string.
	//
	// Returns:
	//   - *entity.Passkey: Matching passkey entity if found.
	//   - error: ErrPasskeyNotFound if missing, or database error.
	//
	// Example SQL:
	//   SELECT id, user_id, credential_id, public_key, counter, aaguid, name, created_at, updated_at FROM passkeys WHERE credential_id = $1 LIMIT 1;
	GetPasskeyByCredentialID(ctx context.Context, credentialID string) (*entity.Passkey, error)

	// ListPasskeysByUserID retrieves all registered passkey credentials belonging to a user.
	//
	// Function:
	//   Used during user security settings listing or passwordless sign-in user credential discovery.
	//
	// Storage:
	//   Database (GORM / SQL) - Query registered credentials by user ID.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - userID: Target user identifier.
	//
	// Returns:
	//   - []*entity.Passkey: Slice of registered passkey credentials.
	//   - error: Nil on success, or database error.
	//
	// Example SQL:
	//   SELECT id, user_id, credential_id, public_key, counter, aaguid, name, created_at, updated_at FROM passkeys WHERE user_id = $1;
	ListPasskeysByUserID(ctx context.Context, userID string) ([]*entity.Passkey, error)

	// UpdatePasskey updates mutable attributes of an existing passkey (e.g. friendly name).
	//
	// Function:
	//   Used when a user renames a registered passkey.
	//
	// Storage:
	//   Database (GORM / SQL) - Record update.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - passkey: Modified passkey entity.
	//
	// Returns:
	//   - error: Nil on success, or database error.
	//
	// Example SQL:
	//   UPDATE passkeys SET name = $1, updated_at = $2 WHERE id = $3;
	UpdatePasskey(ctx context.Context, passkey *entity.Passkey) error

	// UpdatePasskeyCounter updates the signature counter of a passkey after successful assertion.
	//
	// Function:
	//   Called after validating an authentication ceremony response to prevent clone attacks.
	//
	// Storage:
	//   Database (GORM / SQL) - Signature counter update.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - id: Unique passkey record ID.
	//   - newCounter: Incrementally higher signature counter value.
	//
	// Returns:
	//   - error: Nil on success, or database error.
	//
	// Example SQL:
	//   UPDATE passkeys SET counter = $1, updated_at = $2 WHERE id = $3;
	UpdatePasskeyCounter(ctx context.Context, id string, newCounter uint32) error

	// DeletePasskey permanently removes a single passkey credential record.
	//
	// Function:
	//   Called when a user revokes or deletes a passkey in security settings.
	//
	// Storage:
	//   Database (GORM / SQL) - Passkey credential deletion.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - id: Passkey record identifier.
	//
	// Returns:
	//   - error: Nil on success, or database error.
	//
	// Example SQL:
	//   DELETE FROM passkeys WHERE id = $1;
	DeletePasskey(ctx context.Context, id string) error

	// DeletePasskeysByUserID purges all passkeys belonging to a user.
	//
	// Function:
	//   Called during user account deletion.
	//
	// Storage:
	//   Database (GORM / SQL) - Bulk passkey deletion.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - userID: Target user identifier.
	//
	// Returns:
	//   - error: Nil on success, or database error.
	//
	// Example SQL:
	//   DELETE FROM passkeys WHERE user_id = $1;
	DeletePasskeysByUserID(ctx context.Context, userID string) error

	// SavePasskeyChallenge persists an ephemeral WebAuthn ceremony challenge record.
	//
	// Function:
	//   Called during generate-register-options and generate-authenticate-options endpoints.
	//
	// Storage:
	//   Cache (Redis / In-Memory TTL) - Short-lived in-flight challenge token with TTL.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - challenge: Ephemeral PasskeyChallenge state.
	//
	// Returns:
	//   - error: Nil on success, or database error.
	//
	// Example SQL:
	//   INSERT INTO passkey_challenges (token, type, challenge, user_id, session_data, expires_at, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7);
	//
	// Example Cache (Redis):
	//   err := rdb.Set(ctx, "webauthn:challenge:" + challenge.Token, bytes, ttl).Err()
	SavePasskeyChallenge(ctx context.Context, challenge *PasskeyChallenge) error

	// GetPasskeyChallenge retrieves an active ceremony challenge record by challenge token string.
	//
	// Function:
	//   Used to inspect challenge state without consuming it.
	//
	// Storage:
	//   Cache (Redis / In-Memory TTL) - Ephemeral challenge lookup.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - token: Ephemeral challenge token identifier.
	//
	// Returns:
	//   - *PasskeyChallenge: Matching challenge state.
	//   - error: ErrChallengeNotFound if missing or expired.
	//
	// Example SQL:
	//   SELECT token, type, challenge, user_id, session_data, expires_at, created_at FROM passkey_challenges WHERE token = $1 LIMIT 1;
	//
	// Example Cache (Redis):
	//   val, err := rdb.Get(ctx, "webauthn:challenge:" + token).Bytes()
	GetPasskeyChallenge(ctx context.Context, token string) (*PasskeyChallenge, error)

	// ConsumePasskeyChallenge atomically retrieves and removes an in-flight ceremony challenge record.
	//
	// Function:
	//   Called during ceremony verification endpoints to ensure single-use replay protection.
	//
	// Storage:
	//   Cache (Redis GETDEL / Memory) - Atomic read-and-delete single-use challenge consumption.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - token: Ephemeral challenge token identifier.
	//
	// Returns:
	//   - *PasskeyChallenge: The consumed challenge state if valid.
	//   - error: ErrChallengeNotFound if missing, or ErrChallengeExpired if passed validity time.
	//
	// Example SQL:
	//   DELETE FROM passkey_challenges WHERE token = $1 AND expires_at > $2 RETURNING token, type, challenge, user_id, session_data, expires_at, created_at;
	//
	// Example Cache (Redis):
	//   val, err := rdb.GetDel(ctx, "webauthn:challenge:" + token).Bytes()
	ConsumePasskeyChallenge(ctx context.Context, token string) (*PasskeyChallenge, error)

	// DeletePasskeyChallenge removes a challenge record from storage by token.
	//
	// Function:
	//   Called during explicit cancellation or cleanup.
	//
	// Storage:
	//   Cache (Redis / In-Memory TTL) - Challenge token eviction.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - token: Challenge token string.
	//
	// Returns:
	//   - error: Nil on success, or database error.
	//
	// Example SQL:
	//   DELETE FROM passkey_challenges WHERE token = $1;
	//
	// Example Cache (Redis):
	//   err := rdb.Del(ctx, "webauthn:challenge:" + token).Err()
	DeletePasskeyChallenge(ctx context.Context, token string) error

	// GetUserByID retrieves user profile details by ID.
	//
	// Function:
	//   Used during passkey registration to populate WebAuthn User Entity details (name, display name).
	//
	// Storage:
	//   Database (GORM / SQL) - User primary key lookup.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - userID: Target user identifier.
	//
	// Returns:
	//   - *entity.User: Matching user entity if found.
	//   - error: ErrUserNotFound if missing, or database error.
	//
	// Example SQL:
	//   SELECT id, email, name, email_verified, created_at, updated_at FROM users WHERE id = $1 LIMIT 1;
	GetUserByID(ctx context.Context, userID string) (*entity.User, error)

	// GetUserByEmail retrieves user profile details by email address.
	//
	// Function:
	//   Used during passwordless authentication initiation when identifying user by email.
	//
	// Storage:
	//   Database (GORM / SQL) - Query user by email address.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - email: User primary email address.
	//
	// Returns:
	//   - *entity.User: Matching user entity if found.
	//   - error: ErrUserNotFound if missing, or database error.
	//
	// Example SQL:
	//   SELECT id, email, name, email_verified, created_at, updated_at FROM users WHERE email = $1 LIMIT 1;
	GetUserByEmail(ctx context.Context, email string) (*entity.User, error)

	// SessionRepository provides session creation operations.
	repository.SessionRepository
}
