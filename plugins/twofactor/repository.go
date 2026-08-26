package twofactor

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrTwoFactorNotEnabled is returned when 2FA operations are attempted for a user without active 2FA configuration.
	ErrTwoFactorNotEnabled = errors.New("twofactor: two-factor authentication is not enabled for this user")

	// ErrTwoFactorAlreadyEnabled is returned when attempting to enable 2FA on an account that already has verified 2FA active.
	ErrTwoFactorAlreadyEnabled = errors.New("twofactor: two-factor authentication is already enabled")

	// ErrInvalidCode is returned when a provided TOTP or backup code is invalid or does not match stored credentials.
	ErrInvalidCode = errors.New("twofactor: invalid verification code")

	// ErrAccountLocked is returned when 2FA verification is temporarily locked due to excessive failed attempts.
	ErrAccountLocked = errors.New("twofactor: two-factor authentication is temporarily locked due to excessive failed attempts")

	// ErrOTPNotConfigured is returned when attempting to send an OTP challenge without a registered SendOTP delivery callback.
	ErrOTPNotConfigured = errors.New("twofactor: send OTP callback is not configured")

	// ErrOTPExpired is returned when attempting to verify an OTP challenge that has expired or does not exist.
	ErrOTPExpired = errors.New("twofactor: OTP challenge has expired or does not exist")

	// ErrTooManyAttempts is returned when the maximum number of failed attempts on an active OTP challenge or lockout threshold has been exceeded.
	ErrTooManyAttempts = errors.New("twofactor: maximum attempt limit reached")

	// ErrPasswordRequired is returned when an operation strictly requires password confirmation before proceeding.
	ErrPasswordRequired = errors.New("twofactor: password is required for this operation")

	// ErrInvalidDeviceToken is returned when a trusted device token signature fails validation or has expired.
	ErrInvalidDeviceToken = errors.New("twofactor: trusted device token is invalid or expired")

	// ErrChallengeExpired is returned when a sign-in challenge token has passed its expiration time.
	ErrChallengeExpired = errors.New("twofactor: challenge token has expired")

	// ErrInvalidChallengeToken is returned when a submitted sign-in challenge token does not exist in storage.
	ErrInvalidChallengeToken = errors.New("twofactor: invalid challenge token")
)

// TwoFactor represents the persistent storage entity containing a user's 2FA configuration, secrets, and security state.
type TwoFactor struct {
	// ID is the unique database record identifier.
	ID string `json:"id"`

	// UserID uniquely identifies the owner user of this 2FA configuration.
	UserID string `json:"user_id"`

	// Secret is the Base32-encoded cryptographic secret used for TOTP calculation.
	Secret string `json:"secret"`

	// BackupCodes is a serialized JSON array containing unconsumed single-use backup codes (e.g. `["CODE1", "CODE2"]`).
	BackupCodes string `json:"backup_codes"`

	// Verified indicates whether initial TOTP verification has succeeded and 2FA is actively enforced.
	Verified bool `json:"verified"`

	// Failures tracks the number of consecutive failed verification attempts.
	Failures int `json:"failures"`

	// LockedUntil specifies the timestamp until which 2FA operations are locked due to rate limiting (nil if unlocked).
	LockedUntil *time.Time `json:"locked_until"`

	// CreatedAt records the timestamp when 2FA enrollment was initialized.
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt records the timestamp when 2FA settings were last modified.
	UpdatedAt time.Time `json:"updated_at"`
}

// OTPChallenge represents a temporary, short-lived one-time challenge delivered via SMS or Email.
type OTPChallenge struct {
	// Key is the unique challenge storage key (e.g. "2fa-otp-<userID>").
	Key string `json:"key"`

	// UserID is the recipient user's unique identifier.
	UserID string `json:"user_id"`

	// CodeHash is the generated numeric OTP challenge code.
	CodeHash string `json:"code_hash"`

	// Attempts tracks the number of failed verification tries against this specific challenge.
	Attempts int `json:"attempts"`

	// ExpiresAt specifies the exact timestamp after which this challenge is invalid.
	ExpiresAt time.Time `json:"expires_at"`
}

// TrustDeviceRecord stores a persistent authorization record for a recognized client device.
type TrustDeviceRecord struct {
	// ID is the primary key identifier for the trusted device entry.
	ID string `json:"id"`

	// UserID is the owner user's unique identifier.
	UserID string `json:"user_id"`

	// DeviceID is the unique client hardware or browser installation identifier.
	DeviceID string `json:"device_id"`

	// TokenHash is the cryptographic hash or signature of the trusted device token.
	TokenHash string `json:"token_hash"`

	// ExpiresAt specifies when this device trust authorization expires.
	ExpiresAt time.Time `json:"expires_at"`

	// CreatedAt is the timestamp when the device was initially authorized.
	CreatedAt time.Time `json:"created_at"`
}

// ChallengeRecord represents a temporary sign-in challenge issued after primary credential validation.
type ChallengeRecord struct {
	// Token is the unique challenge token string.
	Token string `json:"token"`

	// UserID is the target user required to fulfill the 2FA challenge.
	UserID string `json:"user_id"`

	// ExpiresAt is the timestamp after which this challenge token becomes invalid.
	ExpiresAt time.Time `json:"expires_at"`

	// CreatedAt is the timestamp when the challenge was generated.
	CreatedAt time.Time `json:"created_at"`
}

// Repository defines the persistent storage contract required by the TwoFactor plugin.
// Implement this interface on your custom database adapter (e.g. PostgreSQL, MySQL, SQLite, MongoDB, GORM).
//
// # Implementation Example (GORM / database/sql):
//
//	type GormTwoFactorRepo struct {
//		db *gorm.DB
//	}
//
//	func (r *GormTwoFactorRepo) FindByUserID(ctx context.Context, userID string) (*twofactor.TwoFactor, error) {
//		var m TwoFactorModel
//		if err := r.db.WithContext(ctx).Where("user_id = ?", userID).First(&m).Error; err != nil {
//			if errors.Is(err, gorm.ErrRecordNotFound) {
//				return nil, twofactor.ErrTwoFactorNotEnabled
//			}
//			return nil, err
//		}
//		return m.ToEntity(), nil
//	}
//
// # Storage and Caching Recommendation (Redis Challenge & Lockout Cache):
//
// Ephemeral SMS/Email 2FA challenges (`OTPChallenge`) and lockout timers are temporary states.
// Managing challenge keys (`2fa:challenge:<key>`) in Redis ensures auto-expiry and high availability:
//
//	type RedisTwoFactorChallengeStore struct {
//		redis *redis.Client
//	}
//
//	func (r *RedisTwoFactorChallengeStore) SaveOTPChallenge(ctx context.Context, challenge *twofactor.OTPChallenge) error {
//		bytes, _ := json.Marshal(challenge)
//		ttl := time.Until(challenge.ExpiresAt)
//		return r.redis.Set(ctx, "2fa:challenge:"+challenge.Key, bytes, ttl).Err()
//	}
//
//	func (r *RedisTwoFactorChallengeStore) GetOTPChallenge(ctx context.Context, key string) (*twofactor.OTPChallenge, error) {
//		val, err := r.redis.Get(ctx, "2fa:challenge:"+key).Bytes()
//		if err != nil {
//			return nil, twofactor.ErrOTPExpired
//		}
//		var ch twofactor.OTPChallenge
//		_ = json.Unmarshal(val, &ch)
//		return &ch, nil
//	}
type Repository interface {
	// FindByUserID retrieves the 2FA configuration record for a given user ID.
	//
	// Function:
	//   Used during TOTP validation, backup code verification, and viewing active backup codes.
	//
	// Storage:
	//   Database (GORM / SQL) - Relational 2FA configuration persistence.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - userID: The unique user identifier to look up.
	//
	// Returns:
	//   - *TwoFactor: The populated TwoFactor configuration entity.
	//   - error: ErrTwoFactorNotEnabled if no record exists, or database error on failure.
	//
	// Example SQL:
	//   SELECT id, user_id, secret, backup_codes, verified, failures, locked_until, created_at, updated_at
	//   FROM two_factors WHERE user_id = $1 LIMIT 1;
	FindByUserID(ctx context.Context, userID string) (*TwoFactor, error)

	// Create persists a new TwoFactor entity in storage.
	//
	// Function:
	//   Called during Enable when initializing 2FA enrollment for a user.
	//
	// Storage:
	//   Database (GORM / SQL) - 2FA configuration insert.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - tf: The newly initialized TwoFactor struct.
	//
	// Returns:
	//   - error: Nil on success, or database error on failure.
	//
	// Example SQL:
	//   INSERT INTO two_factors (id, user_id, secret, backup_codes, verified, failures, locked_until, created_at, updated_at)
	//   VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);
	Create(ctx context.Context, tf *TwoFactor) error

	// Update modifies an existing TwoFactor record in storage.
	//
	// Function:
	//   Called after consuming a backup code, regenerating backup codes, updating failure counts,
	//   setting lockout expiration, or marking enrollment as verified.
	//
	// Storage:
	//   Database (GORM / SQL) - 2FA configuration update.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - tf: The modified TwoFactor struct.
	//
	// Returns:
	//   - error: Nil on success, or database error on failure.
	//
	// Example SQL:
	//   UPDATE two_factors SET secret = $1, backup_codes = $2, verified = $3, failures = $4, locked_until = $5, updated_at = $6
	//   WHERE user_id = $7;
	Update(ctx context.Context, tf *TwoFactor) error

	// DeleteByUserID removes 2FA configuration for a user ID when disabling 2FA.
	//
	// Function:
	//   Called during Disable to completely purge 2FA credentials for the user.
	//
	// Storage:
	//   Database (GORM / SQL) - 2FA configuration record removal.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - userID: The target user's ID.
	//
	// Returns:
	//   - error: Nil on success, or database error on failure.
	//
	// Example SQL:
	//   DELETE FROM two_factors WHERE user_id = $1;
	DeleteByUserID(ctx context.Context, userID string) error

	// SaveOTPChallenge stores or updates a short-lived challenge code.
	//
	// Function:
	//   Called during SendOTP when creating a new numeric challenge, or during VerifyOTP when incrementing failed attempts.
	//
	// Storage:
	//   Cache (Redis / In-Memory TTL) - Short-lived numeric OTP challenge state with expiration TTL.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - challenge: The OTPChallenge entity to persist or update.
	//
	// Returns:
	//   - error: Nil on success, or database error on failure.
	//
	// Example SQL:
	//   INSERT INTO otp_challenges (key, user_id, code_hash, attempts, expires_at)
	//   VALUES ($1, $2, $3, $4, $5) ON CONFLICT (key) DO UPDATE SET attempts = $4;
	//
	// Example Cache (Redis):
	//   err := rdb.Set(ctx, "2fa:challenge:" + challenge.Key, bytes, ttl).Err()
	SaveOTPChallenge(ctx context.Context, challenge *OTPChallenge) error

	// GetOTPChallenge retrieves an active challenge by its composite key.
	//
	// Function:
	//   Called during VerifyOTP to compare the user's submitted challenge code and verify expiration.
	//
	// Storage:
	//   Cache (Redis / In-Memory TTL) - OTP challenge key lookup.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - key: The composite challenge key (e.g. "2fa-otp-<userID>").
	//
	// Returns:
	//   - *OTPChallenge: The matching challenge entity.
	//   - error: ErrOTPExpired if no active challenge matches, or database error on failure.
	//
	// Example SQL:
	//   SELECT key, user_id, code_hash, attempts, expires_at FROM otp_challenges WHERE key = $1 LIMIT 1;
	//
	// Example Cache (Redis):
	//   val, err := rdb.Get(ctx, "2fa:challenge:" + key).Bytes()
	GetOTPChallenge(ctx context.Context, key string) (*OTPChallenge, error)

	// DeleteOTPChallenge deletes a consumed or expired OTP challenge.
	//
	// Function:
	//   Called upon successful verification (single-use consumption) or when maximum attempts are exceeded.
	//
	// Storage:
	//   Cache (Redis / In-Memory TTL) - OTP challenge key eviction.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - key: The composite challenge key to delete.
	//
	// Returns:
	//   - error: Nil on success, or database error on failure.
	//
	// Example SQL:
	//   DELETE FROM otp_challenges WHERE key = $1;
	//
	// Example Cache (Redis):
	//   err := rdb.Del(ctx, "2fa:challenge:" + key).Err()
	DeleteOTPChallenge(ctx context.Context, key string) error

	// SaveTrustDevice stores or updates an authorized trusted device record.
	//
	// Function:
	//   Called when a user marks "Trust this device" during 2FA verification or calls TrustDevice.
	//
	// Storage:
	//   Database (GORM / SQL) - Authorized device record.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - record: The TrustDeviceRecord to insert or update.
	//
	// Returns:
	//   - error: Nil on success, or database error on failure.
	//
	// Example SQL:
	//   INSERT INTO trusted_devices (id, user_id, device_id, token_hash, expires_at, created_at)
	//   VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (user_id, device_id) DO UPDATE SET token_hash = $4, expires_at = $5;
	SaveTrustDevice(ctx context.Context, record *TrustDeviceRecord) error

	// FindTrustDevice retrieves an authorized device record by user ID and device ID.
	//
	// Function:
	//   Called during VerifyTrustDevice or challenge creation to check if 2FA can be safely bypassed.
	//
	// Storage:
	//   Database (GORM / SQL) - Trusted device query.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - userID: Target user ID.
	//   - deviceID: Target client hardware/device ID.
	//
	// Returns:
	//   - *TrustDeviceRecord: The matching record.
	//   - error: ErrInvalidDeviceToken if not found or expired, or database error.
	//
	// Example SQL:
	//   SELECT id, user_id, device_id, token_hash, expires_at, created_at
	//   FROM trusted_devices WHERE user_id = $1 AND device_id = $2 LIMIT 1;
	FindTrustDevice(ctx context.Context, userID, deviceID string) (*TrustDeviceRecord, error)

	// DeleteTrustDevice revokes trust for a single device.
	//
	// Function:
	//   Called during RevokeTrustedDevice to unauthorize a specific client device.
	//
	// Storage:
	//   Database (GORM / SQL) - Trusted device deletion.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - userID: Owner user ID.
	//   - deviceID: Device identifier to unauthorize.
	//
	// Returns:
	//   - error: Nil on success, or database error on failure.
	//
	// Example SQL:
	//   DELETE FROM trusted_devices WHERE user_id = $1 AND device_id = $2;
	DeleteTrustDevice(ctx context.Context, userID, deviceID string) error

	// DeleteTrustDevicesByUserID revokes all authorized devices for a user.
	//
	// Function:
	//   Called during Disable or security credential reset to invalidate all trusted client sessions.
	//
	// Storage:
	//   Database (GORM / SQL) - Bulk trusted device deletion.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - userID: Target user ID.
	//
	// Returns:
	//   - error: Nil on success, or database error on failure.
	//
	// Example SQL:
	//   DELETE FROM trusted_devices WHERE user_id = $1;
	DeleteTrustDevicesByUserID(ctx context.Context, userID string) error

	// SaveChallenge stores a temporary sign-in challenge token.
	//
	// Function:
	//   Called during CreateChallenge after primary login when 2FA is required.
	//
	// Storage:
	//   Cache (Redis / In-Memory TTL) - Ephemeral sign-in challenge token.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - challenge: The ChallengeRecord to persist.
	//
	// Returns:
	//   - error: Nil on success, or database error on failure.
	//
	// Example SQL:
	//   INSERT INTO two_factor_challenges (token, user_id, expires_at, created_at)
	//   VALUES ($1, $2, $3, $4);
	//
	// Example Cache (Redis):
	//   err := rdb.Set(ctx, "2fa:signin:" + challenge.Token, bytes, ttl).Err()
	SaveChallenge(ctx context.Context, challenge *ChallengeRecord) error

	// GetChallenge retrieves an active sign-in challenge token record.
	//
	// Function:
	//   Called during VerifyChallenge to validate challenge validity and expiration.
	//
	// Storage:
	//   Cache (Redis / In-Memory TTL) - Ephemeral sign-in challenge lookup.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - token: The challenge token string.
	//
	// Returns:
	//   - *ChallengeRecord: The matching challenge record.
	//   - error: ErrInvalidChallengeToken if missing, ErrChallengeExpired if past expiration, or database error.
	//
	// Example SQL:
	//   SELECT token, user_id, expires_at, created_at
	//   FROM two_factor_challenges WHERE token = $1 LIMIT 1;
	//
	// Example Cache (Redis):
	//   val, err := rdb.Get(ctx, "2fa:signin:" + token).Bytes()
	GetChallenge(ctx context.Context, token string) (*ChallengeRecord, error)

	// DeleteChallenge removes a consumed or expired sign-in challenge.
	//
	// Function:
	//   Called upon successful challenge verification or explicit cancellation.
	//
	// Storage:
	//   Cache (Redis / In-Memory TTL) - Challenge token eviction.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - token: The challenge token string to delete.
	//
	// Returns:
	//   - error: Nil on success, or database error on failure.
	//
	// Example SQL:
	//   DELETE FROM two_factor_challenges WHERE token = $1;
	//
	// Example Cache (Redis):
	//   err := rdb.Del(ctx, "2fa:signin:" + token).Err()
	DeleteChallenge(ctx context.Context, token string) error
}
