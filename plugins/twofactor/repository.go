package twofactor

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrTwoFactorNotEnabled is returned when 2FA operations are attempted for a user without active 2FA configuration.
	ErrTwoFactorNotEnabled = errors.New("twofactor: two-factor authentication is not enabled for this user")

	// ErrTwoFactorAlreadyOn is returned when attempting to enable 2FA on an account that already has verified 2FA active.
	ErrTwoFactorAlreadyOn = errors.New("twofactor: two-factor authentication is already enabled")

	// ErrInvalidCode is returned when a provided TOTP or backup code is invalid or does not match stored credentials.
	ErrInvalidCode = errors.New("twofactor: invalid verification code")

	// ErrAccountLocked is returned when 2FA verification is temporarily locked due to excessive failed attempts.
	ErrAccountLocked = errors.New("twofactor: two-factor authentication is temporarily locked due to excessive failed attempts")

	// ErrOTPNotConfigured is returned when attempting to send an OTP challenge without a registered SendOTP delivery callback.
	ErrOTPNotConfigured = errors.New("twofactor: send OTP callback is not configured")

	// ErrOTPExpired is returned when attempting to verify an OTP challenge that has expired or does not exist.
	ErrOTPExpired = errors.New("twofactor: OTP challenge has expired or does not exist")

	// ErrTooManyAttempts is returned when the maximum number of failed attempts on an active OTP challenge has been exceeded.
	ErrTooManyAttempts = errors.New("twofactor: maximum OTP attempt limit reached")

	// ErrPasswordRequired is returned when an operation strictly requires password confirmation before proceeding.
	ErrPasswordRequired = errors.New("twofactor: password is required for this operation")
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

// Repository defines the persistent storage contract required by the TwoFactor plugin.
// Implement this interface on your custom database adapter (e.g. PostgreSQL, MySQL, MongoDB, GORM).
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
type Repository interface {
	// FindByUserID retrieves the 2FA configuration record for a given user ID.
	//
	// Function:
	//   Used during TOTP validation, backup code verification, and viewing active backup codes.
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
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - challenge: The OTPChallenge entity to persist or update.
	//
	// Returns:
	//   - error: Nil on success, or database error on failure.
	//
	// Example SQL / Redis:
	//   INSERT INTO otp_challenges (key, user_id, code_hash, attempts, expires_at)
	//   VALUES ($1, $2, $3, $4, $5) ON CONFLICT (key) DO UPDATE SET attempts = $4;
	SaveOTPChallenge(ctx context.Context, challenge *OTPChallenge) error

	// GetOTPChallenge retrieves an active challenge by its composite key.
	//
	// Function:
	//   Called during VerifyOTP to compare the user's submitted challenge code and verify expiration.
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
	GetOTPChallenge(ctx context.Context, key string) (*OTPChallenge, error)

	// DeleteOTPChallenge deletes a consumed or expired OTP challenge.
	//
	// Function:
	//   Called upon successful verification (single-use consumption) or when maximum attempts are exceeded.
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
	DeleteOTPChallenge(ctx context.Context, key string) error
}
