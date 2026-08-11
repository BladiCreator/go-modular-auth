// Package twofactor provides functional options, callbacks, and configuration settings for the TwoFactor plugin.
package twofactor

import (
	"context"
	"time"
)

// SendOTPFunc defines the callback function signature for dispatching generated OTP challenge codes via SMS or Email.
type SendOTPFunc func(ctx context.Context, userID string, otp string) error

// Config holds configuration parameters for the two-factor authentication plugin.
type Config struct {
	// Issuer specifies the application name embedded into the TOTP URI shown in authenticator apps (default: "GoModularAuth").
	Issuer string

	// TotpDigits specifies the number of digits in generated TOTP codes (6 or 8, default: 6).
	TotpDigits int

	// TotpPeriod specifies the rotation interval for TOTP codes in seconds (default: 30).
	TotpPeriod int

	// BackupCodeAmount defines the total number of single-use backup codes generated during enrollment (default: 10).
	BackupCodeAmount int

	// BackupCodeLength defines the character length of each generated backup code (default: 10).
	BackupCodeLength int

	// AllowPasswordless allows 2FA management operations without requiring prior password re-validation.
	AllowPasswordless bool

	// SkipVerificationOnEnable marks 2FA as immediately active upon enrollment without demanding a first verified TOTP code.
	SkipVerificationOnEnable bool

	// MaxAllowedAttempts defines the maximum failed attempts permitted before rate limiting lockout triggers (default: 5).
	MaxAllowedAttempts int

	// LockoutDuration defines the temporary lockout penalty after exceeding maximum failed attempts (default: 15 minutes).
	LockoutDuration time.Duration

	// OTPDigits specifies the numeric length for challenge-based OTP codes (default: 6).
	OTPDigits int

	// OTPPeriod defines the expiration duration for temporary OTP challenges (default: 3 minutes).
	OTPPeriod time.Duration

	// SendOTP registers the external delivery callback for SMS or Email OTP dispatches.
	SendOTP SendOTPFunc
}

// Option defines a functional option for configuring the TwoFactor plugin.
type Option func(*Config)

// DefaultConfig returns the default production configuration for the TwoFactor plugin.
func DefaultConfig() Config {
	return Config{
		Issuer:                   "GoModularAuth",
		TotpDigits:               6,
		TotpPeriod:               30,
		BackupCodeAmount:         10,
		BackupCodeLength:         10,
		AllowPasswordless:        false,
		SkipVerificationOnEnable: false,
		MaxAllowedAttempts:       5,
		LockoutDuration:          15 * time.Minute,
		OTPDigits:                6,
		OTPPeriod:                3 * time.Minute,
		SendOTP:                  nil,
	}
}

// WithIssuer sets the issuer name displayed in authenticator applications (e.g. "My Company ERP").
func WithIssuer(issuer string) Option {
	return func(c *Config) {
		if issuer != "" {
			c.Issuer = issuer
		}
	}
}

// WithTOTPOptions configures the number of digits (6 or 8) and rotation period in seconds for RFC 6238 TOTP codes.
func WithTOTPOptions(digits int, period int) Option {
	return func(c *Config) {
		if digits == 6 || digits == 8 {
			c.TotpDigits = digits
		}
		if period > 0 {
			c.TotpPeriod = period
		}
	}
}

// WithBackupCodeOptions sets the quantity and character length of single-use backup codes generated during 2FA setup.
func WithBackupCodeOptions(amount, length int) Option {
	return func(c *Config) {
		if amount > 0 {
			c.BackupCodeAmount = amount
		}
		if length > 0 {
			c.BackupCodeLength = length
		}
	}
}

// WithAllowPasswordless allows 2FA operations without requiring prior user password verification.
func WithAllowPasswordless(allow bool) Option {
	return func(c *Config) {
		c.AllowPasswordless = allow
	}
}

// WithSkipVerificationOnEnable marks 2FA as actively enforced immediately upon secret generation.
func WithSkipVerificationOnEnable(skip bool) Option {
	return func(c *Config) {
		c.SkipVerificationOnEnable = skip
	}
}

// WithLockoutProtection configures the maximum allowed failed attempts before rate limiting locks the account,
// and the lockout penalty duration.
func WithLockoutProtection(maxAttempts int, duration time.Duration) Option {
	return func(c *Config) {
		if maxAttempts > 0 {
			c.MaxAllowedAttempts = maxAttempts
		}
		if duration > 0 {
			c.LockoutDuration = duration
		}
	}
}

// WithSendOTP registers the delivery callback function used to dispatch temporary challenge OTP codes via SMS or Email.
func WithSendOTP(fn SendOTPFunc) Option {
	return func(c *Config) {
		c.SendOTP = fn
	}
}
