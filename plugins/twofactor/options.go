package twofactor

import (
	"context"
	"time"
)

// SendOTPFunc defines the callback function signature for dispatching generated OTP challenge codes via SMS or Email.
type SendOTPFunc func(ctx context.Context, userID string, otp string) error

// AccountLockoutConfig defines rate-limiting brute force protection rules.
type AccountLockoutConfig struct {
	// Enabled indicates if failed verification attempts should lock the account.
	Enabled bool

	// MaxFailedAttempts specifies the maximum consecutive failed attempts before lockout triggers.
	MaxFailedAttempts int

	// Duration specifies how long 2FA operations remain locked out after exceeding max failed attempts.
	Duration time.Duration
}

// Config holds configuration parameters for the two-factor authentication plugin.
type Config struct {
	// Issuer specifies the application name embedded into the TOTP URI shown in authenticator apps (default: "GoModularAuth").
	Issuer string

	// Algorithm specifies the hashing algorithm for TOTP (AlgorithmSHA1, AlgorithmSHA256, AlgorithmSHA512).
	Algorithm TOTPAlgorithm

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

	// ChallengeExpiry defines the expiration duration for sign-in 2FA challenge tokens (default: 10 minutes).
	ChallengeExpiry time.Duration

	// TrustDeviceMaxAge defines the validity duration for authorized trusted devices (default: 30 days).
	TrustDeviceMaxAge time.Duration

	// TrustDeviceSecret is the HMAC secret used to cryptographically sign trusted device tokens.
	TrustDeviceSecret string

	// OTPDigits specifies the numeric length for challenge-based OTP codes (default: 6).
	OTPDigits int

	// OTPPeriod defines the expiration duration for temporary OTP challenges (default: 3 minutes).
	OTPPeriod time.Duration

	// Lockout holds configuration for account lockout rate limiting.
	Lockout AccountLockoutConfig

	// SendOTP registers the external delivery callback for SMS or Email OTP dispatches.
	SendOTP SendOTPFunc
}

// Option defines a functional option for configuring the TwoFactor plugin.
type Option func(*Config)

// DefaultConfig returns the default production configuration for the TwoFactor plugin.
func DefaultConfig() Config {
	return Config{
		Issuer:                   "GoModularAuth",
		Algorithm:                AlgorithmSHA1,
		TotpDigits:               6,
		TotpPeriod:               30,
		BackupCodeAmount:         10,
		BackupCodeLength:         10,
		AllowPasswordless:        false,
		SkipVerificationOnEnable: false,
		ChallengeExpiry:          10 * time.Minute,
		TrustDeviceMaxAge:        30 * 24 * time.Hour,
		TrustDeviceSecret:        "",
		OTPDigits:                6,
		OTPPeriod:                3 * time.Minute,
		Lockout: AccountLockoutConfig{
			Enabled:           true,
			MaxFailedAttempts: 5,
			Duration:          15 * time.Minute,
		},
		SendOTP: nil,
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

// WithAlgorithm sets the cryptographic hashing algorithm for TOTP calculations (SHA1, SHA256, SHA512).
func WithAlgorithm(alg TOTPAlgorithm) Option {
	return func(c *Config) {
		if alg != "" {
			c.Algorithm = alg
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

// WithChallengeExpiry sets the expiration duration for temporary sign-in 2FA challenge tokens.
func WithChallengeExpiry(d time.Duration) Option {
	return func(c *Config) {
		if d > 0 {
			c.ChallengeExpiry = d
		}
	}
}

// WithTrustDevice configures trusted device parameters, including the cryptographic HMAC secret and duration.
func WithTrustDevice(secret string, maxAge time.Duration) Option {
	return func(c *Config) {
		if secret != "" {
			c.TrustDeviceSecret = secret
		}
		if maxAge > 0 {
			c.TrustDeviceMaxAge = maxAge
		}
	}
}

// WithLockoutProtection configures the maximum allowed failed attempts before rate limiting locks the account,
// and the lockout penalty duration.
func WithLockoutProtection(maxAttempts int, duration time.Duration) Option {
	return func(c *Config) {
		c.Lockout.Enabled = true
		if maxAttempts > 0 {
			c.Lockout.MaxFailedAttempts = maxAttempts
		}
		if duration > 0 {
			c.Lockout.Duration = duration
		}
	}
}

// WithAccountLockout configures the full AccountLockout settings.
func WithAccountLockout(enabled bool, maxAttempts int, duration time.Duration) Option {
	return func(c *Config) {
		c.Lockout.Enabled = enabled
		if maxAttempts > 0 {
			c.Lockout.MaxFailedAttempts = maxAttempts
		}
		if duration > 0 {
			c.Lockout.Duration = duration
		}
	}
}

// WithSendOTP registers the delivery callback function used to dispatch temporary challenge OTP codes via SMS or Email.
func WithSendOTP(fn SendOTPFunc) Option {
	return func(c *Config) {
		c.SendOTP = fn
	}
}

// WithOTPOptions configures the number of digits and validity period for temporary challenge OTP codes.
func WithOTPOptions(digits int, period time.Duration) Option {
	return func(c *Config) {
		if digits > 0 {
			c.OTPDigits = digits
		}
		if period > 0 {
			c.OTPPeriod = period
		}
	}
}
