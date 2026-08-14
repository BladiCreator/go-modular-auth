package emailotp

import (
	"context"
	"time"
)

// SendVerificationOTPFunc defines the callback function invoked when dispatching an OTP to a recipient email.
type SendVerificationOTPFunc func(ctx context.Context, data SendEmailData) error

// SendEmailData contains the parameters delivered to the transactional email delivery callback.
type SendEmailData struct {
	// Email is the destination recipient email address.
	Email string `json:"email"`

	// OTP is the raw numeric OTP verification code to deliver.
	OTP string `json:"otp"`

	// Type indicates the specific operation requiring verification.
	Type OTPType `json:"type"`
}

// GenerateOTPFunc allows overriding the default random numeric code generation routine.
type GenerateOTPFunc func(ctx context.Context, email string, otpType OTPType) (string, error)

// ChangeEmailConfig configures the email change verification flow.
type ChangeEmailConfig struct {
	// Enabled toggles whether users are permitted to change their email via OTP.
	Enabled bool `json:"enabled"`

	// VerifyCurrentEmail enforces sending and verifying an OTP to the current email address before sending one to the new address.
	VerifyCurrentEmail bool `json:"verify_current_email"`
}

// RateLimitConfig configures sliding rate limits to protect OTP dispatching from spam abuse.
type RateLimitConfig struct {
	// Window specifies the duration of the rate-limiting window.
	Window time.Duration `json:"window"`

	// Max specifies the maximum allowed requests within the configured window.
	Max int `json:"max"`
}

// Config structures all configuration options for the Email OTP plugin.
type Config struct {
	// SendVerificationOTP is the required email delivery callback.
	SendVerificationOTP SendVerificationOTPFunc

	// OTPLength is the number of digits in generated numeric OTPs (default: 6).
	OTPLength int

	// ExpiresIn is the duration after which an unverified OTP expires (default: 5 minutes).
	ExpiresIn time.Duration

	// AllowedAttempts is the maximum number of failed verification tries permitted before invalidating the code (default: 3).
	AllowedAttempts int

	// StoreOTPMode defines how the OTP is persisted ("plain", "hashed", "encrypted", default: "plain").
	StoreOTPMode StoreOTPMode

	// SecretKey is the symmetric key used when StoreOTPMode is "encrypted".
	SecretKey string

	// CustomHasher is an optional custom Hasher implementation for "hashed" mode.
	CustomHasher Hasher

	// CustomCipher is an optional custom Cipher implementation for "encrypted" mode.
	CustomCipher Cipher

	// ResendStrategy specifies behavior on resend requests ("rotate" or "reuse", default: "rotate").
	ResendStrategy ResendStrategy

	// SendVerificationOnSignUp automatically sends an email verification OTP when a user registers.
	SendVerificationOnSignUp bool

	// DisableSignUp prevents creating a new user if an account does not exist during SignInEmailOTP.
	DisableSignUp bool

	// OverrideDefaultEmailVerification overrides default email verification behaviors.
	OverrideDefaultEmailVerification bool

	// AutoSignInAfterVerification automatically generates an authenticated session upon successful email verification (default: true).
	AutoSignInAfterVerification bool

	// RevokeSessionsOnPasswordReset invalidates all active user sessions after a successful password reset (default: true).
	RevokeSessionsOnPasswordReset bool

	// MinPasswordLength is the minimum password length enforced during password resets (default: 8).
	MinPasswordLength int

	// MaxPasswordLength is the maximum password length enforced during password resets (default: 128).
	MaxPasswordLength int

	// ChangeEmail holds email change flow configuration.
	ChangeEmail ChangeEmailConfig

	// RateLimit holds request throttling configuration.
	RateLimit RateLimitConfig

	// GenerateOTP is an optional custom OTP code generator.
	GenerateOTP GenerateOTPFunc
}

// DefaultConfig returns the recommended default configuration for Email OTP authentication.
func DefaultConfig() Config {
	return Config{
		SendVerificationOTP:              nil,
		OTPLength:                        6,
		ExpiresIn:                        5 * time.Minute,
		AllowedAttempts:                  3,
		StoreOTPMode:                     StoreOTPPlain,
		SecretKey:                        "",
		CustomHasher:                     DefaultSHA256Hasher{},
		CustomCipher:                     nil,
		ResendStrategy:                   ResendStrategyRotate,
		SendVerificationOnSignUp:         false,
		DisableSignUp:                    false,
		OverrideDefaultEmailVerification: false,
		AutoSignInAfterVerification:      true,
		RevokeSessionsOnPasswordReset:    true,
		MinPasswordLength:                8,
		MaxPasswordLength:                128,
		ChangeEmail: ChangeEmailConfig{
			Enabled:            false,
			VerifyCurrentEmail: false,
		},
		RateLimit: RateLimitConfig{
			Window: 1 * time.Minute,
			Max:    3,
		},
		GenerateOTP: nil,
	}
}

// Option represents a functional option to configure the Email OTP plugin.
type Option func(*Config)

// WithSendVerificationOTP configures the email delivery callback function.
func WithSendVerificationOTP(fn SendVerificationOTPFunc) Option {
	return func(c *Config) { c.SendVerificationOTP = fn }
}

// WithOTPLength sets the number of digits in generated numeric OTPs.
func WithOTPLength(length int) Option {
	return func(c *Config) {
		if length > 0 {
			c.OTPLength = length
		}
	}
}

// WithExpiresIn sets the duration for which an OTP remains valid.
func WithExpiresIn(d time.Duration) Option {
	return func(c *Config) {
		if d > 0 {
			c.ExpiresIn = d
		}
	}
}

// WithAllowedAttempts sets the maximum number of incorrect attempts before permanently consuming and invalidating the OTP.
func WithAllowedAttempts(attempts int) Option {
	return func(c *Config) {
		if attempts > 0 {
			c.AllowedAttempts = attempts
		}
	}
}

// WithStoreOTP configures the storage strategy for OTP codes ("plain", "hashed", or "encrypted").
func WithStoreOTP(mode StoreOTPMode, secretKey ...string) Option {
	return func(c *Config) {
		c.StoreOTPMode = mode
		if len(secretKey) > 0 && secretKey[0] != "" {
			c.SecretKey = secretKey[0]
		}
	}
}

// WithCustomHasher configures a custom Hasher for hashing OTPs.
func WithCustomHasher(h Hasher) Option {
	return func(c *Config) { c.CustomHasher = h }
}

// WithCustomCipher configures a custom Cipher for symmetric encryption of OTPs.
func WithCustomCipher(cipher Cipher) Option {
	return func(c *Config) { c.CustomCipher = cipher }
}

// WithResendStrategy configures whether to rotate codes or reuse unexpired active codes on resend.
func WithResendStrategy(strategy ResendStrategy) Option {
	return func(c *Config) { c.ResendStrategy = strategy }
}

// WithSendVerificationOnSignUp configures whether to automatically dispatch a verification OTP when a user signs up.
func WithSendVerificationOnSignUp(send bool) Option {
	return func(c *Config) { c.SendVerificationOnSignUp = send }
}

// WithDisableSignUp disables automatic user provisioning when verifying a sign-in OTP for an unknown email.
func WithDisableSignUp(disable bool) Option {
	return func(c *Config) { c.DisableSignUp = disable }
}

// WithOverrideDefaultEmailVerification overrides the framework default verification flow.
func WithOverrideDefaultEmailVerification(override bool) Option {
	return func(c *Config) { c.OverrideDefaultEmailVerification = override }
}

// WithAutoSignInAfterVerification configures whether to issue a session immediately upon successful email verification.
func WithAutoSignInAfterVerification(autoSignIn bool) Option {
	return func(c *Config) { c.AutoSignInAfterVerification = autoSignIn }
}

// WithRevokeSessionsOnPasswordReset configures whether all active sessions are revoked when resetting passwords via OTP.
func WithRevokeSessionsOnPasswordReset(revoke bool) Option {
	return func(c *Config) { c.RevokeSessionsOnPasswordReset = revoke }
}

// WithPasswordLength configures the minimum and maximum password length permitted during password resets.
func WithPasswordLength(minLen, maxLen int) Option {
	return func(c *Config) {
		if minLen > 0 {
			c.MinPasswordLength = minLen
		}
		if maxLen >= c.MinPasswordLength {
			c.MaxPasswordLength = maxLen
		}
	}
}

// WithChangeEmail configures whether email changes via OTP are enabled and whether the current email must be verified first.
func WithChangeEmail(enabled, verifyCurrent bool) Option {
	return func(c *Config) {
		c.ChangeEmail = ChangeEmailConfig{
			Enabled:            enabled,
			VerifyCurrentEmail: verifyCurrent,
		}
	}
}

// WithGenerateOTP provides a custom code generation callback.
func WithGenerateOTP(fn GenerateOTPFunc) Option {
	return func(c *Config) { c.GenerateOTP = fn }
}

// WithRateLimit configures rate limiting parameters for OTP dispatch requests.
func WithRateLimit(window time.Duration, max int) Option {
	return func(c *Config) {
		if window > 0 && max > 0 {
			c.RateLimit = RateLimitConfig{
				Window: window,
				Max:    max,
			}
		}
	}
}
