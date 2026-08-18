package phonenumber

import (
	"context"
	"fmt"
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/entity"
)

// SendOTPData contains the parameters delivered to the transactional SMS delivery callback.
type SendOTPData struct {
	// PhoneNumber is the destination recipient phone number.
	PhoneNumber string `json:"phone_number"`

	// Code is the raw numeric OTP verification code to deliver.
	Code string `json:"code"`

	// Type indicates the specific operation requiring verification ("phone-verification", "phone-password-reset").
	Type OTPType `json:"type"`

	// Extra holds dynamic metadata passed through event interceptors.
	Extra map[string]any `json:"extra,omitempty"`
}

// VerifyOTPData contains the parameters passed to the custom verification callback.
type VerifyOTPData struct {
	// PhoneNumber is the destination recipient phone number.
	PhoneNumber string `json:"phone_number"`

	// Code is the verification code submitted by the user.
	Code string `json:"code"`

	// Extra holds dynamic metadata passed through event interceptors.
	Extra map[string]any `json:"extra,omitempty"`
}

// OnVerificationData contains the context delivered to the post-verification callback.
type OnVerificationData struct {
	// PhoneNumber is the verified phone number.
	PhoneNumber string `json:"phone_number"`

	// User is the updated or newly created user entity.
	User *entity.User `json:"user"`

	// Extra holds dynamic metadata passed through event interceptors.
	Extra map[string]any `json:"extra,omitempty"`
}

// SignUpOnVerificationConfig configures automatic user creation upon phone verification.
type SignUpOnVerificationConfig struct {
	// GetTempEmail resolves a fallback email for auto-created users given their phone number.
	GetTempEmail func(phoneNumber string) string

	// GetTempName resolves a fallback display name for auto-created users given their phone number.
	GetTempName func(phoneNumber string) string
}

// Callback and hook function types
type (
	// SendOTPFunc defines the callback function invoked to dispatch an SMS OTP.
	SendOTPFunc func(ctx context.Context, data SendOTPData) error

	// VerifyOTPFunc defines an optional external OTP verification callback (e.g. Twilio Verify).
	VerifyOTPFunc func(ctx context.Context, data VerifyOTPData) (bool, error)

	// PhoneNumberValidatorFunc defines custom phone number validation (e.g. E.164 format verification).
	PhoneNumberValidatorFunc func(ctx context.Context, phoneNumber string) (bool, error)

	// CallbackOnVerificationFunc defines a hook executed after a phone number is successfully verified.
	CallbackOnVerificationFunc func(ctx context.Context, data OnVerificationData) error

	// OnPasswordResetFunc defines a hook executed after a password reset is confirmed.
	OnPasswordResetFunc func(ctx context.Context, user *entity.User) error

	// GenerateOTPFunc allows overriding the default random numeric code generation routine.
	GenerateOTPFunc func(ctx context.Context, phoneNumber string, otpType OTPType) (string, error)
)

// Config structures all configuration options for the Phone Number plugin.
type Config struct {
	// SendOTP is the required SMS delivery callback.
	SendOTP SendOTPFunc

	// VerifyOTP is an optional delegated verification callback.
	VerifyOTP VerifyOTPFunc

	// SendPasswordResetOTP is an optional dedicated callback for password reset SMS OTPs.
	SendPasswordResetOTP SendOTPFunc

	// PhoneNumberValidator is an optional callback to validate phone number format.
	PhoneNumberValidator PhoneNumberValidatorFunc

	// CallbackOnVerification is an optional callback executed upon successful phone verification.
	CallbackOnVerification CallbackOnVerificationFunc

	// OnPasswordReset is an optional callback executed upon password reset confirmation.
	OnPasswordReset OnPasswordResetFunc

	// SignUpOnVerification configures temporary credentials for auto-created users.
	SignUpOnVerification *SignUpOnVerificationConfig

	// GenerateOTP is an optional custom OTP generator function.
	GenerateOTP GenerateOTPFunc

	// OTPLength is the number of digits in generated numeric OTPs (default: 6).
	OTPLength int

	// ExpiresIn is the duration after which an unverified OTP expires (default: 5 minutes).
	ExpiresIn time.Duration

	// AllowedAttempts is the maximum number of failed verification tries permitted before invalidating the code (default: 3).
	AllowedAttempts int

	// RequireVerification enforces that the phone number must already be verified before allowing password-based sign-in.
	RequireVerification bool

	// DisableSignUp prevents creating a new user if an account does not exist during phone verification.
	DisableSignUp bool

	// RevokeSessionsOnPasswordReset invalidates all active user sessions after a successful password reset (default: true).
	RevokeSessionsOnPasswordReset bool

	// MinPasswordLength is the minimum password length enforced during password resets (default: 8).
	MinPasswordLength int

	// MaxPasswordLength is the maximum password length enforced during password resets (default: 128).
	MaxPasswordLength int

	// StoreOTPMode defines how the OTP is persisted ("plain", "hashed", "encrypted", default: "plain").
	StoreOTPMode StoreOTPMode

	// SecretKey is the symmetric key used when StoreOTPMode is "encrypted".
	SecretKey string

	// ResendStrategy specifies behavior on resend requests ("rotate" or "reuse", default: "rotate").
	ResendStrategy ResendStrategy

	// CustomHasher is an optional custom Hasher implementation for "hashed" mode.
	CustomHasher Hasher

	// CustomCipher is an optional custom Cipher implementation for "encrypted" mode.
	CustomCipher Cipher
}

// DefaultConfig returns recommended production default settings for the Phone Number plugin.
func DefaultConfig() Config {
	return Config{
		OTPLength:                     6,
		ExpiresIn:                     5 * time.Minute,
		AllowedAttempts:               3,
		RequireVerification:           false,
		DisableSignUp:                 false,
		RevokeSessionsOnPasswordReset: true,
		MinPasswordLength:             8,
		MaxPasswordLength:             128,
		StoreOTPMode:                  StoreOTPPlain,
		ResendStrategy:                ResendStrategyRotate,
		CustomHasher:                  DefaultSHA256Hasher{},
	}
}

// Option represents a configuration modifier function.
type Option func(*Config)

// WithSendOTP configures the SMS delivery callback function.
func WithSendOTP(fn SendOTPFunc) Option {
	return func(c *Config) {
		c.SendOTP = fn
	}
}

// WithVerifyOTP configures an optional delegated verification callback (e.g. Twilio Verify API).
func WithVerifyOTP(fn VerifyOTPFunc) Option {
	return func(c *Config) {
		c.VerifyOTP = fn
	}
}

// WithSendPasswordResetOTP configures a dedicated SMS delivery callback for password resets.
func WithSendPasswordResetOTP(fn SendOTPFunc) Option {
	return func(c *Config) {
		c.SendPasswordResetOTP = fn
	}
}

// WithOTPLength configures the number of digits in generated numeric OTPs.
func WithOTPLength(length int) Option {
	return func(c *Config) {
		if length > 0 {
			c.OTPLength = length
		}
	}
}

// WithExpiresIn configures the lifespan of generated OTPs.
func WithExpiresIn(d time.Duration) Option {
	return func(c *Config) {
		if d > 0 {
			c.ExpiresIn = d
		}
	}
}

// WithAllowedAttempts sets the maximum number of failed verification tries allowed on an active OTP before locking out.
func WithAllowedAttempts(attempts int) Option {
	return func(c *Config) {
		if attempts > 0 {
			c.AllowedAttempts = attempts
		}
	}
}

// WithRequireVerification enforces that phone numbers must be verified before allowing phone + password sign-in.
func WithRequireVerification(require bool) Option {
	return func(c *Config) {
		c.RequireVerification = require
	}
}

// WithDisableSignUp disables automatic user provisioning when verifying an unregistered phone number.
func WithDisableSignUp(disable bool) Option {
	return func(c *Config) {
		c.DisableSignUp = disable
	}
}

// WithStoreOTP configures the persistence strategy and optional secret key for encrypted mode.
func WithStoreOTP(mode StoreOTPMode, secretKey ...string) Option {
	return func(c *Config) {
		c.StoreOTPMode = mode
		if len(secretKey) > 0 {
			c.SecretKey = secretKey[0]
		}
	}
}

// WithResendStrategy configures the behavior when a user requests an OTP while an active one exists.
func WithResendStrategy(strategy ResendStrategy) Option {
	return func(c *Config) {
		c.ResendStrategy = strategy
	}
}

// WithPhoneNumberValidator sets a custom validator function for phone number formats.
func WithPhoneNumberValidator(fn PhoneNumberValidatorFunc) Option {
	return func(c *Config) {
		c.PhoneNumberValidator = fn
	}
}

// WithCallbackOnVerification registers a hook to be called after a phone number is verified.
func WithCallbackOnVerification(fn CallbackOnVerificationFunc) Option {
	return func(c *Config) {
		c.CallbackOnVerification = fn
	}
}

// WithSignUpOnVerification configures temporary naming and email resolution for auto-registered users.
func WithSignUpOnVerification(cfg SignUpOnVerificationConfig) Option {
	return func(c *Config) {
		if cfg.GetTempName == nil {
			cfg.GetTempName = func(phone string) string { return phone }
		}
		if cfg.GetTempEmail == nil {
			cfg.GetTempEmail = func(phone string) string { return fmt.Sprintf("%s@phone.local", phone) }
		}
		c.SignUpOnVerification = &cfg
	}
}

// WithOnPasswordReset sets a callback hook executed upon successful password reset.
func WithOnPasswordReset(fn OnPasswordResetFunc) Option {
	return func(c *Config) {
		c.OnPasswordReset = fn
	}
}

// WithRevokeSessionsOnPasswordReset configures whether to revoke all active sessions on password reset.
func WithRevokeSessionsOnPasswordReset(revoke bool) Option {
	return func(c *Config) {
		c.RevokeSessionsOnPasswordReset = revoke
	}
}

// WithMinPasswordLength configures the minimum required password length.
func WithMinPasswordLength(minLen int) Option {
	return func(c *Config) {
		if minLen > 0 {
			c.MinPasswordLength = minLen
		}
	}
}

// WithMaxPasswordLength configures the maximum allowed password length.
func WithMaxPasswordLength(maxLen int) Option {
	return func(c *Config) {
		if maxLen > 0 {
			c.MaxPasswordLength = maxLen
		}
	}
}

// WithPasswordPolicy sets password length constraints and session revocation behavior upon password reset.
func WithPasswordPolicy(minLen, maxLen int, revokeOnReset bool) Option {
	return func(c *Config) {
		if minLen > 0 {
			c.MinPasswordLength = minLen
		}
		if maxLen >= minLen {
			c.MaxPasswordLength = maxLen
		}
		c.RevokeSessionsOnPasswordReset = revokeOnReset
	}
}

// WithCustomHasher registers a custom Hasher for StoreOTPHashed mode.
func WithCustomHasher(hasher Hasher) Option {
	return func(c *Config) {
		c.CustomHasher = hasher
	}
}

// WithCustomCipher registers a custom Cipher for StoreOTPEncrypted mode.
func WithCustomCipher(cipher Cipher) Option {
	return func(c *Config) {
		c.CustomCipher = cipher
	}
}

// WithGenerateOTP registers a custom OTP code generation routine.
func WithGenerateOTP(fn GenerateOTPFunc) Option {
	return func(c *Config) {
		c.GenerateOTP = fn
	}
}
