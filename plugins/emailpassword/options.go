package emailpassword

import (
	"context"
	"time"
)

// SendEmailFunc defines the callback signature used to dispatch transactional emails (e.g. password resets or verification).
type SendEmailFunc func(ctx context.Context, email string, token string, expiresAt time.Time, extra map[string]any) error

// Config defines the configurable options and callbacks for the EmailPassword plugin.
type Config struct {
	// MinPasswordLength specifies the minimum acceptable length for user passwords (default: 8).
	MinPasswordLength int

	// MaxPasswordLength specifies the maximum acceptable length for user passwords (default: 128).
	MaxPasswordLength int

	// RequireEmailVerification enforces that user.EmailVerified must be true before sign-in succeeds (default: false).
	RequireEmailVerification bool

	// SendVerificationOnSignUp automatically generates and dispatches an email verification token upon registration (default: false).
	SendVerificationOnSignUp bool

	// ResetTokenExpiry specifies the duration for which password reset tokens remain valid (default: 15 minutes).
	ResetTokenExpiry time.Duration

	// VerificationTokenExpiry specifies the duration for which email verification tokens remain valid (default: 24 hours).
	VerificationTokenExpiry time.Duration

	// SendResetPasswordEmail is an optional callback invoked when a password reset token is requested.
	SendResetPasswordEmail SendEmailFunc

	// SendVerificationEmail is an optional callback invoked when an email verification token is requested.
	SendVerificationEmail SendEmailFunc
}

// DefaultConfig returns the safe production default configuration values for the EmailPassword plugin.
func DefaultConfig() Config {
	return Config{
		MinPasswordLength:        8,
		MaxPasswordLength:        128,
		RequireEmailVerification: false,
		SendVerificationOnSignUp: false,
		ResetTokenExpiry:         15 * time.Minute,
		VerificationTokenExpiry:  24 * time.Hour,
		SendResetPasswordEmail:   nil,
		SendVerificationEmail:    nil,
	}
}

// Option defines a functional option for configuring the EmailPassword plugin.
type Option func(*Config)

// WithMinPasswordLength sets the minimum required password length during registration and password change operations.
func WithMinPasswordLength(length int) Option {
	return func(c *Config) {
		if length > 0 {
			c.MinPasswordLength = length
		}
	}
}

// WithMaxPasswordLength sets the maximum allowed password length.
func WithMaxPasswordLength(length int) Option {
	return func(c *Config) {
		if length > 0 {
			c.MaxPasswordLength = length
		}
	}
}

// WithRequireEmailVerification defines whether email verification is strictly required before sign-in succeeds.
func WithRequireEmailVerification(require bool) Option {
	return func(c *Config) {
		c.RequireEmailVerification = require
	}
}

// WithSendVerificationOnSignUp configures whether to automatically send a verification email upon user registration.
func WithSendVerificationOnSignUp(send bool) Option {
	return func(c *Config) {
		c.SendVerificationOnSignUp = send
	}
}

// WithResetTokenExpiry sets the validity duration for generated password reset tokens.
func WithResetTokenExpiry(d time.Duration) Option {
	return func(c *Config) {
		if d > 0 {
			c.ResetTokenExpiry = d
		}
	}
}

// WithVerificationTokenExpiry sets the validity duration for generated email verification tokens.
func WithVerificationTokenExpiry(d time.Duration) Option {
	return func(c *Config) {
		if d > 0 {
			c.VerificationTokenExpiry = d
		}
	}
}

// WithSendResetPasswordEmail registers an email delivery callback invoked during password reset requests.
func WithSendResetPasswordEmail(fn SendEmailFunc) Option {
	return func(c *Config) {
		c.SendResetPasswordEmail = fn
	}
}

// WithSendVerificationEmail registers an email delivery callback invoked during email verification requests.
func WithSendVerificationEmail(fn SendEmailFunc) Option {
	return func(c *Config) {
		c.SendVerificationEmail = fn
	}
}
