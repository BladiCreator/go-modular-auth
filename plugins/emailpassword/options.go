// Package emailpassword provides functional options and configuration settings for the EmailPassword plugin.
package emailpassword

import "time"

// Config defines the configurable options for the EmailPassword plugin.
type Config struct {
	// MinPasswordLength specifies the minimum acceptable length for user passwords (default: 8).
	MinPasswordLength int

	// RequireEmailVerification enforces that user.EmailVerified must be true before sign-in succeeds (default: false).
	RequireEmailVerification bool

	// ResetTokenExpiry specifies the duration for which password reset tokens remain valid (default: 15 minutes).
	ResetTokenExpiry time.Duration
}

// defaultConfig returns the safe production default configuration values for the EmailPassword plugin.
func defaultConfig() Config {
	return Config{
		MinPasswordLength:        8,
		RequireEmailVerification: false,
		ResetTokenExpiry:         15 * time.Minute,
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

// WithRequireEmailVerification defines whether email verification is strictly required before sign-in succeeds.
func WithRequireEmailVerification(require bool) Option {
	return func(c *Config) {
		c.RequireEmailVerification = require
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
