package emailpassword

import "time"

// Config defines the configurable options for the EmailPassword plugin.
type Config struct {
	MinPasswordLength        int
	RequireEmailVerification bool
	ResetTokenExpiry         time.Duration
}

// defaultConfig returns safe default configuration values.
func defaultConfig() Config {
	return Config{
		MinPasswordLength:        8,
		RequireEmailVerification: false,
		ResetTokenExpiry:         15 * time.Minute,
	}
}

// Option defines a functional option for configuring the EmailPassword plugin.
type Option func(*Config)

// WithMinPasswordLength sets the minimum required password length.
func WithMinPasswordLength(length int) Option {
	return func(c *Config) {
		if length > 0 {
			c.MinPasswordLength = length
		}
	}
}

// WithRequireEmailVerification defines whether email verification is required before sign-in.
func WithRequireEmailVerification(require bool) Option {
	return func(c *Config) {
		c.RequireEmailVerification = require
	}
}

// WithResetTokenExpiry sets the validity duration for password reset tokens.
func WithResetTokenExpiry(d time.Duration) Option {
	return func(c *Config) {
		if d > 0 {
			c.ResetTokenExpiry = d
		}
	}
}