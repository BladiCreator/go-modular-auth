package username

import (
	"context"
	"regexp"
	"strings"
)

// Default username regex pattern: alphanumeric, underscores, and dots.
var defaultUsernameRegex = regexp.MustCompile(`^[a-zA-Z0-9_.]+$`)

// CustomValidatorFunc defines a custom validation function signature for username validation.
type CustomValidatorFunc func(ctx context.Context, username string) error

// NormalizationFunc defines a function signature for normalizing username input.
type NormalizationFunc func(username string) string

// Config holds all configuration parameters for the Username plugin.
type Config struct {
	// MinLength specifies the minimum allowed username length (default: 3).
	MinLength int

	// MaxLength specifies the maximum allowed username length (default: 30).
	MaxLength int

	// RegexValidator is the compiled regular expression used to validate format (default: ^[a-zA-Z0-9_.]+$).
	RegexValidator *regexp.Regexp

	// CustomValidator is an optional user-defined function for advanced username validation (e.g. reserved word check).
	CustomValidator CustomValidatorFunc

	// EnableNormalization determines whether username strings are automatically normalized (default: true).
	EnableNormalization bool

	// NormalizeFunc defines the normalization routine applied to usernames (default: strings.ToLower).
	NormalizeFunc NormalizationFunc

	// RequireEmailVerification enforces that user emails must be verified before username sign-in (default: false).
	RequireEmailVerification bool
}

// DefaultConfig returns the default configuration settings for the Username plugin.
func DefaultConfig() Config {
	return Config{
		MinLength:                3,
		MaxLength:                30,
		RegexValidator:           defaultUsernameRegex,
		EnableNormalization:      true,
		NormalizeFunc:            strings.ToLower,
		RequireEmailVerification: false,
	}
}

// Option defines a functional option signature for configuring the Username plugin.
type Option func(*Config)

// WithMinLength sets the minimum allowed username length.
func WithMinLength(minLen int) Option {
	return func(c *Config) {
		if minLen > 0 {
			c.MinLength = minLen
		}
	}
}

// WithMaxLength sets the maximum allowed username length.
func WithMaxLength(maxLen int) Option {
	return func(c *Config) {
		if maxLen > 0 {
			c.MaxLength = maxLen
		}
	}
}

// WithUsernameValidator sets a custom regex pattern string for format validation.
func WithUsernameValidator(pattern string) Option {
	return func(c *Config) {
		if compiled, err := regexp.Compile(pattern); err == nil {
			c.RegexValidator = compiled
		}
	}
}

// WithCustomValidator attaches an asynchronous custom validator callback.
func WithCustomValidator(fn CustomValidatorFunc) Option {
	return func(c *Config) {
		c.CustomValidator = fn
	}
}

// WithNormalization enables or disables automatic username normalization.
func WithNormalization(enable bool) Option {
	return func(c *Config) {
		c.EnableNormalization = enable
	}
}

// WithNormalizationFunc sets a custom normalization routine (e.g. lowercasing / trimming).
func WithNormalizationFunc(fn NormalizationFunc) Option {
	return func(c *Config) {
		if fn != nil {
			c.NormalizeFunc = fn
		}
	}
}

// WithRequireEmailVerification configures whether email verification is required prior to sign-in.
func WithRequireEmailVerification(require bool) Option {
	return func(c *Config) {
		c.RequireEmailVerification = require
	}
}
