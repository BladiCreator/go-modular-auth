package deviceauth

import (
	"context"
	"time"
)

// Config holds all configuration settings for the Device Authorization plugin.
type Config struct {
	// ExpiresIn specifies the lifetime duration of a device code grant (default: 30 minutes).
	ExpiresIn time.Duration

	// Interval specifies the minimum polling interval expected between token requests (default: 5 seconds).
	Interval time.Duration

	// DeviceCodeLength specifies the random character length for generated device codes (default: 40).
	DeviceCodeLength int

	// UserCodeLength specifies the random character length for generated user codes (default: 8).
	UserCodeLength int

	// VerificationURI specifies the relative or absolute user verification path (default: "/device").
	VerificationURI string

	// CustomURI optionally specifies a custom base URI for completing verification URLs.
	CustomURI string

	// SessionExpiry specifies the default duration of sessions created upon token exchange (default: 24 hours).
	SessionExpiry time.Duration

	// GenerateDeviceCode allows overriding the default device code generator.
	GenerateDeviceCode func(length int) (string, error)

	// GenerateUserCode allows overriding the default user code generator.
	GenerateUserCode func(length int) (string, error)

	// ValidateClient is an optional hook to validate client_id during device code authorization requests.
	ValidateClient func(ctx context.Context, clientID string) (bool, error)

	// OnDeviceAuthRequest is an optional hook executed during device code authorization requests.
	OnDeviceAuthRequest func(ctx context.Context, clientID string, scope *string) error
}

// DefaultConfig returns a Config struct pre-populated with standard RFC 8628 defaults.
func DefaultConfig() Config {
	return Config{
		ExpiresIn:        30 * time.Minute,
		Interval:         5 * time.Second,
		DeviceCodeLength: 40,
		UserCodeLength:   8,
		VerificationURI:  "/device",
		SessionExpiry:    24 * time.Hour,
	}
}

// Option represents a functional option for configuring the Device Authorization plugin.
type Option func(*Config)

// WithExpiresIn sets the expiration duration of issued device code grants.
func WithExpiresIn(d time.Duration) Option {
	return func(c *Config) {
		if d > 0 {
			c.ExpiresIn = d
		}
	}
}

// WithInterval sets the minimum polling interval requirement.
func WithInterval(d time.Duration) Option {
	return func(c *Config) {
		if d > 0 {
			c.Interval = d
		}
	}
}

// WithDeviceCodeLength sets the character length of generated device codes.
func WithDeviceCodeLength(length int) Option {
	return func(c *Config) {
		if length > 0 {
			c.DeviceCodeLength = length
		}
	}
}

// WithUserCodeLength sets the character length of generated user verification codes.
func WithUserCodeLength(length int) Option {
	return func(c *Config) {
		if length > 0 {
			c.UserCodeLength = length
		}
	}
}

// WithVerificationURI sets the base verification URI returned in device code responses.
func WithVerificationURI(uri string) Option {
	return func(c *Config) {
		if uri != "" {
			c.VerificationURI = uri
		}
	}
}

// WithCustomURI sets a custom domain/host URI used for completing verification URLs.
func WithCustomURI(uri string) Option {
	return func(c *Config) {
		c.CustomURI = uri
	}
}

// WithSessionExpiry sets the duration of sessions generated when exchanging an approved device code.
func WithSessionExpiry(d time.Duration) Option {
	return func(c *Config) {
		if d > 0 {
			c.SessionExpiry = d
		}
	}
}

// WithGenerateDeviceCode overrides the default cryptographic device code generator function.
func WithGenerateDeviceCode(fn func(length int) (string, error)) Option {
	return func(c *Config) {
		if fn != nil {
			c.GenerateDeviceCode = fn
		}
	}
}

// WithGenerateUserCode overrides the default cryptographic user code generator function.
func WithGenerateUserCode(fn func(length int) (string, error)) Option {
	return func(c *Config) {
		if fn != nil {
			c.GenerateUserCode = fn
		}
	}
}

// WithValidateClient registers a callback to validate client_id strings.
func WithValidateClient(fn func(ctx context.Context, clientID string) (bool, error)) Option {
	return func(c *Config) {
		c.ValidateClient = fn
	}
}

// WithOnDeviceAuthRequest registers a hook executed when a device code is requested.
func WithOnDeviceAuthRequest(fn func(ctx context.Context, clientID string, scope *string) error) Option {
	return func(c *Config) {
		c.OnDeviceAuthRequest = fn
	}
}
