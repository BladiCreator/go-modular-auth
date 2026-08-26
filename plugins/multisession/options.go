package multisession

import "context"

// SessionActivatedCallback is invoked whenever a device session is set active.
type SessionActivatedCallback func(ctx context.Context, res *SetActiveSessionResult) error

// SessionRevokedCallback is invoked whenever a device session is revoked.
type SessionRevokedCallback func(ctx context.Context, res *RevokeDeviceSessionResult) error

// Config defines the configuration parameters for the MultiSession plugin.
type Config struct {
	// MaximumSessions specifies the maximum number of active concurrent multi-sessions allowed on a single device.
	// Default: 5
	MaximumSessions int

	// CookiePrefix defines the prefix for multi-session cookies.
	// Default: "better-auth"
	CookiePrefix string

	// Secret is the HMAC SHA-256 secret key used for signing and verifying multi-session cookies.
	Secret string

	// OnSessionActivated is an optional callback triggered after a session is set active.
	OnSessionActivated SessionActivatedCallback

	// OnSessionRevoked is an optional callback triggered after a session is revoked.
	OnSessionRevoked SessionRevokedCallback
}

// DefaultConfig returns a Config struct initialized with recommended default values.
func DefaultConfig() Config {
	return Config{
		MaximumSessions: 5,
		CookiePrefix:    "better-auth",
		Secret:          "",
	}
}

// Option defines a functional option type for configuring the plugin.
type Option func(*Config)

// WithMaximumSessions configures the maximum session limit per device.
func WithMaximumSessions(max int) Option {
	return func(c *Config) {
		if max > 0 {
			c.MaximumSessions = max
		}
	}
}

// WithCookiePrefix configures the custom prefix used for multi-session cookies.
func WithCookiePrefix(prefix string) Option {
	return func(c *Config) {
		if prefix != "" {
			c.CookiePrefix = prefix
		}
	}
}

// WithSecret configures the cryptographic secret key used for HMAC cookie signature verification.
func WithSecret(secret string) Option {
	return func(c *Config) {
		c.Secret = secret
	}
}

// WithOnSessionActivated sets an optional callback executed after a session is set active.
func WithOnSessionActivated(fn SessionActivatedCallback) Option {
	return func(c *Config) {
		c.OnSessionActivated = fn
	}
}

// WithOnSessionRevoked sets an optional callback executed after a session is revoked.
func WithOnSessionRevoked(fn SessionRevokedCallback) Option {
	return func(c *Config) {
		c.OnSessionRevoked = fn
	}
}
