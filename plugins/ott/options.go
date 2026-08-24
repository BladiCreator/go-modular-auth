package ott

import (
	"time"
)

// StoreTokenMode defines how one-time tokens are persisted in storage ("plain" or "hashed").
type StoreTokenMode string

const (
	// StoreTokenPlain persists the token in raw plain text format.
	StoreTokenPlain StoreTokenMode = "plain"

	// StoreTokenHashed persists the token as a one-way SHA-256 base64url hash.
	StoreTokenHashed StoreTokenMode = "hashed"
)

// HasherFunc defines a custom function signature for hashing OTT tokens.
type HasherFunc func(token string) (string, error)

// TokenGeneratorFunc defines a custom function signature for generating random OTT token strings.
type TokenGeneratorFunc func(length int) (string, error)

// Config structures all operational settings for the One-Time Token (OTT) plugin.
type Config struct {
	// ExpiresIn specifies the validity duration for generated OTT tokens (default: 3 minutes).
	ExpiresIn time.Duration

	// DisableClientRequest when true rejects token generation requests originating directly from client-side HTTP callers.
	DisableClientRequest bool

	// DisableSetSessionCookie when true prevents setting the session HTTP cookie upon token verification.
	DisableSetSessionCookie bool

	// SetOttHeaderOnNewSession when true enables automatically attaching the set-ott header on new session creation.
	SetOttHeaderOnNewSession bool

	// StoreTokenMode defines token persistence security ("plain" or "hashed", default: "plain").
	StoreTokenMode StoreTokenMode

	// CustomHasher overrides the default SHA-256 base64url token hasher.
	CustomHasher HasherFunc

	// CustomGenerator overrides the default crypto/rand random token generator.
	CustomGenerator TokenGeneratorFunc
}

// DefaultConfig returns recommended default settings for the OTT plugin.
func DefaultConfig() Config {
	return Config{
		ExpiresIn:                3 * time.Minute,
		DisableClientRequest:     false,
		DisableSetSessionCookie:  false,
		SetOttHeaderOnNewSession: false,
		StoreTokenMode:           StoreTokenPlain,
	}
}

// Option configures functional options for the OTT plugin.
type Option func(*Config)

// WithExpiresIn sets the expiration duration for issued one-time tokens.
func WithExpiresIn(d time.Duration) Option {
	return func(c *Config) {
		if d > 0 {
			c.ExpiresIn = d
		}
	}
}

// WithDisableClientRequest configures whether to reject client-initiated token generation requests.
func WithDisableClientRequest(disable bool) Option {
	return func(c *Config) {
		c.DisableClientRequest = disable
	}
}

// WithDisableSetSessionCookie configures whether to disable setting session cookies upon verification.
func WithDisableSetSessionCookie(disable bool) Option {
	return func(c *Config) {
		c.DisableSetSessionCookie = disable
	}
}

// WithSetOttHeaderOnNewSession enables or disables automatic set-ott header emission on new session creation.
func WithSetOttHeaderOnNewSession(enable bool) Option {
	return func(c *Config) {
		c.SetOttHeaderOnNewSession = enable
	}
}

// WithStoreTokenMode configures token storage security mode ("plain" or "hashed").
func WithStoreTokenMode(mode StoreTokenMode) Option {
	return func(c *Config) {
		c.StoreTokenMode = mode
	}
}

// WithCustomHasher sets a custom token hashing function.
func WithCustomHasher(fn HasherFunc) Option {
	return func(c *Config) {
		c.CustomHasher = fn
	}
}

// WithCustomGenerator sets a custom token string generator function.
func WithCustomGenerator(fn TokenGeneratorFunc) Option {
	return func(c *Config) {
		c.CustomGenerator = fn
	}
}
