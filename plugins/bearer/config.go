package bearer

import (
	"time"
)

const (
	// DefaultCacheTTL is the duration cached token records remain valid in the cache adapter.
	DefaultCacheTTL = 5 * time.Minute

	// DefaultTokenPrefix is prepended to generated opaque tokens to facilitate identification.
	DefaultTokenPrefix = "gmb_"
)

// Config configures the bearer token authentication plugin.
type Config struct {
	// DefaultTTL specifies the default expiration duration for newly issued tokens.
	DefaultTTL time.Duration

	// CacheTTL specifies the maximum time-to-live for cached token records.
	CacheTTL time.Duration

	// TokenPrefix is prepended to generated tokens (e.g. "gmb_").
	TokenPrefix string

	// Hooks provides lifecycle interceptors for bearer operations.
	Hooks *Hooks
}

// Option configures a Config struct.
type Option func(*Config)

// WithDefaultTTL sets the default token expiration duration.
func WithDefaultTTL(d time.Duration) Option {
	return func(c *Config) {
		c.DefaultTTL = d
	}
}

// WithCacheTTL sets the cache entry time-to-live.
func WithCacheTTL(d time.Duration) Option {
	return func(c *Config) {
		c.CacheTTL = d
	}
}

// WithTokenPrefix sets the prefix for newly generated tokens.
func WithTokenPrefix(prefix string) Option {
	return func(c *Config) {
		c.TokenPrefix = prefix
	}
}

// WithHooks sets the lifecycle hooks for the plugin.
func WithHooks(h *Hooks) Option {
	return func(c *Config) {
		c.Hooks = h
	}
}

func (c Config) withDefaults() Config {
	if c.DefaultTTL <= 0 {
		c.DefaultTTL = DefaultTokenTTL
	}
	if c.CacheTTL <= 0 {
		c.CacheTTL = DefaultCacheTTL
	}
	if c.TokenPrefix == "" {
		c.TokenPrefix = DefaultTokenPrefix
	}
	if c.Hooks == nil {
		c.Hooks = NewHooks()
	}
	return c
}
