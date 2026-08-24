package apikey

import "time"

// KeyGeneratorFunc is a custom function signature for generating random API Keys.
type KeyGeneratorFunc func(length int, prefix string) (string, error)

// KeyHasherFunc is a custom function signature for computing key hashes.
type KeyHasherFunc func(key string) (string, error)

// Config holds operational settings for the API Key plugin.
type Config struct {
	// ApiKeyHeaders defines HTTP request header names inspected for API Keys (default: ["X-API-Key"]).
	ApiKeyHeaders []string

	// DefaultKeyLength specifies the byte/char length of generated random keys (default: 32).
	DefaultKeyLength int

	// DefaultPrefix specifies default string prefix attached to issued keys (e.g. "sk_live_").
	DefaultPrefix string

	// KeyExpiration specifies default lifetime duration applied to new keys (optional).
	KeyExpiration *time.Duration

	// RateLimitEnabled enables rate limiting by default for newly created keys.
	RateLimitEnabled bool

	// RateLimitTimeWindow sets default rate limit sliding window duration.
	RateLimitTimeWindow time.Duration

	// RateLimitMax sets default max requests per sliding window.
	RateLimitMax int64

	// DisableKeyHashing when true stores raw plaintext keys in database (NOT recommended for production).
	DisableKeyHashing bool

	// EnableSessionForAPIKeys populates mock user session context during HTTP middleware processing.
	EnableSessionForAPIKeys bool

	// DeferUpdates when true updates request counter and usage timestamps asynchronously in goroutines.
	DeferUpdates bool

	// CustomKeyGenerator overrides standard crypto/rand key generator.
	CustomKeyGenerator KeyGeneratorFunc

	// CustomKeyHasher overrides standard SHA-256 base64url key hasher.
	CustomKeyHasher KeyHasherFunc
}

// DefaultConfig returns recommended production default settings for the API Key plugin.
func DefaultConfig() Config {
	return Config{
		ApiKeyHeaders:           []string{"X-API-Key"},
		DefaultKeyLength:        32,
		DefaultPrefix:           "",
		KeyExpiration:           nil,
		RateLimitEnabled:        false,
		RateLimitTimeWindow:     time.Minute,
		RateLimitMax:            100,
		DisableKeyHashing:       false,
		EnableSessionForAPIKeys: true,
		DeferUpdates:            false,
	}
}

// Option configures functional options for the API Key plugin.
type Option func(*Config)

// WithHeaderNames customizes HTTP header names checked during HTTP middleware key extraction.
func WithHeaderNames(headers ...string) Option {
	return func(c *Config) {
		if len(headers) > 0 {
			c.ApiKeyHeaders = headers
		}
	}
}

// WithDefaultKeyLength configures the length of randomly generated keys.
func WithDefaultKeyLength(length int) Option {
	return func(c *Config) {
		if length > 0 {
			c.DefaultKeyLength = length
		}
	}
}

// WithDefaultPrefix sets the default prefix string prepended to new keys (e.g. "sk_live_").
func WithDefaultPrefix(prefix string) Option {
	return func(c *Config) {
		c.DefaultPrefix = prefix
	}
}

// WithRateLimit configures default sliding window rate limiting for issued keys.
func WithRateLimit(enabled bool, window time.Duration, maxReq int64) Option {
	return func(c *Config) {
		c.RateLimitEnabled = enabled
		if window > 0 {
			c.RateLimitTimeWindow = window
		}
		if maxReq > 0 {
			c.RateLimitMax = maxReq
		}
	}
}

// WithExpiration sets default lifetime expiration duration for issued keys.
func WithExpiration(defaultExpiresIn *time.Duration) Option {
	return func(c *Config) {
		c.KeyExpiration = defaultExpiresIn
	}
}

// WithDisableKeyHashing toggles storing plaintext raw keys instead of SHA-256 hashes.
func WithDisableKeyHashing(disable bool) Option {
	return func(c *Config) {
		c.DisableKeyHashing = disable
	}
}

// WithEnableSessionForAPIKeys configures whether middleware mock user session is populated upon authentication.
func WithEnableSessionForAPIKeys(enable bool) Option {
	return func(c *Config) {
		c.EnableSessionForAPIKeys = enable
	}
}

// WithDeferUpdates enables asynchronous background updates of key counters (RequestCount, LastRequest, Remaining).
func WithDeferUpdates(deferUpdates bool) Option {
	return func(c *Config) {
		c.DeferUpdates = deferUpdates
	}
}

// WithCustomKeyGenerator overrides standard crypto/rand key generator implementation.
func WithCustomKeyGenerator(fn KeyGeneratorFunc) Option {
	return func(c *Config) {
		if fn != nil {
			c.CustomKeyGenerator = fn
		}
	}
}

// WithCustomKeyHasher overrides standard SHA-256 base64url key hasher implementation.
func WithCustomKeyHasher(fn KeyHasherFunc) Option {
	return func(c *Config) {
		if fn != nil {
			c.CustomKeyHasher = fn
		}
	}
}
