package apikeys

import (
	"time"

	"github.com/BladiCreator/go-modular-auth-apikeys/store"
)

// SubjectStrategy defines how an API key resolves its auth.Principal.Subject.
type SubjectStrategy string

const (
	// SubjectStrategyKeyID sets Principal.Subject to the unique API key ID (default).
	SubjectStrategyKeyID SubjectStrategy = "key_id"

	// SubjectStrategyOwner prioritizes UserID, then ServiceID, then KeyID as Principal.Subject.
	SubjectStrategyOwner SubjectStrategy = "owner"
)

// Config configures the API keys plugin module.
type Config struct {
	// Store provides persistence for API keys. Required.
	Store store.Store

	// KeyPrefix is the default prefix prepended to issued API keys (defaults to "gma_").
	KeyPrefix string

	// DefaultExpiresIn sets a default expiration duration if none is specified at creation.
	DefaultExpiresIn time.Duration

	// CacheTTL defines how long active keys are retained in cache (defaults to 5m).
	CacheTTL time.Duration

	// MaxFailedAttempts specifies the maximum failed verification attempts before throttling.
	MaxFailedAttempts int

	// BruteForceWindow is the evaluation window for failed verification attempts.
	BruteForceWindow time.Duration

	// SubjectStrategy controls how auth.Principal.Subject is populated.
	SubjectStrategy SubjectStrategy

	// TouchLastUsedThreshold prevents database write amplification by updating LastUsedAt
	// only if the key was last used longer ago than this threshold (defaults to 1m).
	TouchLastUsedThreshold time.Duration
}

// Option modifies Config.
type Option func(*Config)

// WithStore configures the persistence store adapter.
func WithStore(s store.Store) Option {
	return func(c *Config) {
		c.Store = s
	}
}

// WithKeyPrefix sets the default prefix for newly generated API keys.
func WithKeyPrefix(p string) Option {
	return func(c *Config) {
		c.KeyPrefix = p
	}
}

// WithDefaultExpiresIn sets the default expiration lifetime for keys created without explicit expiration.
func WithDefaultExpiresIn(d time.Duration) Option {
	return func(c *Config) {
		c.DefaultExpiresIn = d
	}
}

// WithCacheTTL configures the TTL for cached API keys.
func WithCacheTTL(d time.Duration) Option {
	return func(c *Config) {
		c.CacheTTL = d
	}
}

// WithBruteForceProtection configures rate limiting on failed key verification attempts.
func WithBruteForceProtection(maxAttempts int, window time.Duration) Option {
	return func(c *Config) {
		c.MaxFailedAttempts = maxAttempts
		c.BruteForceWindow = window
	}
}

// WithSubjectStrategy configures how the principal subject is resolved.
func WithSubjectStrategy(s SubjectStrategy) Option {
	return func(c *Config) {
		c.SubjectStrategy = s
	}
}

// WithTouchLastUsedThreshold configures the minimum interval between LastUsedAt database writes.
func WithTouchLastUsedThreshold(d time.Duration) Option {
	return func(c *Config) {
		c.TouchLastUsedThreshold = d
	}
}

func (c Config) withDefaults() Config {
	if c.KeyPrefix == "" {
		c.KeyPrefix = DefaultKeyPrefix
	}
	if c.CacheTTL <= 0 {
		c.CacheTTL = 5 * time.Minute
	}
	if c.MaxFailedAttempts <= 0 {
		c.MaxFailedAttempts = 10
	}
	if c.BruteForceWindow <= 0 {
		c.BruteForceWindow = 1 * time.Minute
	}
	if c.SubjectStrategy == "" {
		c.SubjectStrategy = SubjectStrategyKeyID
	}
	if c.TouchLastUsedThreshold <= 0 {
		c.TouchLastUsedThreshold = 1 * time.Minute
	}
	return c
}
