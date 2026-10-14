package anonymous

import (
	"time"

	"github.com/BladiCreator/go-modular-auth/password"
)

// Default settings for anonymous identity management.
const (
	DefaultIdentityTTL       = 30 * 24 * time.Hour
	DefaultSessionTTL        = 30 * 24 * time.Hour
	DefaultCacheTTL          = 5 * time.Minute
	DefaultEmailDomain       = "anonymous.invalid"
	DefaultMinPasswordLength = 8
	DefaultMaxPasswordLength = 128
)

// Config configures the anonymous authentication plugin.
type Config struct {
	// IdentityTTL is the duration after which an unconverted anonymous identity expires.
	IdentityTTL time.Duration

	// SessionTTL is the duration granted to anonymous sessions.
	SessionTTL time.Duration

	// CacheTTL is the time-to-live for cached anonymous identities.
	CacheTTL time.Duration

	// EmailDomain is the synthetic domain used for generated placeholder emails (e.g. "anonymous.invalid").
	EmailDomain string

	// MinPasswordLength is the minimum allowed password length for permanent accounts during conversion.
	MinPasswordLength int

	// MaxPasswordLength is the maximum allowed password length for permanent accounts during conversion.
	MaxPasswordLength int

	// Hasher is the password hashing implementation used during account conversion.
	// Defaults to Argon2id if nil.
	Hasher password.Hasher

	// Hooks provides lifecycle interceptors for anonymous workflows.
	Hooks *Hooks
}

// Option configures an anonymous plugin module.
type Option func(*Config)

// WithIdentityTTL sets the expiration duration for anonymous identities.
func WithIdentityTTL(ttl time.Duration) Option {
	return func(c *Config) {
		c.IdentityTTL = ttl
	}
}

// WithSessionTTL sets the session duration for anonymous user sessions.
func WithSessionTTL(ttl time.Duration) Option {
	return func(c *Config) {
		c.SessionTTL = ttl
	}
}

// WithCacheTTL sets the cache duration for anonymous identities.
func WithCacheTTL(ttl time.Duration) Option {
	return func(c *Config) {
		c.CacheTTL = ttl
	}
}

// WithEmailDomain configures the domain used for synthetic placeholder emails.
func WithEmailDomain(domain string) Option {
	return func(c *Config) {
		c.EmailDomain = domain
	}
}

// WithPasswordPolicy sets password length constraints used during conversion.
func WithPasswordPolicy(minLen, maxLen int) Option {
	return func(c *Config) {
		c.MinPasswordLength = minLen
		c.MaxPasswordLength = maxLen
	}
}

// WithHasher configures a custom password hasher for conversions.
func WithHasher(h password.Hasher) Option {
	return func(c *Config) {
		c.Hasher = h
	}
}

// WithHooks sets the lifecycle hooks registry.
func WithHooks(h *Hooks) Option {
	return func(c *Config) {
		c.Hooks = h
	}
}

func (c Config) withDefaults() Config {
	if c.IdentityTTL <= 0 {
		c.IdentityTTL = DefaultIdentityTTL
	}
	if c.SessionTTL <= 0 {
		c.SessionTTL = DefaultSessionTTL
	}
	if c.CacheTTL <= 0 {
		c.CacheTTL = DefaultCacheTTL
	}
	if c.EmailDomain == "" {
		c.EmailDomain = DefaultEmailDomain
	}
	if c.MinPasswordLength <= 0 {
		c.MinPasswordLength = DefaultMinPasswordLength
	}
	if c.MaxPasswordLength <= 0 {
		c.MaxPasswordLength = DefaultMaxPasswordLength
	}
	if c.Hasher == nil {
		c.Hasher = password.NewArgon2id(password.DefaultArgon2idParams)
	}
	if c.Hooks == nil {
		c.Hooks = NewHooks()
	}
	return c
}
