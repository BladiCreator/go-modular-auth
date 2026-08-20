package magiclink

import (
	"context"
	"time"
)

// StoreTokenMode defines how magic link verification tokens are persisted in storage.
type StoreTokenMode string

const (
	// StoreTokenPlain persists the token in raw plain text format.
	StoreTokenPlain StoreTokenMode = "plain"

	// StoreTokenHashed persists the token as a one-way cryptographic hash (SHA-256 by default).
	StoreTokenHashed StoreTokenMode = "hashed"

	// StoreTokenEncrypted persists the token using AES-256-GCM symmetric encryption.
	StoreTokenEncrypted StoreTokenMode = "encrypted"
)

// SendMagicLinkData contains parameters passed to the transactional email delivery callback.
type SendMagicLinkData struct {
	// Email is the target recipient email address.
	Email string `json:"email"`

	// Name is an optional recipient display name.
	Name string `json:"name,omitempty"`

	// URL is the generated full verification URL including token and query parameters.
	URL string `json:"url"`

	// Token is the raw verification token string.
	Token string `json:"token"`

	// CallbackURL is the destination URL to redirect upon successful verification.
	CallbackURL string `json:"callback_url,omitempty"`

	// NewUserCallbackURL is an optional destination URL for newly registered users.
	NewUserCallbackURL string `json:"new_user_callback_url,omitempty"`

	// ErrorCallbackURL is an optional destination URL on verification failures.
	ErrorCallbackURL string `json:"error_callback_url,omitempty"`

	// Extra holds dynamic metadata passed through request parameters or hooks.
	Extra map[string]any `json:"extra,omitempty"`
}

// SendMagicLinkFunc defines the required transactional email delivery callback.
type SendMagicLinkFunc func(ctx context.Context, data SendMagicLinkData) error

// TokenGeneratorFunc defines a custom random verification token generator callback.
type TokenGeneratorFunc func(ctx context.Context, email string) (string, error)

// RateLimitConfig defines request throttling limits for magic link dispatching.
type RateLimitConfig struct {
	// Window specifies the sliding rate limit time window.
	Window time.Duration `json:"window"`

	// Max specifies the maximum allowed requests within the configured window.
	Max int `json:"max"`
}

// Config structures all configuration options for the Magic Link plugin.
type Config struct {
	// SendMagicLink is the required callback function for dispatching email links.
	SendMagicLink SendMagicLinkFunc

	// ExpiresIn specifies the lifetime of generated magic link tokens (default: 5 minutes).
	ExpiresIn time.Duration

	// DisableSignUp prevents creation of new accounts when an email is not yet registered (default: false).
	DisableSignUp bool

	// DefaultCallbackURL specifies the fallback redirect URL after successful verification.
	DefaultCallbackURL string

	// GenerateToken allows overriding the default random token generator.
	GenerateToken TokenGeneratorFunc

	// StoreTokenMode defines token persistence security ("plain", "hashed", "encrypted", default: "plain").
	StoreTokenMode StoreTokenMode

	// SecretKey is the symmetric key used when StoreTokenMode is "encrypted".
	SecretKey string

	// CustomHasher allows overriding the default SHA-256 token hasher.
	CustomHasher Hasher

	// CustomCipher allows overriding the default AES-256-GCM cipher.
	CustomCipher Cipher

	// RateLimit holds rate limiting rules for magic link requests.
	RateLimit RateLimitConfig
}

// DefaultConfig returns recommended production defaults for the Magic Link plugin.
func DefaultConfig() Config {
	return Config{
		ExpiresIn:          5 * time.Minute,
		DisableSignUp:      false,
		StoreTokenMode:     StoreTokenPlain,
		DefaultCallbackURL: "/",
		RateLimit: RateLimitConfig{
			Window: 60 * time.Second,
			Max:    5,
		},
	}
}

// Option modifies a Magic Link plugin Config instance.
type Option func(*Config)

// WithSendMagicLink registers the required email delivery callback.
func WithSendMagicLink(fn SendMagicLinkFunc) Option {
	return func(c *Config) {
		c.SendMagicLink = fn
	}
}

// WithExpiresIn configures the magic link token expiration duration.
func WithExpiresIn(d time.Duration) Option {
	return func(c *Config) {
		c.ExpiresIn = d
	}
}

// WithDisableSignUp toggles whether unregistered users can sign up via magic links.
func WithDisableSignUp(disable bool) Option {
	return func(c *Config) {
		c.DisableSignUp = disable
	}
}

// WithDefaultCallbackURL sets the default post-login redirect URL.
func WithDefaultCallbackURL(url string) Option {
	return func(c *Config) {
		c.DefaultCallbackURL = url
	}
}

// WithStoreTokenMode configures how tokens are stored in the database ("plain", "hashed", "encrypted").
func WithStoreTokenMode(mode StoreTokenMode) Option {
	return func(c *Config) {
		c.StoreTokenMode = mode
	}
}

// WithSecretKey configures the secret key for encrypted token mode.
func WithSecretKey(key string) Option {
	return func(c *Config) {
		c.SecretKey = key
	}
}

// WithCustomHasher sets a custom Hasher for hashed token mode.
func WithCustomHasher(h Hasher) Option {
	return func(c *Config) {
		c.CustomHasher = h
	}
}

// WithCustomCipher sets a custom Cipher for encrypted token mode.
func WithCustomCipher(ciph Cipher) Option {
	return func(c *Config) {
		c.CustomCipher = ciph
	}
}

// WithGenerateToken sets a custom token generation function.
func WithGenerateToken(fn TokenGeneratorFunc) Option {
	return func(c *Config) {
		c.GenerateToken = fn
	}
}

// WithRateLimit configures rate limiting parameters.
func WithRateLimit(window time.Duration, max int) Option {
	return func(c *Config) {
		c.RateLimit = RateLimitConfig{
			Window: window,
			Max:    max,
		}
	}
}
