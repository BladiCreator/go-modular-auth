package phone

import (
	"time"

	"github.com/BladiCreator/go-modular-auth-phone/cache"
)

// RateLimitConfig configures throttling and abuse mitigation.
type RateLimitConfig struct {
	Enabled       bool
	Max           int
	Window        time.Duration
	Cooldown      time.Duration
	FailurePolicy cache.FailurePolicy
}

// Config defines the configuration for the Phone authentication plugin.
type Config struct {
	// Provider delivers transactional SMS/voice messages.
	Provider PhoneProvider

	// TTL defines the lifespan of an issued OTP code. Default: 5 minutes.
	TTL time.Duration

	// OTPLength defines the numeric digit count of the OTP. Default: 6.
	OTPLength int

	// MaxAttempts defines the maximum failed attempts permitted before locking the OTP. Default: 3.
	MaxAttempts int

	// AllowSignUp allows automatic creation of accounts for unknown phone numbers upon verification. Default: true.
	AllowSignUp bool

	// RevokePreviousOnRequest revokes active OTPs for the phone prior to issuing a new code. Default: true.
	RevokePreviousOnRequest bool

	// RateLimit holds rate limiting and cooldown rules.
	RateLimit RateLimitConfig

	// CacheTTL defines the TTL for ephemeral phone lookups. Default: 15 minutes.
	CacheTTL time.Duration

	// Normalizer normalizes raw phone strings into canonical E.164 format.
	Normalizer Normalizer

	// Validator validates canonical phone strings.
	Validator Validator

	// MessageBuilder formats message body and delivery parameters.
	MessageBuilder MessageBuilder

	// Hooks provides workflow extension points.
	Hooks *Hooks
}

func (c Config) withDefaults() Config {
	if c.TTL <= 0 {
		c.TTL = 5 * time.Minute
	}
	if c.OTPLength <= 0 {
		c.OTPLength = DefaultOTPLength
	}
	if c.MaxAttempts <= 0 {
		c.MaxAttempts = 3
	}
	if c.CacheTTL <= 0 {
		c.CacheTTL = 15 * time.Minute
	}
	if c.Normalizer == nil {
		c.Normalizer = DefaultNormalizer()
	}
	if c.Validator == nil {
		c.Validator = DefaultValidator()
	}
	if c.MessageBuilder == nil {
		c.MessageBuilder = DefaultMessageBuilder
	}
	if c.Hooks == nil {
		c.Hooks = NewHooks()
	}
	if c.RateLimit.FailurePolicy == "" {
		c.RateLimit.FailurePolicy = cache.FailOpen
	}
	return c
}

// Option applies a functional configuration option.
type Option func(*Config)

// WithProvider sets the message delivery provider.
func WithProvider(p PhoneProvider) Option {
	return func(c *Config) {
		c.Provider = p
	}
}

// WithTTL sets the validity lifetime of generated OTP codes.
func WithTTL(ttl time.Duration) Option {
	return func(c *Config) {
		if ttl > 0 {
			c.TTL = ttl
		}
	}
}

// WithOTPLength sets the digit count of generated OTP codes.
func WithOTPLength(length int) Option {
	return func(c *Config) {
		if length >= MinOTPLength && length <= MaxOTPLength {
			c.OTPLength = length
		}
	}
}

// WithMaxAttempts sets the maximum verification attempts allowed per OTP.
func WithMaxAttempts(attempts int) Option {
	return func(c *Config) {
		if attempts > 0 {
			c.MaxAttempts = attempts
		}
	}
}

// WithAllowSignUp specifies whether unregistered phone numbers can register automatically.
func WithAllowSignUp(allow bool) Option {
	return func(c *Config) {
		c.AllowSignUp = allow
	}
}

// WithRevokePreviousOnRequest controls whether existing active OTPs are revoked when a new code is requested.
func WithRevokePreviousOnRequest(revoke bool) Option {
	return func(c *Config) {
		c.RevokePreviousOnRequest = revoke
	}
}

// WithRateLimit enables rate limiting and cooldown rules.
func WithRateLimit(max int, window, cooldown time.Duration) Option {
	return func(c *Config) {
		c.RateLimit.Enabled = true
		c.RateLimit.Max = max
		c.RateLimit.Window = window
		c.RateLimit.Cooldown = cooldown
	}
}

// WithCacheFailurePolicy explicitly defines fail-open vs fail-closed handling for cache errors.
func WithCacheFailurePolicy(policy cache.FailurePolicy) Option {
	return func(c *Config) {
		c.RateLimit.FailurePolicy = policy
	}
}

// WithCacheTTL sets the duration for ephemeral cache entries.
func WithCacheTTL(ttl time.Duration) Option {
	return func(c *Config) {
		if ttl > 0 {
			c.CacheTTL = ttl
		}
	}
}

// WithNormalizer sets a custom phone normalizer.
func WithNormalizer(n Normalizer) Option {
	return func(c *Config) {
		if n != nil {
			c.Normalizer = n
		}
	}
}

// WithValidator sets a custom phone validator.
func WithValidator(v Validator) Option {
	return func(c *Config) {
		if v != nil {
			c.Validator = v
		}
	}
}

// WithMessageBuilder sets a custom message constructor.
func WithMessageBuilder(mb MessageBuilder) Option {
	return func(c *Config) {
		if mb != nil {
			c.MessageBuilder = mb
		}
	}
}

// WithHooks sets custom workflow hooks.
func WithHooks(h *Hooks) Option {
	return func(c *Config) {
		if h != nil {
			c.Hooks = h
		}
	}
}
