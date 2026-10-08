package emailotp

import (
	"fmt"
	"time"

	"github.com/BladiCreator/go-modular-auth-email-otp/cache"
	"github.com/BladiCreator/go-modular-auth-email-otp/store"
	"github.com/BladiCreator/go-modular-auth-email-otp/store/memory"
	"github.com/BladiCreator/go-modular-auth/email"
)

// MessageBuilder builds a transactional email message for OTP delivery.
type MessageBuilder func(to, code string, ttl time.Duration) email.Message

// RateLimitConfig configures throttling and abuse mitigation.
type RateLimitConfig struct {
	Enabled       bool
	Max           int
	Window        time.Duration
	Cooldown      time.Duration
	FailurePolicy cache.FailurePolicy
}

// Config defines the configuration for the Email OTP plugin.
type Config struct {
	// Store is the authoritative storage adapter for OTP records.
	// Defaults to an in-memory store if nil.
	Store store.Store

	// EmailSender physically delivers email messages.
	// If nil, the host's configured email sender is used.
	EmailSender email.Sender

	// TTL defines the lifespan of an issued OTP code. Default: 10 minutes.
	TTL time.Duration

	// OTPLength defines the number of numeric digits in the OTP code. Default: 6.
	OTPLength int

	// MaxAttempts defines the maximum failed attempts permitted before locking the OTP. Default: 3.
	MaxAttempts int

	// AllowSignUp allows automatic creation of accounts for unknown email addresses. Default: true.
	AllowSignUp bool

	// RevokePreviousOnRequest revokes active OTPs for the email prior to issuing a new code. Default: true.
	RevokePreviousOnRequest bool

	// RateLimit holds rate limiting and cooldown rules.
	RateLimit RateLimitConfig

	// MessageBuilder customizes the subject and body of OTP delivery emails.
	MessageBuilder MessageBuilder

	// Hooks provides workflow extension points.
	Hooks *Hooks
}

func (c Config) withDefaults() Config {
	if c.Store == nil {
		c.Store = memory.New()
	}
	if c.TTL <= 0 {
		c.TTL = 10 * time.Minute
	}
	if c.OTPLength <= 0 {
		c.OTPLength = DefaultOTPLength
	}
	if c.MaxAttempts <= 0 {
		c.MaxAttempts = 3
	}
	if c.MessageBuilder == nil {
		c.MessageBuilder = defaultMessageBuilder
	}
	if c.Hooks == nil {
		c.Hooks = NewHooks()
	}
	if c.RateLimit.FailurePolicy == "" {
		c.RateLimit.FailurePolicy = cache.FailOpen
	}
	return c
}

func defaultMessageBuilder(to, code string, ttl time.Duration) email.Message {
	mins := int(ttl.Minutes())
	text := fmt.Sprintf("Your verification code is: %s\n\nThis code will expire in %d minutes.\nIf you did not request this code, you can safely ignore this email.", code, mins)
	html := fmt.Sprintf("<p>Your verification code is: <strong>%s</strong></p><p>This code will expire in %d minutes.</p><p>If you did not request this, please ignore this email.</p>", code, mins)

	return email.Message{
		To:      to,
		Subject: "Your Verification Code",
		Text:    text,
		HTML:    html,
	}
}

// Option applies a functional configuration option.
type Option func(*Config)

// WithStore sets the authoritative Store adapter.
func WithStore(s store.Store) Option {
	return func(c *Config) {
		if s != nil {
			c.Store = s
		}
	}
}

// WithEmailSender sets a custom email sender for OTP delivery.
func WithEmailSender(s email.Sender) Option {
	return func(c *Config) {
		c.EmailSender = s
	}
}

// WithTTL sets the lifetime of generated OTP codes.
func WithTTL(ttl time.Duration) Option {
	return func(c *Config) {
		if ttl > 0 {
			c.TTL = ttl
		}
	}
}

// WithOTPLength sets the length of generated OTP codes.
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

// WithAllowSignUp specifies whether unknown emails can register automatically.
func WithAllowSignUp(allow bool) Option {
	return func(c *Config) {
		c.AllowSignUp = allow
	}
}

// WithRevokePreviousOnRequest controls whether old active OTPs are revoked when a new code is requested.
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
