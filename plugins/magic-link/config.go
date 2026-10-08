package magiclink

import (
	"fmt"
	"net/url"
	"time"

	"github.com/BladiCreator/go-modular-auth/email"
)

// MessageBuilder builds the transactional email message sent to the user.
// It receives the destination email, the raw plaintext token, and the optional constructed URL.
type MessageBuilder func(to string, token string, verificationURL string) email.Message

// RateLimitConfig configures request throttling.
type RateLimitConfig struct {
	// Enabled determines whether rate limiting is active.
	Enabled bool

	// Max is the maximum number of requests allowed in Window.
	// Default: 5 requests.
	Max int

	// Window is the time window for rate limiting.
	// Default: 15 minutes.
	Window time.Duration

	// Cooldown is the minimum duration required between consecutive requests for the same email.
	// Default: 60 seconds.
	Cooldown time.Duration
}

// Config configures the magic link plugin module.
type Config struct {
	// TTL is the lifetime of an issued magic link token.
	// Default: 15 minutes.
	TTL time.Duration

	// AllowSignUp allows automatically creating a new user and account
	// if the requested email is not already registered.
	// Default: false (only existing users can authenticate).
	AllowSignUp bool

	// RevokePreviousOnRequest deletes any active magic link tokens for the subject
	// when a new magic link is requested.
	// Default: true.
	RevokePreviousOnRequest bool

	// BaseURL is an optional base URL used to construct the full magic link URL.
	// e.g. "https://myapp.com/auth/magiclink/verify".
	// The token is appended as a query parameter ("?token=").
	BaseURL string

	// RateLimit configures optional request throttling and cooldowns.
	RateLimit RateLimitConfig

	// MessageBuilder formats the transactional email.
	MessageBuilder MessageBuilder

	// EmailSender overrides the email sender configured on the host.
	EmailSender email.Sender

	// Hooks provides access to pre-request and pre-consume security hooks.
	Hooks *Hooks
}

// Option modifies a Config instance.
type Option func(*Config)

// WithTTL sets the lifetime of magic link tokens.
func WithTTL(ttl time.Duration) Option {
	return func(c *Config) { c.TTL = ttl }
}

// WithAllowSignUp toggles automatic user sign-up on magic link verification.
func WithAllowSignUp(allow bool) Option {
	return func(c *Config) { c.AllowSignUp = allow }
}

// WithRevokePreviousOnRequest sets whether requesting a token revokes earlier tokens.
func WithRevokePreviousOnRequest(revoke bool) Option {
	return func(c *Config) { c.RevokePreviousOnRequest = revoke }
}

// WithBaseURL sets the base URL for constructing magic link hyperlinks.
func WithBaseURL(rawURL string) Option {
	return func(c *Config) { c.BaseURL = rawURL }
}

// WithRateLimit configures rate limiting and cooldown policies.
func WithRateLimit(cfg RateLimitConfig) Option {
	return func(c *Config) { c.RateLimit = cfg }
}

// WithMessageBuilder configures a custom email message builder.
func WithMessageBuilder(builder MessageBuilder) Option {
	return func(c *Config) { c.MessageBuilder = builder }
}

// WithEmailSender provides an explicit email.Sender.
func WithEmailSender(sender email.Sender) Option {
	return func(c *Config) { c.EmailSender = sender }
}

// WithHooks sets custom security hooks.
func WithHooks(hooks *Hooks) Option {
	return func(c *Config) { c.Hooks = hooks }
}

func (c Config) withDefaults() Config {
	if c.TTL <= 0 {
		c.TTL = 15 * time.Minute
	}
	if c.MessageBuilder == nil {
		c.MessageBuilder = defaultMessageBuilder
	}
	if c.Hooks == nil {
		c.Hooks = NewHooks()
	}
	if c.RateLimit.Enabled {
		if c.RateLimit.Max <= 0 {
			c.RateLimit.Max = 5
		}
		if c.RateLimit.Window <= 0 {
			c.RateLimit.Window = 15 * time.Minute
		}
		if c.RateLimit.Cooldown <= 0 {
			c.RateLimit.Cooldown = 60 * time.Second
		}
	}
	return c
}

func defaultMessageBuilder(to string, token string, verificationURL string) email.Message {
	body := fmt.Sprintf("Hello,\n\nUse the following token to sign in:\n\n%s\n", token)
	if verificationURL != "" {
		body += fmt.Sprintf("\nOr click this link directly:\n%s\n", verificationURL)
	}
	body += "\nThis link is single-use and will expire shortly.\nIf you did not request this email, you can safely ignore it.\n"

	return email.Message{
		To:      to,
		Subject: "Your Magic Sign-In Link",
		Text:    body,
	}
}

// buildVerificationURL constructs a magic link URL from baseURL and token.
func buildVerificationURL(baseURL, token string) string {
	if baseURL == "" {
		return ""
	}
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return ""
	}
	q := parsed.Query()
	q.Set("token", token)
	parsed.RawQuery = q.Encode()
	return parsed.String()
}
