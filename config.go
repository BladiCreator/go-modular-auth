package auth

import (
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/BladiCreator/go-modular-auth/adapter"
	"github.com/BladiCreator/go-modular-auth/cache"
	"github.com/BladiCreator/go-modular-auth/email"
	"github.com/BladiCreator/go-modular-auth/password"
	"github.com/BladiCreator/go-modular-auth/user"
)

// Config configures an Auth instance. Adapter is required;
// every zero value falls back to a secure default.
type Config struct {
	// Adapter is the generic, schema-driven storage adapter. Required.
	Adapter adapter.Adapter
	// Cache is an optional performance layer. When nil every read hits the Store.
	Cache cache.Cache
	// Email is an optional sender used by email verification and password reset.
	Email email.Sender
	// Hasher hashes passwords. Defaults to Argon2id with OWASP parameters.
	Hasher password.Hasher
	// Plugins are the plugin modules to install.
	Plugins []PluginModule
	// Logger receives operational logs (cache degradation, hook panics...). Defaults to discard.
	Logger *slog.Logger
	// Now is the clock. Defaults to time.Now.
	Now func() time.Time

	Session           SessionConfig
	User              UserConfig
	Password          PasswordPolicy
	EmailVerification EmailVerificationConfig
	PasswordReset     PasswordResetConfig
	Messages          Messages
}

// SessionConfig configures opaque sessions.
type SessionConfig struct {
	// TTL is the session lifetime. Default: 7 days.
	TTL time.Duration
	// CacheTTL is the maximum time a session stays cached. The effective TTL
	// is min(CacheTTL, time until expiration). It bounds the inconsistency
	// window should a cache invalidation fail. Default: 5 minutes.
	CacheTTL time.Duration
}

// UserConfig configures user caching.
type UserConfig struct {
	// CacheTTL is the time a user stays cached. Default: 5 minutes.
	CacheTTL time.Duration
}

// PasswordPolicy constrains acceptable passwords.
type PasswordPolicy struct {
	// MinLength in bytes. Default: 8.
	MinLength int
	// MaxLength in bytes, protecting the hasher from DoS. Default: 128.
	MaxLength int
}

// EmailVerificationConfig configures email verification.
type EmailVerificationConfig struct {
	// Required forbids sign in (and session issuance at sign up) until the email is verified.
	Required bool
	// SendOnSignUp sends the verification email right after sign up (requires Config.Email).
	SendOnSignUp bool
	// TokenTTL is the verification token lifetime. Default: 24 hours.
	TokenTTL time.Duration
}

// PasswordResetConfig configures password reset.
type PasswordResetConfig struct {
	// TokenTTL is the reset token lifetime. Default: 1 hour.
	TokenTTL time.Duration
}

// Messages builds the emails sent by the core. Builders receive the
// plaintext token; it is the application's job to embed it (e.g. into a URL
// served by its transport adapter). The core fills Message.To.
type Messages struct {
	EmailVerification func(u *user.User, token string) email.Message
	PasswordReset     func(u *user.User, token string) email.Message
}

func (c Config) withDefaults() (Config, error) {
	if c.Adapter == nil {
		return c, ErrAdapterRequired
	}
	if c.Hasher == nil {
		c.Hasher = password.NewArgon2id(password.DefaultArgon2idParams)
	}
	if c.Logger == nil {
		c.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	c.Session.TTL = orDefault(c.Session.TTL, 7*24*time.Hour)
	c.Session.CacheTTL = orDefault(c.Session.CacheTTL, 5*time.Minute)
	c.User.CacheTTL = orDefault(c.User.CacheTTL, 5*time.Minute)
	c.Password.MinLength = orDefault(c.Password.MinLength, 8)
	c.Password.MaxLength = orDefault(c.Password.MaxLength, 128)
	if c.Password.MinLength > c.Password.MaxLength {
		return c, fmt.Errorf("auth: password MinLength (%d) > MaxLength (%d)", c.Password.MinLength, c.Password.MaxLength)
	}
	c.EmailVerification.TokenTTL = orDefault(c.EmailVerification.TokenTTL, 24*time.Hour)
	c.PasswordReset.TokenTTL = orDefault(c.PasswordReset.TokenTTL, time.Hour)
	if c.EmailVerification.SendOnSignUp && c.Email == nil {
		return c, fmt.Errorf("%w: EmailVerification.SendOnSignUp requires Config.Email", ErrEmailNotConfigured)
	}
	if c.Messages.EmailVerification == nil {
		c.Messages.EmailVerification = defaultVerificationMessage
	}
	if c.Messages.PasswordReset == nil {
		c.Messages.PasswordReset = defaultResetMessage
	}
	return c, nil
}

func orDefault[T comparable](v, def T) T {
	var zero T
	if v == zero {
		return def
	}
	return v
}

func defaultVerificationMessage(_ *user.User, token string) email.Message {
	return email.Message{
		Subject: "Verify your email address",
		Text:    "Use the following code to verify your email address:\n\n" + token + "\n",
	}
}

func defaultResetMessage(_ *user.User, token string) email.Message {
	return email.Message{
		Subject: "Reset your password",
		Text:    "Use the following code to reset your password:\n\n" + token + "\n\nIf you did not request it, ignore this email.\n",
	}
}
