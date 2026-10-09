package passwordpolicy

import (
	"time"

	"github.com/BladiCreator/go-modular-auth-password-policy/store"
	"github.com/BladiCreator/go-modular-auth-password-policy/store/memory"
	"github.com/BladiCreator/go-modular-auth/password"
)

// Config holds configuration parameters for the Password Policy plugin.
type Config struct {
	// Policy defines the active password strength, complexity, history, and compromised rules.
	Policy Policy

	// CompromisedChecker overrides the default compromised passwords checker if non-nil.
	CompromisedChecker CompromisedChecker

	// Hasher provides password hashing verification for history comparison.
	// Reuses Core's Argon2id hasher by default.
	Hasher password.Hasher

	// Store provides persistence for password history records.
	Store store.Store

	// EnforceOnSignUp controls whether the BeforeSignUp hook validates passwords. Defaults to true.
	EnforceOnSignUp bool

	// Clock provides time abstraction for deterministic testing. Defaults to time.Now().UTC.
	Clock func() time.Time
}

// Option configures Config.
type Option func(*Config)

// WithPolicy sets the complete password policy.
func WithPolicy(p Policy) Option {
	return func(c *Config) {
		c.Policy = p
	}
}

// WithMinLength sets the minimum password length.
func WithMinLength(min int) Option {
	return func(c *Config) {
		if min > 0 {
			c.Policy.MinLength = min
		}
	}
}

// WithMaxLength sets the maximum password length.
func WithMaxLength(max int) Option {
	return func(c *Config) {
		if max > 0 {
			c.Policy.MaxLength = max
		}
	}
}

// WithComplexity sets complexity requirements.
func WithComplexity(upper, lower, digit, symbol bool) Option {
	return func(c *Config) {
		c.Policy.RequireUppercase = upper
		c.Policy.RequireLowercase = lower
		c.Policy.RequireDigit = digit
		c.Policy.RequireSymbol = symbol
	}
}

// WithHistoryCount sets the number of past passwords to remember and prevent reuse.
func WithHistoryCount(count int) Option {
	return func(c *Config) {
		c.Policy.HistoryCount = count
	}
}

// WithRejectCompromised sets whether compromised passwords should be rejected.
func WithRejectCompromised(reject bool) Option {
	return func(c *Config) {
		c.Policy.RejectCompromised = reject
	}
}

// WithCompromisedChecker configures a custom checker for compromised passwords.
func WithCompromisedChecker(checker CompromisedChecker) Option {
	return func(c *Config) {
		if checker != nil {
			c.CompromisedChecker = checker
		}
	}
}

// WithHasher configures the password hasher to reuse from Core.
func WithHasher(hasher password.Hasher) Option {
	return func(c *Config) {
		if hasher != nil {
			c.Hasher = hasher
		}
	}
}

// WithStore sets the password history persistence store.
func WithStore(s store.Store) Option {
	return func(c *Config) {
		if s != nil {
			c.Store = s
		}
	}
}

// WithEnforceOnSignUp configures whether the BeforeSignUp hook validates passwords.
func WithEnforceOnSignUp(enforce bool) Option {
	return func(c *Config) {
		c.EnforceOnSignUp = enforce
	}
}

// WithClock sets a custom clock function.
func WithClock(clock func() time.Time) Option {
	return func(c *Config) {
		if clock != nil {
			c.Clock = clock
		}
	}
}

func defaultConfig() Config {
	return Config{
		Policy:             DefaultPolicy(),
		CompromisedChecker: DefaultCompromisedChecker,
		Hasher:             password.NewArgon2id(password.DefaultArgon2idParams),
		Store:              memory.New(),
		EnforceOnSignUp:    true,
		Clock: func() time.Time {
			return time.Now().UTC()
		},
	}
}
