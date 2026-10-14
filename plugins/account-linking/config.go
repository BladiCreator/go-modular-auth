package accountlinking

import (
	"time"
)

// Config holds configuration parameters for the Account Linking plugin.
type Config struct {
	// DefaultTicketTTL is the default validity duration for linking tickets. Defaults to 15 minutes.
	DefaultTicketTTL time.Duration

	// AllowOrphanByDefault controls whether removing the final authentication method is allowed by default. Defaults to false.
	AllowOrphanByDefault bool

	// Clock provides time abstraction for deterministic testing. Defaults to time.Now().UTC.
	Clock func() time.Time
}

// Option configures Config.
type Option func(*Config)

// WithDefaultTicketTTL sets the default validity duration for linking tickets.
func WithDefaultTicketTTL(ttl time.Duration) Option {
	return func(c *Config) {
		if ttl > 0 {
			c.DefaultTicketTTL = ttl
		}
	}
}

// WithAllowOrphanByDefault sets whether removing the final auth method is permitted globally.
func WithAllowOrphanByDefault(allow bool) Option {
	return func(c *Config) {
		c.AllowOrphanByDefault = allow
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
		DefaultTicketTTL:     15 * time.Minute,
		AllowOrphanByDefault: false,
		Clock: func() time.Time {
			return time.Now().UTC()
		},
	}
}
