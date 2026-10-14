package rbac

import (
	"time"

	"github.com/BladiCreator/go-modular-auth-rbac/cache"
)

// Config holds configuration parameters for the RBAC plugin.
type Config struct {
	Cache    cache.Cache
	CacheTTL time.Duration
	Clock    func() time.Time
}

// Option configures an RBAC plugin instance.
type Option func(*Config)

// WithCache configures an explicit authorization cache.
func WithCache(cacheImpl cache.Cache) Option {
	return func(c *Config) {
		c.Cache = cacheImpl
	}
}

// WithCacheTTL sets the time-to-live for cached authorization decisions.
func WithCacheTTL(ttl time.Duration) Option {
	return func(c *Config) {
		c.CacheTTL = ttl
	}
}

// WithClock sets a custom time provider for testing.
func WithClock(clock func() time.Time) Option {
	return func(c *Config) {
		c.Clock = clock
	}
}

func defaultConfig() Config {
	return Config{
		CacheTTL: 5 * time.Minute,
		Clock:    time.Now,
	}
}
