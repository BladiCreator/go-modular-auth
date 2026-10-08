package username

import (
	"time"

	"github.com/BladiCreator/go-modular-auth-username/store"
	"github.com/BladiCreator/go-modular-auth-username/store/memory"
)

// Config holds configuration parameters for the username plugin.
type Config struct {
	Store         store.Store
	MinLength     int
	MaxLength     int
	CaseSensitive bool
	Reserved      map[string]struct{}
	Normalizer    Normalizer
	Validator     Validator
	CacheTTL      time.Duration
}

// Option modifies plugin configuration.
type Option func(*Config)

// WithStore sets the persistence Store adapter. If not provided, an in-memory store is used by default.
func WithStore(s store.Store) Option {
	return func(c *Config) {
		if s != nil {
			c.Store = s
		}
	}
}

// WithMinLength sets the minimum allowed username length.
func WithMinLength(min int) Option {
	return func(c *Config) {
		if min > 0 {
			c.MinLength = min
		}
	}
}

// WithMaxLength sets the maximum allowed username length.
func WithMaxLength(max int) Option {
	return func(c *Config) {
		if max > 0 {
			c.MaxLength = max
		}
	}
}

// WithCaseSensitive explicitly sets whether usernames are case-sensitive.
// When false (default), comparisons and uniqueness are case-insensitive.
func WithCaseSensitive(sensitive bool) Option {
	return func(c *Config) {
		c.CaseSensitive = sensitive
		c.Normalizer = DefaultNormalizer(sensitive)
	}
}

// WithReserved adds additional names to the reserved keywords list.
func WithReserved(names ...string) Option {
	return func(c *Config) {
		if c.Reserved == nil {
			c.Reserved = make(map[string]struct{})
		}
		for _, n := range names {
			c.Reserved[n] = struct{}{}
		}
	}
}

// WithNormalizer sets a custom normalization function.
func WithNormalizer(n Normalizer) Option {
	return func(c *Config) {
		if n != nil {
			c.Normalizer = n
		}
	}
}

// WithValidator sets a custom validation function.
func WithValidator(v Validator) Option {
	return func(c *Config) {
		if v != nil {
			c.Validator = v
		}
	}
}

// WithCacheTTL sets the cache duration for username records.
func WithCacheTTL(d time.Duration) Option {
	return func(c *Config) {
		if d > 0 {
			c.CacheTTL = d
		}
	}
}

func defaultConfig() Config {
	cfg := Config{
		MinLength:     3,
		MaxLength:     30,
		CaseSensitive: false,
		Reserved:      make(map[string]struct{}, len(DefaultReservedUsernames)),
		CacheTTL:      5 * time.Minute,
	}
	for k := range DefaultReservedUsernames {
		cfg.Reserved[k] = struct{}{}
	}
	cfg.Normalizer = DefaultNormalizer(cfg.CaseSensitive)
	cfg.Validator = DefaultValidator(cfg.MinLength, cfg.MaxLength, cfg.Reserved)
	cfg.Store = memory.New()
	return cfg
}
