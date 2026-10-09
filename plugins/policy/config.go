package policy

import (
	"time"

	"github.com/BladiCreator/go-modular-auth-policy/cache"
	"github.com/BladiCreator/go-modular-auth-policy/store"
	"github.com/BladiCreator/go-modular-auth-policy/store/memory"
)

// CombinatorType defines the root policy composition algorithm.
type CombinatorType string

const (
	CombinatorDenyOverrides CombinatorType = "deny_overrides"
	CombinatorAllOf         CombinatorType = "all_of"
	CombinatorAnyOf         CombinatorType = "any_of"
)

// Config holds configuration parameters for the policy plugin.
type Config struct {
	Store           store.Store
	Cache           cache.Cache
	CacheTTL        time.Duration
	Combinator      CombinatorType
	InitialPolicies []Evaluator
	Clock           func() time.Time
}

// Option configures a policy plugin instance.
type Option func(*Config)

// WithStore sets an explicit store for policy metadata persistence.
func WithStore(s store.Store) Option {
	return func(c *Config) {
		c.Store = s
	}
}

// WithCache sets an explicit cache implementation for derived decisions.
func WithCache(cacheImpl cache.Cache) Option {
	return func(c *Config) {
		c.Cache = cacheImpl
	}
}

// WithCacheTTL sets the time-to-live for cached evaluation decisions.
func WithCacheTTL(ttl time.Duration) Option {
	return func(c *Config) {
		c.CacheTTL = ttl
	}
}

// WithCombinator configures the top-level composition combination algorithm.
func WithCombinator(comb CombinatorType) Option {
	return func(c *Config) {
		c.Combinator = comb
	}
}

// WithInitialPolicies registers baseline policies at initialization.
func WithInitialPolicies(policies ...Evaluator) Option {
	return func(c *Config) {
		c.InitialPolicies = append(c.InitialPolicies, policies...)
	}
}

// WithClock sets a custom clock provider.
func WithClock(clock func() time.Time) Option {
	return func(c *Config) {
		c.Clock = clock
	}
}

func defaultConfig() Config {
	return Config{
		Store:      memory.NewStore(),
		CacheTTL:   5 * time.Minute,
		Combinator: CombinatorDenyOverrides,
		Clock:      time.Now,
	}
}
