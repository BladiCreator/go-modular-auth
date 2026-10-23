package ratelimit

import (
	"time"
)

// Config defines the configuration options for the rate-limit plugin.
type Config struct {
	Policies        map[string]Policy
	DefaultFailMode FailMode
	AutoHooks       bool
	Clock           func() time.Time
}

func defaultConfig() Config {
	cfg := Config{
		Policies:        make(map[string]Policy),
		DefaultFailMode: FailOpen,
		AutoHooks:       true,
		Clock:           time.Now,
	}

	// Standard out-of-the-box production defaults
	cfg.registerDefault(Policy{
		Action:    ActionSignIn,
		Algorithm: AlgorithmSlidingWindow,
		Limit:     5,
		Window:    1 * time.Minute,
		KeyType:   KeyTypeComposite,
		FailMode:  FailOpen,
	})

	cfg.registerDefault(Policy{
		Action:    ActionSignUp,
		Algorithm: AlgorithmSlidingWindow,
		Limit:     5,
		Window:    10 * time.Minute,
		KeyType:   KeyTypeIP,
		FailMode:  FailOpen,
	})

	cfg.registerDefault(Policy{
		Action:    ActionPasswordReset,
		Algorithm: AlgorithmSlidingWindow,
		Limit:     3,
		Window:    15 * time.Minute,
		KeyType:   KeyTypeIdentity,
		FailMode:  FailOpen,
	})

	cfg.registerDefault(Policy{
		Action:    ActionEmailOTP,
		Algorithm: AlgorithmSlidingWindow,
		Limit:     3,
		Window:    5 * time.Minute,
		KeyType:   KeyTypeIdentity,
		FailMode:  FailOpen,
	})

	cfg.registerDefault(Policy{
		Action:    ActionMagicLink,
		Algorithm: AlgorithmSlidingWindow,
		Limit:     3,
		Window:    15 * time.Minute,
		KeyType:   KeyTypeIdentity,
		FailMode:  FailOpen,
	})

	cfg.registerDefault(Policy{
		Action:    ActionPhoneOTP,
		Algorithm: AlgorithmSlidingWindow,
		Limit:     3,
		Window:    5 * time.Minute,
		KeyType:   KeyTypeIdentity,
		FailMode:  FailOpen,
	})

	cfg.registerDefault(Policy{
		Action:    ActionAccountRecovery,
		Algorithm: AlgorithmSlidingWindow,
		Limit:     2,
		Window:    1 * time.Hour,
		KeyType:   KeyTypeIdentity,
		FailMode:  FailOpen,
	})

	cfg.registerDefault(Policy{
		Action:     ActionAPIKey,
		Algorithm:  AlgorithmTokenBucket,
		Capacity:   100,
		RefillRate: 50.0, // 50 tokens per second
		KeyType:    KeyTypeIdentity,
		FailMode:   FailOpen,
	})

	cfg.registerDefault(Policy{
		Action:    ActionAdmin,
		Algorithm: AlgorithmSlidingWindow,
		Limit:     30,
		Window:    1 * time.Minute,
		KeyType:   KeyTypeIdentity,
		FailMode:  FailOpen,
	})

	return cfg
}

func (c *Config) registerDefault(p Policy) {
	c.Policies[p.Action] = p
}

// Option modifies Config settings.
type Option func(*Config)

// WithPolicy sets or overrides a rate limiting policy for an action.
func WithPolicy(p Policy) Option {
	return func(c *Config) {
		if c.Policies == nil {
			c.Policies = make(map[string]Policy)
		}
		c.Policies[p.Action] = p
	}
}

// WithDefaultFailMode configures whether throttling fails open or closed when the cache is down.
func WithDefaultFailMode(m FailMode) Option {
	return func(c *Config) {
		c.DefaultFailMode = m
	}
}

// WithAutoHooks enables or disables automated Core workflow interception (BeforeSignIn / BeforeSignUp).
func WithAutoHooks(enabled bool) Option {
	return func(c *Config) {
		c.AutoHooks = enabled
	}
}

// WithClock overrides the system clock (useful in deterministic testing).
func WithClock(clk func() time.Time) Option {
	return func(c *Config) {
		if clk != nil {
			c.Clock = clk
		}
	}
}
