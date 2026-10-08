package multisession

import (
	"time"

	"github.com/BladiCreator/go-modular-auth-multisession/store"
	"github.com/BladiCreator/go-modular-auth-multisession/store/memory"
)

// OverflowPolicy defines the action taken when a user exceeds MaxConcurrentSessions.
type OverflowPolicy string

const (
	// OverflowRevokeOldest automatically revokes the user's oldest active session(s)
	// to make room for the newly requested session (FIFO eviction).
	OverflowRevokeOldest OverflowPolicy = "revoke_oldest"

	// OverflowReject rejects the new session creation request by returning
	// ErrMaxConcurrentSessionsReached.
	OverflowReject OverflowPolicy = "reject"
)

// Config holds configuration parameters for the multisession plugin.
type Config struct {
	// MaxConcurrentSessions sets the maximum concurrent active sessions per user.
	// 0 or negative value disables concurrency limiting.
	MaxConcurrentSessions int

	// OverflowPolicy controls what happens when the session concurrency limit is exceeded.
	OverflowPolicy OverflowPolicy

	// MetadataStore is the persistence adapter for optional session and device metadata.
	// If nil, defaults to an in-memory store.
	MetadataStore store.Store

	// MetadataCacheTTL controls how long session metadata is cached.
	MetadataCacheTTL time.Duration
}

// Option configures the multisession plugin.
type Option func(*Config)

// WithMaxConcurrentSessions configures the concurrent session limit and optional overflow policy.
func WithMaxConcurrentSessions(limit int, policy ...OverflowPolicy) Option {
	return func(c *Config) {
		c.MaxConcurrentSessions = limit
		if len(policy) > 0 {
			c.OverflowPolicy = policy[0]
		}
	}
}

// WithOverflowPolicy sets the strategy when MaxConcurrentSessions is exceeded.
func WithOverflowPolicy(policy OverflowPolicy) Option {
	return func(c *Config) {
		if policy == OverflowRevokeOldest || policy == OverflowReject {
			c.OverflowPolicy = policy
		}
	}
}

// WithMetadataStore sets the persistence adapter for session metadata.
func WithMetadataStore(s store.Store) Option {
	return func(c *Config) {
		if s != nil {
			c.MetadataStore = s
		}
	}
}

// WithMetadataCacheTTL sets the cache duration for session metadata.
func WithMetadataCacheTTL(ttl time.Duration) Option {
	return func(c *Config) {
		if ttl > 0 {
			c.MetadataCacheTTL = ttl
		}
	}
}

func defaultConfig() Config {
	return Config{
		MaxConcurrentSessions: 0, // Concurrency limit disabled by default
		OverflowPolicy:        OverflowRevokeOldest,
		MetadataStore:         memory.New(),
		MetadataCacheTTL:      10 * time.Minute,
	}
}
