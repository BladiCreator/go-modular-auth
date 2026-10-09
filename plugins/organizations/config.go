package organizations

import (
	"time"

	"github.com/BladiCreator/go-modular-auth-organizations/store"
	"github.com/BladiCreator/go-modular-auth-organizations/store/memory"
)

// Default configurations.
const (
	DefaultCacheTTL      = 5 * time.Minute
	DefaultInvitationTTL = 7 * 24 * time.Hour // 7 days
)

// Config configures the organizations plugin module.
type Config struct {
	// Store provides persistence for organizations, members, teams, and invitations.
	// If nil, defaults to an in-memory store.
	Store store.Store

	// CacheTTL controls how long organizations and memberships are cached.
	// Defaults to 5 minutes. If non-positive, caching is disabled.
	CacheTTL time.Duration

	// DefaultInvitationTTL sets the duration an invitation remains valid.
	// Defaults to 7 days.
	DefaultInvitationTTL time.Duration
}

func defaultConfig() Config {
	return Config{
		Store:                memory.New(),
		CacheTTL:             DefaultCacheTTL,
		DefaultInvitationTTL: DefaultInvitationTTL,
	}
}

// Option configures a Config.
type Option func(*Config)

// WithStore sets the persistence store adapter.
func WithStore(s store.Store) Option {
	return func(c *Config) {
		if s != nil {
			c.Store = s
		}
	}
}

// WithCacheTTL configures the caching TTL duration for organizations and memberships.
func WithCacheTTL(ttl time.Duration) Option {
	return func(c *Config) {
		c.CacheTTL = ttl
	}
}

// WithDefaultInvitationTTL sets the default validity duration for newly created invitations.
func WithDefaultInvitationTTL(ttl time.Duration) Option {
	return func(c *Config) {
		if ttl > 0 {
			c.DefaultInvitationTTL = ttl
		}
	}
}
