package ott

import (
	"time"

	"github.com/BladiCreator/go-modular-auth/verification"
)

// DefaultPurpose is the default verification purpose for one-time tokens.
const DefaultPurpose verification.Purpose = "ott:token"

// Config defines the configuration for the one-time token plugin.
type Config struct {
	DefaultTTL time.Duration
	Purpose    verification.Purpose
}

// Option modifies Config.
type Option func(*Config)

// WithTTL sets the default TTL for issued tokens.
func WithTTL(ttl time.Duration) Option {
	return func(c *Config) {
		c.DefaultTTL = ttl
	}
}

// WithPurpose sets the default verification purpose for tokens.
func WithPurpose(p verification.Purpose) Option {
	return func(c *Config) {
		c.Purpose = p
	}
}

func (c Config) withDefaults() Config {
	if c.DefaultTTL <= 0 {
		c.DefaultTTL = 10 * time.Minute
	}
	if c.Purpose == "" {
		c.Purpose = DefaultPurpose
	}
	return c
}
