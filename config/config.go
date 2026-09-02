// Package config defines global configuration options and functional option helpers for the Auth engine.
package config

import (
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/repository"
	"github.com/BladiCreator/go-modular-auth/plugin"
	"golang.org/x/crypto/bcrypt"
)

// SessionConfig defines session lifetime, renewal, and cookie configuration.
type SessionConfig struct {
	// DefaultDuration specifies the standard validity lifetime for issued sessions (default: 24h).
	DefaultDuration time.Duration
	// RememberMeDuration specifies the extended validity lifetime when RememberMe is requested (default: 30 days).
	RememberMeDuration time.Duration
	// CookieName specifies the session cookie identifier (default: "auth_session").
	CookieName string
}

// DefaultSessionConfig returns sensible default session settings (24h default, 30-day remember me).
func DefaultSessionConfig() SessionConfig {
	return SessionConfig{
		DefaultDuration:    24 * time.Hour,
		RememberMeDuration: 30 * 24 * time.Hour,
		CookieName:         "auth_session",
	}
}

// Config holds the main settings used when constructing an Auth instance.
type Config struct {
	BcryptCost        int
	Plugins           []plugin.Plugin
	SessionRepository repository.SessionRepository
	SessionConfig     SessionConfig
}

// DefaultConfig returns a Config initialized with sensible default values.
func DefaultConfig() Config {
	return Config{
		BcryptCost:    bcrypt.DefaultCost,
		Plugins:       []plugin.Plugin{},
		SessionConfig: DefaultSessionConfig(),
	}
}

// Option represents a functional configuration option for Auth.
type Option func(*Config)

// WithBcryptCost sets a custom bcrypt cost for password hashing.
func WithBcryptCost(cost int) Option {
	return func(c *Config) { c.BcryptCost = cost }
}

// WithPlugins registers one or more modular authentication plugins into the Auth engine.
func WithPlugins(plugins ...plugin.Plugin) Option {
	return func(c *Config) { c.Plugins = append(c.Plugins, plugins...) }
}
