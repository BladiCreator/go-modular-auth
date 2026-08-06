// Package config defines global configuration options and functional option helpers for the Auth engine.
package config

import (
	"github.com/BladiCreator/go-modular-auth/plugin"
	"golang.org/x/crypto/bcrypt"
)

// Config holds the main settings used when constructing an Auth instance.
type Config struct {
	BcryptCost int
	Plugins    []plugin.Plugin
}

// DefaultConfig returns a Config initialized with sensible default values.
func DefaultConfig() Config {
	return Config{
		BcryptCost: bcrypt.DefaultCost,
		Plugins:    []plugin.Plugin{},
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