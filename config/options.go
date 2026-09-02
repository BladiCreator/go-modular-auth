package config

import (
	"github.com/BladiCreator/go-modular-auth/domain/repository"
)

// WithSessionRepository configures the persistent storage repository for authentication sessions.
func WithSessionRepository(repo repository.SessionRepository) Option {
	return func(c *Config) {
		c.SessionRepository = repo
	}
}

// WithSessionConfig sets custom session lifetime and behavioral configuration.
func WithSessionConfig(cfg SessionConfig) Option {
	return func(c *Config) {
		c.SessionConfig = cfg
	}
}
