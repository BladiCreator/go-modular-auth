package config

import (
	"log/slog"

	"github.com/BladiCreator/go-modular-auth/domain/repository"
	"github.com/BladiCreator/go-modular-auth/plugin"
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

// WithInterceptor registers one or more structured or functional interceptors into the Auth engine pipeline.
func WithInterceptor(interceptors ...any) Option {
	return func(c *Config) {
		for _, it := range interceptors {
			if it != nil {
				c.Interceptors = append(c.Interceptors, it)
			}
		}
	}
}

// WithBeforeSignIn registers functional interceptors executed before user sign-in.
func WithBeforeSignIn(fns ...plugin.BeforeSignInFunc) Option {
	return func(c *Config) {
		for _, fn := range fns {
			if fn != nil {
				c.Interceptors = append(c.Interceptors, fn)
			}
		}
	}
}

// WithAfterSignIn registers functional interceptors executed after successful user sign-in.
func WithAfterSignIn(fns ...plugin.AfterSignInFunc) Option {
	return func(c *Config) {
		for _, fn := range fns {
			if fn != nil {
				c.Interceptors = append(c.Interceptors, fn)
			}
		}
	}
}

// WithBeforeSignUp registers functional interceptors executed before user registration.
func WithBeforeSignUp(fns ...plugin.BeforeSignUpFunc) Option {
	return func(c *Config) {
		for _, fn := range fns {
			if fn != nil {
				c.Interceptors = append(c.Interceptors, fn)
			}
		}
	}
}

// WithAfterSignUp registers functional interceptors executed after user registration.
func WithAfterSignUp(fns ...plugin.AfterSignUpFunc) Option {
	return func(c *Config) {
		for _, fn := range fns {
			if fn != nil {
				c.Interceptors = append(c.Interceptors, fn)
			}
		}
	}
}

// WithBeforeCreateSession registers functional interceptors executed before session creation.
func WithBeforeCreateSession(fns ...plugin.BeforeCreateSessionFunc) Option {
	return func(c *Config) {
		for _, fn := range fns {
			if fn != nil {
				c.Interceptors = append(c.Interceptors, fn)
			}
		}
	}
}

// WithAfterCreateSession registers functional interceptors executed after session creation.
func WithAfterCreateSession(fns ...plugin.AfterCreateSessionFunc) Option {
	return func(c *Config) {
		for _, fn := range fns {
			if fn != nil {
				c.Interceptors = append(c.Interceptors, fn)
			}
		}
	}
}

// WithHooks configures a custom lifecycle hooks instance into the Auth engine.
func WithHooks(hooks *plugin.Hooks) Option {
	return func(c *Config) {
		c.Hooks = hooks
	}
}

// WithAsyncHooks toggles whether lifecycle hooks are dispatched asynchronously.
func WithAsyncHooks(async bool) Option {
	return func(c *Config) {
		c.AsyncHooks = async
	}
}

// WithLogger sets a structured slog.Logger for the Auth engine and plugins.
// If nil is passed, a discard logger is used to prevent nil pointer panics.
func WithLogger(logger *slog.Logger) Option {
	return func(c *Config) {
		if logger == nil {
			c.Logger = slog.New(slog.DiscardHandler)
			return
		}
		c.Logger = logger
	}
}
