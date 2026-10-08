package sdk

import (
	"context"
	"log/slog"
	"time"
)

// Context provides the host runtime environment and services to a plugin module.
type Context struct {
	module string
	logger *slog.Logger
	now    func() time.Time
	values map[string]any
}

// NewContext creates a new plugin context for a module.
func NewContext(module string, logger *slog.Logger, now func() time.Time) *Context {
	if logger == nil {
		logger = slog.Default()
	}
	if now == nil {
		now = time.Now
	}
	return &Context{
		module: module,
		logger: logger.With("plugin", module),
		now:    now,
		values: make(map[string]any),
	}
}

// ModuleID returns the ID of the plugin module.
func (c *Context) ModuleID() string {
	return c.module
}

// Logger returns the logger scoped to this plugin module.
func (c *Context) Logger() *slog.Logger {
	return c.logger
}

// Now returns the current time from the host clock.
func (c *Context) Now() time.Time {
	return c.now()
}

// Set stores a key-value pair in the context.
func (c *Context) Set(key string, val any) {
	c.values[key] = val
}

// Get retrieves a value by key from the context.
func (c *Context) Get(key string) (any, bool) {
	v, ok := c.values[key]
	return v, ok
}

// StandardContext returns a background context.Context.
func (c *Context) StandardContext() context.Context {
	return context.Background()
}
