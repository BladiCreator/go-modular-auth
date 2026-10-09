package audit

import (
	"context"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	"github.com/BladiCreator/go-modular-auth-audit/store"
	"github.com/BladiCreator/go-modular-auth-audit/store/memory"
)

// EventFilter is a predicate function to decide if an event should be audited.
// Returns true to audit, false to drop.
type EventFilter func(ev auth.Event) bool

// OrgResolver extracts an organization ID from context or event payload.
type OrgResolver func(ctx context.Context, ev auth.Event) string

// Config holds settings for the audit plugin.
type Config struct {
	Store         store.Store
	Filter        EventFilter
	AsyncWorkers  int
	BufferSize    int
	BatchSize     int
	FlushInterval time.Duration
	OrgResolver   OrgResolver
}

func defaultConfig() Config {
	return Config{
		Store:         memory.New(),
		AsyncWorkers:  0, // synchronous by default for immediate consistency
		BufferSize:    1024,
		BatchSize:     50,
		FlushInterval: 250 * time.Millisecond,
	}
}

// Option configures audit plugin behavior.
type Option func(*Config)

// WithStore sets the underlying persistence adapter for audit logs.
func WithStore(s store.Store) Option {
	return func(c *Config) {
		if s != nil {
			c.Store = s
		}
	}
}

// WithFilter configures a predicate to selectively filter out events from being audited.
func WithFilter(f EventFilter) Option {
	return func(c *Config) {
		c.Filter = f
	}
}

// WithAsync enables asynchronous background worker processing for non-blocking audit logging.
func WithAsync(workers, bufferSize, batchSize int, flushInterval time.Duration) Option {
	return func(c *Config) {
		if workers > 0 {
			c.AsyncWorkers = workers
		}
		if bufferSize > 0 {
			c.BufferSize = bufferSize
		}
		if batchSize > 0 {
			c.BatchSize = batchSize
		}
		if flushInterval > 0 {
			c.FlushInterval = flushInterval
		}
	}
}

// WithOrgResolver configures a custom organization ID extractor for tenant scoping.
func WithOrgResolver(resolver OrgResolver) Option {
	return func(c *Config) {
		c.OrgResolver = resolver
	}
}
