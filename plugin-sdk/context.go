package sdk

import (
	"context"
	"log/slog"
	"sync"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	"github.com/BladiCreator/go-modular-auth/adapter"
	"github.com/BladiCreator/go-modular-auth/cache"
	"github.com/BladiCreator/go-modular-auth/email"
	"github.com/BladiCreator/go-modular-auth/schema"
	"github.com/BladiCreator/go-modular-auth/store"
)

// Context provides the host runtime environment and services to a plugin module.
// It acts as the isolation boundary so plugins only interact with public
// infrastructure contracts and never private core internals.
type Context struct {
	host    *auth.Host
	adapter adapter.Adapter
	cache   cache.Cache
	email   email.Sender
	mu      sync.RWMutex
	values  map[string]any
}

// NewContext creates a new plugin context wrapping the host runtime.
func NewContext(host *auth.Host) *Context {
	return &Context{
		host:   host,
		values: make(map[string]any),
	}
}

// NewTestContext creates a standalone test Context with injected adapters.
func NewTestContext(ad adapter.Adapter, c cache.Cache, em email.Sender) *Context {
	return &Context{
		adapter: ad,
		cache:   c,
		email:   em,
		values:  make(map[string]any),
	}
}

// Host returns the underlying core Host instance.
func (c *Context) Host() *auth.Host {
	return c.host
}

// ModuleID returns the ID of the plugin module.
func (c *Context) ModuleID() string {
	if c.host == nil {
		return ""
	}
	return c.host.ModuleID()
}

// Core returns the Auth engine instance.
func (c *Context) Core() *auth.Auth {
	if c.host == nil {
		return nil
	}
	return c.host.Auth()
}

// Store returns the core store (bridged from adapter when necessary).
func (c *Context) Store() store.Store {
	if c.host == nil || c.host.Auth() == nil {
		return nil
	}
	return c.host.Auth().Store()
}

// Adapter returns the generic schema-driven storage adapter, or nil if none is configured.
func (c *Context) Adapter() adapter.Adapter {
	if c.adapter != nil {
		return c.adapter
	}
	if c.host == nil {
		return nil
	}
	return c.host.Adapter()
}

// Schema returns the compiled database schema, or nil if none is active.
func (c *Context) Schema() *schema.Schema {
	if c.host == nil {
		return nil
	}
	return c.host.Schema()
}

// DB returns the typed database access facade.
func (c *Context) DB() *DB {
	return &DB{adapter: c.Adapter()}
}

// Cache returns the shared cache adapter, or nil when none is configured.
// Plugins must namespace their cache keys.
func (c *Context) Cache() cache.Cache {
	if c.cache != nil {
		return c.cache
	}
	if c.host == nil {
		return nil
	}
	return c.host.Cache()
}

// Email returns the transactional email sender, or nil when none is configured.
func (c *Context) Email() email.Sender {
	if c.email != nil {
		return c.email
	}
	if c.host == nil {
		return nil
	}
	return c.host.Email()
}

// Hooks returns the workflow hooks registry for intercepting auth workflows.
func (c *Context) Hooks() *auth.Hooks {
	if c.host == nil {
		return nil
	}
	return c.host.Hooks()
}

// Events returns the event dispatcher for subscribing to or emitting events.
func (c *Context) Events() *auth.Events {
	if c.host == nil {
		return nil
	}
	return c.host.Events()
}

// Logger returns a structured logger scoped and tagged with the module ID.
func (c *Context) Logger() *slog.Logger {
	if c.host == nil {
		return slog.Default()
	}
	return c.host.Logger()
}

// Now returns the current time according to the host clock.
func (c *Context) Now() time.Time {
	if c.host == nil {
		return time.Now()
	}
	return c.host.Now()
}

// Set stores a key-value pair in the contextual execution bag.
// It is safe for concurrent use.
func (c *Context) Set(key string, val any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.values == nil {
		c.values = make(map[string]any)
	}
	c.values[key] = val
}

// Get retrieves a value by key from the contextual execution bag.
// It is safe for concurrent use.
func (c *Context) Get(key string) (any, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	v, ok := c.values[key]
	return v, ok
}

// StandardContext returns a background context.Context.
func (c *Context) StandardContext() context.Context {
	return context.Background()
}
