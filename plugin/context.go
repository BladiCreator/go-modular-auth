package plugin

import (
	"sync"
)

// CryptoUtils defines cryptographic utility operations provided to plugins (hashing, comparison, random tokens).
type CryptoUtils interface {
	HashPassword(password string) (string, error)
	ComparePassword(hash, password string) bool
	GenerateRandomToken(length int) (string, error)
}

// ContextOption allows configuring optional dependencies into the shared plugin Context.
type ContextOption func(*Context)

// WithPipeline configures a custom Pipeline into the plugin Context.
func WithPipeline(p *Pipeline) ContextOption {
	return func(c *Context) {
		if p != nil {
			c.pipeline = p
		}
	}
}

// WithHooks configures a custom Hooks dispatcher into the plugin Context.
func WithHooks(h *Hooks) ContextOption {
	return func(c *Context) {
		if h != nil {
			c.hooks = h
		}
	}
}

// WithContextSessionManager configures a SessionManager into the plugin Context.
func WithContextSessionManager(sm SessionManager) ContextOption {
	return func(c *Context) {
		c.sessionManager = sm
	}
}

// Context represents the shared environment provided to plugins upon initialization,
// containing cryptographic tools, synchronous execution pipelines, typed lifecycle hooks,
// central session management, and a thread-safe key-value store.
type Context struct {
	crypto         CryptoUtils
	pipeline       *Pipeline
	hooks          *Hooks
	sessionManager SessionManager
	store          sync.Map
}

// NewContext creates a new Context with the specified cryptographic utilities and optional pipeline/hooks.
func NewContext(crypto CryptoUtils, opts ...ContextOption) *Context {
	c := &Context{
		crypto:   crypto,
		pipeline: NewPipeline(),
		hooks:    NewHooks(),
	}
	for _, opt := range opts {
		if opt != nil {
			opt(c)
		}
	}
	return c
}

// Crypto returns the cryptographic utilities instance.
func (c *Context) Crypto() CryptoUtils { return c.crypto }

// Pipeline returns the synchronous interceptor pipeline for authentication operations.
func (c *Context) Pipeline() *Pipeline { return c.pipeline }

// SetPipeline updates the synchronous interceptor pipeline in the shared context.
func (c *Context) SetPipeline(p *Pipeline) { c.pipeline = p }

// Hooks returns the typed lifecycle hooks and event dispatcher.
func (c *Context) Hooks() *Hooks { return c.hooks }

// SetHooks updates the lifecycle hooks instance in the shared context.
func (c *Context) SetHooks(h *Hooks) { c.hooks = h }

// Session returns the central SessionManager instance available in the execution environment.
func (c *Context) Session() SessionManager { return c.sessionManager }

// SessionManager returns the central SessionManager instance (alias for Session).
func (c *Context) SessionManager() SessionManager { return c.sessionManager }

// SetSessionManager configures the central SessionManager instance into the shared context.
func (c *Context) SetSessionManager(sm SessionManager) { c.sessionManager = sm }

// Set stores a key-value pair in the shared thread-safe context store.
func (c *Context) Set(key string, value any) { c.store.Store(key, value) }

// Get retrieves a value from the shared thread-safe context store by key.
func (c *Context) Get(key string) (any, bool) { return c.store.Load(key) }
