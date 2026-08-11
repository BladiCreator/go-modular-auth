package plugin

import (
	"sync"

	"github.com/asaskevich/EventBus"
)

// CryptoUtils defines cryptographic utility operations provided to plugins (hashing, comparison, random tokens).
type CryptoUtils interface {
	HashPassword(password string) (string, error)
	ComparePassword(hash, password string) bool
	GenerateRandomToken(length int) (string, error)
}

// Context represents the shared environment provided to plugins upon initialization, containing cryptographic tools, event buses, and a key-value store.
type Context struct {
	crypto CryptoUtils
	events EventBus.Bus
	store  sync.Map
}

// NewContext creates a new Context with the specified cryptographic utilities and event bus.
func NewContext(crypto CryptoUtils, bus EventBus.Bus) *Context {
	return &Context{
		crypto: crypto,
		events: bus,
	}
}

// Crypto returns the cryptographic utilities instance.
func (c *Context) Crypto() CryptoUtils { return c.crypto }

// Events returns the shared EventBus instance for subscribing or publishing plugin lifecycle events.
func (c *Context) Events() EventBus.Bus { return c.events }

// Set stores a key-value pair in the shared thread-safe context store.
func (c *Context) Set(key string, value any) { c.store.Store(key, value) }

// Get retrieves a value from the shared thread-safe context store by key.
func (c *Context) Get(key string) (any, bool) { return c.store.Load(key) }
