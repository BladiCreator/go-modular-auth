// Package memory provides an in-process cache.Cache for tests and local
// development. It is not shared between instances: do not use it as a
// distributed cache in production.
//
// Values are JSON encoded on Set and decoded on Get, mimicking the
// serialization boundary of network caches and preventing aliasing bugs.
package memory

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/BladiCreator/go-modular-auth/cache"
)

// ErrInvalidTTL is returned when an entry is written without a positive TTL.
var ErrInvalidTTL = errors.New("cache/memory: ttl must be positive")

type entry struct {
	value     []byte
	counter   int64
	isCounter bool
	expiresAt time.Time
}

// Cache is an in-memory cache with lazy expiration.
type Cache struct {
	mu      sync.Mutex
	entries map[string]entry
	now     func() time.Time
}

var (
	_ cache.Cache   = (*Cache)(nil)
	_ cache.Counter = (*Cache)(nil)
)

// Option configures the memory cache.
type Option func(*Cache)

// WithClock overrides the clock (useful for TTL tests).
func WithClock(now func() time.Time) Option {
	return func(c *Cache) { c.now = now }
}

// New returns an empty memory cache.
func New(opts ...Option) *Cache {
	c := &Cache{entries: map[string]entry{}, now: time.Now}
	for _, o := range opts {
		o(c)
	}
	return c
}

func (c *Cache) live(key string) (entry, bool) {
	e, ok := c.entries[key]
	if !ok {
		return entry{}, false
	}
	if !c.now().Before(e.expiresAt) {
		delete(c.entries, key)
		return entry{}, false
	}
	return e, true
}

// Get decodes the cached value into value or returns cache.ErrMiss.
func (c *Cache) Get(ctx context.Context, key string, value any) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	e, ok := c.live(key)
	c.mu.Unlock()
	if !ok {
		return cache.ErrMiss
	}
	if e.isCounter {
		b, _ := json.Marshal(e.counter)
		return json.Unmarshal(b, value)
	}
	return json.Unmarshal(e.value, value)
}

// Set stores value under key for ttl.
func (c *Cache) Set(ctx context.Context, key string, value any, ttl time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if ttl <= 0 {
		return ErrInvalidTTL
	}
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.entries[key] = entry{value: b, expiresAt: c.now().Add(ttl)}
	c.mu.Unlock()
	return nil
}

// Delete removes key. Deleting a missing key is not an error.
func (c *Cache) Delete(ctx context.Context, key string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	delete(c.entries, key)
	c.mu.Unlock()
	return nil
}

// Increment atomically adds delta to the counter stored at key.
func (c *Cache) Increment(ctx context.Context, key string, delta int64, ttl time.Duration) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if ttl <= 0 {
		return 0, ErrInvalidTTL
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.live(key)
	if !ok || !e.isCounter {
		e = entry{isCounter: true, expiresAt: c.now().Add(ttl)}
	}
	e.counter += delta
	c.entries[key] = e
	return e.counter, nil
}

// Len returns the number of live entries (test helper).
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for k := range c.entries {
		if _, ok := c.live(k); ok {
			n++
		}
	}
	return n
}
