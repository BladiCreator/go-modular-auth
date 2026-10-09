// Package redis provides a Redis/Valkey implementation of GoModularAuth cache.Cache
// and cache.Counter.
package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/BladiCreator/go-modular-auth/cache"
)

// Client abstracts the underlying Redis/Valkey client library.
type Client interface {
	Get(ctx context.Context, key string) ([]byte, error)
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error
	Del(ctx context.Context, keys ...string) error
	IncrBy(ctx context.Context, key string, delta int64, ttl time.Duration) (int64, error)
}

// Cache wraps a Client to implement cache.Cache and cache.Counter.
type Cache struct {
	client Client
}

var (
	_ cache.Cache   = (*Cache)(nil)
	_ cache.Counter = (*Cache)(nil)
)

// New creates a new Redis/Valkey cache adapter.
func New(client Client) *Cache {
	return &Cache{client: client}
}

// Get retrieves a key and JSON-unmarshals its value into dest.
func (c *Cache) Get(ctx context.Context, key string, dest any) error {
	if c.client == nil {
		return errors.New("cache/redis: nil client")
	}
	bytes, err := c.client.Get(ctx, key)
	if err != nil {
		if errors.Is(err, cache.ErrMiss) {
			return cache.ErrMiss
		}
		return fmt.Errorf("cache/redis: get failed: %w", err)
	}
	if len(bytes) == 0 {
		return cache.ErrMiss
	}

	if ptr, ok := dest.(*[]byte); ok {
		*ptr = bytes
		return nil
	}
	if ptr, ok := dest.(*string); ok {
		*ptr = string(bytes)
		return nil
	}

	if err := json.Unmarshal(bytes, dest); err != nil {
		return fmt.Errorf("cache/redis: unmarshal failed: %w", err)
	}
	return nil
}

// Set JSON-marshals value and stores it with the provided TTL.
func (c *Cache) Set(ctx context.Context, key string, value any, ttl time.Duration) error {
	if c.client == nil {
		return errors.New("cache/redis: nil client")
	}
	if ttl <= 0 {
		return errors.New("cache/redis: ttl must be positive")
	}

	var bytes []byte
	switch v := value.(type) {
	case []byte:
		bytes = v
	case string:
		bytes = []byte(v)
	default:
		var err error
		bytes, err = json.Marshal(value)
		if err != nil {
			return fmt.Errorf("cache/redis: marshal failed: %w", err)
		}
	}

	return c.client.Set(ctx, key, bytes, ttl)
}

// Delete removes a key.
func (c *Cache) Delete(ctx context.Context, key string) error {
	if c.client == nil {
		return errors.New("cache/redis: nil client")
	}
	return c.client.Del(ctx, key)
}

// Increment adds delta to key with ttl, implementing cache.Counter.
func (c *Cache) Increment(ctx context.Context, key string, delta int64, ttl time.Duration) (int64, error) {
	if c.client == nil {
		return 0, errors.New("cache/redis: nil client")
	}
	return c.client.IncrBy(ctx, key, delta, ttl)
}
