// Package valkey provides a Valkey implementation of GoModularAuth cache.Cache
// and cache.Counter. Valkey is a high-performance, open-source continuation of Redis.
package valkey

import (
	"github.com/BladiCreator/go-modular-auth/adapters/redis"
	"github.com/BladiCreator/go-modular-auth/cache"
)

// Client abstracts the underlying Valkey client library.
type Client = redis.Client

// Cache implements cache.Cache and cache.Counter for Valkey.
type Cache = redis.Cache

var (
	_ cache.Cache   = (*Cache)(nil)
	_ cache.Counter = (*Cache)(nil)
)

// New creates a new Valkey cache adapter.
func New(client Client) *Cache {
	return redis.New(client)
}
