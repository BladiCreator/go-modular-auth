// Package cache defines the Cache Adapter contracts of GoModularAuth.
//
// Store = source of truth. Cache = performance / ephemeral state.
//
// A cache is always optional: the core works identically without one and
// degrades to the Store when the cache fails. Every entry must carry an
// explicit TTL, keys must be namespaced (see Key) and secrets must never be
// used as keys: derive keys from hashes instead.
package cache

import (
	"context"
	"errors"
	"strings"
	"time"
)

// ErrMiss is returned by Cache.Get when the key does not exist or expired.
var ErrMiss = errors.New("cache: miss")

// Namespace is the root prefix of every key written by GoModularAuth.
const Namespace = "gomodularauth"

// Cache is the generic infrastructure contract implemented by cache adapters
// (memory, Redis, Valkey, Memcached, ...).
//
// Implementations serialize values; Get decodes into the pointer value.
// ttl must be > 0: entries without expiration are not allowed.
type Cache interface {
	Get(ctx context.Context, key string, value any) error
	Set(ctx context.Context, key string, value any, ttl time.Duration) error
	Delete(ctx context.Context, key string) error
}

// Counter is an optional capability for atomic counters (e.g. distributed
// rate limiting). Increment adds delta to key, creating it with ttl when it
// does not exist, and returns the new value. The ttl is not refreshed by
// subsequent increments (fixed window semantics).
type Counter interface {
	Increment(ctx context.Context, key string, delta int64, ttl time.Duration) (int64, error)
}

// Key builds a namespaced key: Key("session", h) => "gomodularauth:session:<h>".
// Plugins must use their own segment: Key("organizations", "member", org, user).
func Key(parts ...string) string {
	return Namespace + ":" + strings.Join(parts, ":")
}
