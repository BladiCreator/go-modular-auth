# Cache Adapter (Performance & Ephemeral State)

## 1. Principles of the Cache Adapter

The **Cache Adapter** is an optional acceleration layer designed to minimize read latency on high-throughput authentication paths.

- **Non-Authoritative**: The cache is never the source of truth. If the cache is omitted, unpopulated, or offline, GoModularAuth continues to operate seamlessly by querying the Store directly.
- **Cache-Aside Pattern**: Reads query the cache first; on a cache miss, the core reads from the Store and populates the cache.
- **Post-Commit Invalidation**: Mutations and revocations update the Store first. Upon transaction commit, the cache entries are evicted or updated.
- **Bounded TTL**: Cache TTLs are strictly bounded by the entity's remaining lifetime: `effectiveTTL = min(Config.CacheTTL, remaining entity lifetime)`.
- **Hashed Keys**: Plaintext secrets or raw bearer tokens are **never** used as cache keys. Keys are derived from SHA-256 hashes.

---

## 2. Contracts: `cache.Cache` & `cache.Counter`

```go
package cache

type Cache interface {
    Get(ctx context.Context, key string, dest any) error
    Set(ctx context.Context, key string, value any, ttl time.Duration) error
    Delete(ctx context.Context, key string) error
}

type Counter interface {
    Increment(ctx context.Context, key string, delta int64, ttl time.Duration) (int64, error)
}
```

### 2.1 Namespacing Helper
All keys written by the engine use the root prefix `gomodularauth:`:

```go
// Returns "gomodularauth:session:<hash>"
key := cache.Key("session", tokenHash)

// Plugins namespace their own entries
key := cache.Key("organizations", "member", orgID, userID)
```

---

## 3. Semantic Caches

GoModularAuth wraps the generic `cache.Cache` in type-safe semantic wrappers:

- **`SessionCache` (`cache.NewSessionCache`)**:
  Caches active `session.Session` records indexed by token hash. When a session is revoked or signed out, `a.invalidateSessions()` evicts the session from cache immediately.
- **`UserCache` (`cache.NewUserCache`)**:
  Caches `user.User` domain records indexed by User ID.

---

## 4. Official Cache Adapters

### 4.1 Redis Adapter (`adapters/redis`)
Compatible with Redis clients such as `github.com/redis/go-redis/v9`:

```go
package main

import (
    "context"
    "time"

    "github.com/BladiCreator/go-modular-auth/adapters/redis"
    goredis "github.com/redis/go-redis/v9"
)

type redisClientWrapper struct {
    rdb *goredis.Client
}

func (w *redisClientWrapper) Get(ctx context.Context, key string) ([]byte, error) {
    return w.rdb.Get(ctx, key).Bytes()
}

func (w *redisClientWrapper) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
    return w.rdb.Set(ctx, key, value, ttl).Err()
}

func (w *redisClientWrapper) Del(ctx context.Context, keys ...string) error {
    return w.rdb.Del(ctx, keys...).Err()
}

func (w *redisClientWrapper) IncrBy(ctx context.Context, key string, delta int64, ttl time.Duration) (int64, error) {
    val, err := w.rdb.IncrBy(ctx, key, delta).Result()
    if err == nil {
        w.rdb.Expire(ctx, key, ttl)
    }
    return val, err
}

func NewRedisCache(rdb *goredis.Client) *redis.Cache {
    return redis.New(&redisClientWrapper{rdb: rdb})
}
```

### 4.2 Valkey Adapter (`adapters/valkey`)
Valkey is a high-performance open-source fork of Redis:

```go
import "github.com/BladiCreator/go-modular-auth/adapters/valkey"

cacheAdapter := valkey.New(clientWrapper)
```

### 4.3 In-Memory Cache (`adapters/memory`)
Thread-safe in-memory cache featuring automatic TTL expiration and atomic counter increments:

```go
import "github.com/BladiCreator/go-modular-auth/adapters/memory"

cacheAdapter := memory.NewCache()
```
