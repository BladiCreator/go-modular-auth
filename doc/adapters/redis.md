# Redis Cache Adapter

The **Redis Adapter** (`adapters/redis`) implements both `cache.Cache` and `cache.Counter` for distributed caching, ephemeral state, and distributed rate limiting.

---

## Installation

```bash
go get github.com/BladiCreator/go-modular-auth/adapters/redis
```

Recommended client library:
- `github.com/redis/go-redis/v9`

---

## Quickstart

```go
package main

import (
    "context"
    "time"

    auth "github.com/BladiCreator/go-modular-auth"
    "github.com/BladiCreator/go-modular-auth/adapters/redis"
    goredis "github.com/redis/go-redis/v9"
)

// redisWrapper bridges go-redis to the redis.Client interface
type redisWrapper struct {
    client *goredis.Client
}

func (w *redisWrapper) Get(ctx context.Context, key string) ([]byte, error) {
    return w.client.Get(ctx, key).Bytes()
}

func (w *redisWrapper) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
    return w.client.Set(ctx, key, value, ttl).Err()
}

func (w *redisWrapper) Del(ctx context.Context, keys ...string) error {
    return w.client.Del(ctx, keys...).Err()
}

func (w *redisWrapper) IncrBy(ctx context.Context, key string, delta int64, ttl time.Duration) (int64, error) {
    val, err := w.client.IncrBy(ctx, key, delta).Result()
    if err == nil {
        w.client.Expire(ctx, key, ttl)
    }
    return val, err
}

func main() {
    rdb := goredis.NewClient(&goredis.Options{
        Addr:     "localhost:6379",
        Password: "",
        DB:       0,
    })

    // Instantiate Redis Cache Adapter
    cacheAdapter := redis.New(&redisWrapper{client: rdb})

    engine, err := auth.New(auth.Config{
        Store: myStore,
        Cache: cacheAdapter, // Injects Redis into sessionCache and userCache
    })
    if err != nil {
        panic(err)
    }

    _ = engine
}
```

---

## Features

1. **Automatic JSON Serialization**: Transparently marshals and unmarshals cached domain objects (`User`, `Session`).
2. **Fixed-Window Distributed Counters**: Implements `cache.Counter` for plugins such as `rate-limit`.
3. **Graceful Degradation**: If Redis experiences an outage, `engine.GetSession` logs the incident and transparently falls back to querying the database Store.
