# Cache Adapter (Performance & Ephemeral State)

## 1. Principles of the Cache Adapter

The **Cache Adapter** provides optional, non-authoritative acceleration:

- **Store = Source of Truth**: The cache is purely a performance optimization. Data loss in the cache must not corrupt or compromise the system.
- **Cache is Optional**: If `Config.Cache` is omitted (`nil`), GoModularAuth functions completely and queries the Store directly.
- **Fail-Open Resilience**: If the cache backend (e.g. Redis/Valkey cluster) crashes or encounters network timeouts, the core logs a warning and degrades seamlessly to the Store without failing requests.
- **Never Store Secrets Directly**: Plaintext tokens or raw passwords are never cached or used as cache keys. Only SHA-256 token hashes are used as keys.

---

## 2. Infrastructure Contract: `cache.Cache`

```go
type Cache interface {
    Get(ctx context.Context, key string, value any) error
    Set(ctx context.Context, key string, value any, ttl time.Duration) error
    Delete(ctx context.Context, key string) error
}
```

### Key Rules for Implementations
1. **Mandatory TTL**: `Set` must enforce `ttl > 0`. Entries without expiration are forbidden to prevent memory leaks and infinite stale data.
2. **Serialization Boundary**: Implementations should serialize values (e.g. JSON or MessagePack) to emulate distributed cache semantics and prevent struct reference aliasing.
3. **Miss Sentinel**: When a key does not exist or has expired, `Get` must return `cache.ErrMiss`.

---

## 3. Semantic Caches

Rather than spreading raw string keys throughout the codebase, GoModularAuth wraps `cache.Cache` with semantic interfaces:

### 3.1 `SessionCache`
```go
type SessionCache interface {
    Get(ctx context.Context, tokenHash string) (*session.Session, error)
    Set(ctx context.Context, s *session.Session, ttl time.Duration) error
    Delete(ctx context.Context, tokenHash string) error
}
```
Constructed via `cache.NewSessionCache(c)`. Keys follow `gomodularauth:session:<tokenHash>`.

### 3.2 `UserCache`
```go
type UserCache interface {
    Get(ctx context.Context, id string) (*user.User, error)
    Set(ctx context.Context, u *user.User, ttl time.Duration) error
    Delete(ctx context.Context, id string) error
}
```
Constructed via `cache.NewUserCache(c)`. Keys follow `gomodularauth:user:<id>`.

---

## 4. Cache-Aside and Invalidation Flow

### Read Path (`GetSession`, `GetUser`)
1. Derive key from SHA-256 hash or user ID.
2. Query `cache.Get`.
3. If **HIT**: Return cached entity immediately.
4. If **MISS** (or cache error):
   - Query authoritative Store.
   - If found and active: Calculate `min(Config.CacheTTL, remainingEntityLifetime)`.
   - Call `cache.Set` with calculated TTL.
   - Return entity.

### Write / Invalidation Path
1. Execute database mutation inside `Store.Transaction(...)`.
2. Commit database transaction.
3. **Post-Commit Invalidation**: Explicitly invoke `cache.Delete` for modified or revoked entities.

> **Important**: Cache invalidation occurs **after** the database commit. It is never included as part of an ACID database transaction.

---

## 5. Distributed Counters (`cache.Counter`)

Plugins like **Rate Limiting** can optionally take advantage of `cache.Counter`:

```go
type Counter interface {
    Increment(ctx context.Context, key string, delta int64, ttl time.Duration) (int64, error)
}
```
- Implements fixed-window counters.
- If the key does not exist, it is initialized with `delta` and bound to `ttl`.
- Supported out-of-the-box by `cache/memory` and standard Redis/Valkey adapters via atomic `INCRBY` + `EXPIRE`.
