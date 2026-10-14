# gomodularauth-bearer

[![Go Reference](https://pkg.go.dev/badge/github.com/BladiCreator/go-modular-auth/plugins/bearer.svg)](https://pkg.go.dev/github.com/BladiCreator/go-modular-auth/plugins/bearer)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

`gomodularauth-bearer` provides transport-independent Bearer token authentication for server-side APIs built with [GoModularAuth](https://github.com/BladiCreator/go-modular-auth).

---

## 1. Problem Solved

Standard authentication frameworks tightly couple token extraction with HTTP request handling (`net/http`, headers, cookies). In modern architectures, server-side APIs often receive requests through heterogeneous transports:
- REST / JSON over `net/http`
- High-performance web frameworks (Gin, Fiber, Echo)
- gRPC microservices
- WebSockets and message brokers (e.g. NATS, RabbitMQ)
- CLI utilities and background workers

`gomodularauth-bearer` completely decouples Bearer credential verification from the transport layer:
1. **Transport-Agnostic Input**: Accepts raw token credentials through clean Go structs.
2. **Principal Resolution**: Resolves tokens into strongly typed `auth.Principal` instances.
3. **High Security Opaque Tokens**: Tokens carry 256 bits of cryptographically secure entropy (`crypto/rand`) and are stored exclusively as SHA-256 digests.
4. **Zero Credential Exposure**: Plaintext tokens are NEVER logged, NEVER exposed in error messages, and NEVER stored in persistence or cache keys.
5. **Granular Scopes**: Built-in validation of permission scopes.
6. **Expiration & Revocation**: Instant individual token revocation, bulk revocation by subject (e.g. upon user logout or compromise), and lifecycle expiration purging.
7. **Cache Acceleration**: Transparent cache lookup using derived cryptographic hashes while keeping `store.Store` as the authoritative source of truth.
8. **Transport Integration Contract**: Exposes explicit contracts and helper extractors for transport adapters.

---

## 2. Installation

```bash
go get github.com/BladiCreator/go-modular-auth/plugins/bearer
```

---

## 3. Architecture

```text
HTTP / gRPC / CLI / WebSocket (Transport Layer)
          │  Extracts credentials via ExtractBearerToken
          ▼
   AuthenticateInput{Token: "...", RequiredScopes: [...]}
          │
          ▼
┌─────────────────────────────────────────────────────────────┐
│                 gomodularauth-bearer                        │
│                                                             │
│  1. Hash Token (SHA-256)                                    │
│  2. Cache Check (Optional Acceleration)                     │
│  3. Store Lookup (Source of Truth)                          │
│  4. Expiration & Revocation Validation                      │
│  5. Scope Permissions Verification                          │
└─────────────────────────────────────────────────────────────┘
          │
          ▼
   auth.Principal{Subject: "usr_123", Type: "user"}
          │  Injected into context via auth.WithPrincipal(ctx, p)
          ▼
Downstream Business Handlers
```

---

## 4. Registering in GoModularAuth

```go
package main

import (
    "log"

    "github.com/BladiCreator/go-modular-auth/auth"
    storememory "github.com/BladiCreator/go-modular-auth/store/memory"
    bearer "github.com/BladiCreator/go-modular-auth/plugins/bearer"
    "github.com/BladiCreator/go-modular-auth/plugins/bearer/plugins"
)

func main() {
    // 1. Initialize GoModularAuth engine with Bearer plugin
    authApp, err := auth.New(auth.Config{
        Store: storememory.New(),
        Plugins: []auth.PluginModule{
            bearer.New(
                bearer.WithTokenPrefix("gmb_"), // Default prefix
            ),
        },
    })
    if err != nil {
        log.Fatalf("failed to initialize auth: %v", err)
    }

    // 2. Retrieve strongly typed capability
    bearerPlugin, err := auth.Get[plugins.Bearer](authApp)
    if err != nil {
        log.Fatalf("bearer plugin missing: %v", err)
    }

    _ = bearerPlugin
}
```

---

## 5. Public Capability API

Applications and transport adapters consume the `Bearer` capability:

```go
type Bearer interface {
    // Authenticate validates credentials and resolves the Principal.
    Authenticate(ctx context.Context, in AuthenticateInput) (*AuthResult, error)

    // Issue generates and stores a new opaque token. Plaintext is returned strictly once.
    Issue(ctx context.Context, in IssueInput) (*IssueResult, error)

    // Revoke invalidates an individual token by ID.
    Revoke(ctx context.Context, tokenID string) error

    // RevokeBySubject revokes all active tokens belonging to a subject.
    RevokeBySubject(ctx context.Context, subject string) error

    // Get retrieves public metadata for a token by ID (never secret or hash).
    Get(ctx context.Context, tokenID string) (*TokenInfo, error)

    // ListBySubject retrieves metadata for all tokens belonging to a subject.
    ListBySubject(ctx context.Context, subject string) ([]*TokenInfo, error)

    // Delete permanently deletes a token record by ID.
    Delete(ctx context.Context, tokenID string) error

    // PurgeExpired permanently removes expired and revoked tokens from persistence.
    PurgeExpired(ctx context.Context) (int, error)
}
```

---

## 6. Issuing & Authenticating Tokens

### Issuing a Token
```go
res, err := bearerPlugin.Issue(ctx, bearer.IssueInput{
    Subject:       "usr_98765",
    PrincipalType: auth.PrincipalUser,
    Scopes:        []string{"read:reports", "write:reports"},
    TTL:           24 * time.Hour,
    Metadata: map[string]string{
        "device": "desktop",
    },
})
if err != nil {
    log.Fatal(err)
}

// Plaintext token to return to client (returned ONCE upon creation):
fmt.Println("Bearer token:", res.Token) // e.g. "gmb_y2e9m1x..."
fmt.Println("Token ID:", res.Info.ID)
```

### Authenticating a Token
```go
authRes, err := bearerPlugin.Authenticate(ctx, bearer.AuthenticateInput{
    Token:          rawToken,
    RequiredScopes: []string{"read:reports"},
})
if err != nil {
    switch {
    case errors.Is(err, bearer.ErrInvalidToken):
        // Token doesn't exist or is malformed
    case errors.Is(err, bearer.ErrTokenExpired):
        // Token has passed its TTL
    case errors.Is(err, bearer.ErrTokenRevoked):
        // Token was revoked
    case errors.Is(err, bearer.ErrInsufficientScope):
        // Token lacks required scopes
    }
    return
}

fmt.Printf("Authenticated Principal: %+v\n", authRes.Principal)
```

---

## 7. Transport Adapter Integration

`gomodularauth-bearer` provides an explicit contract and utility helpers:

### 7.1 Standard `net/http` Middleware
```go
package transport

import (
    "net/http"

    "github.com/BladiCreator/go-modular-auth/auth"
    bearer "github.com/BladiCreator/go-modular-auth/plugins/bearer"
)

func BearerAuthMiddleware(b bearer.Bearer, requiredScopes ...string) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            token, err := bearer.ExtractBearerToken(r.Header.Get("Authorization"))
            if err != nil {
                http.Error(w, "Unauthorized: missing or invalid bearer token", http.StatusUnauthorized)
                return
            }

            res, err := b.Authenticate(r.Context(), bearer.AuthenticateInput{
                Token:          token,
                RequiredScopes: requiredScopes,
            })
            if err != nil {
                http.Error(w, "Unauthorized", http.StatusUnauthorized)
                return
            }

            // Inject Principal and TokenInfo into context
            ctx := auth.WithPrincipal(r.Context(), res.Principal)
            ctx = bearer.WithTokenInfo(ctx, res.Token)

            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }
}
```

### 7.2 Gin Middleware
```go
func GinBearerMiddleware(b bearer.Bearer, requiredScopes ...string) gin.HandlerFunc {
    return func(c *gin.Context) {
        token, err := bearer.ExtractBearerToken(c.GetHeader("Authorization"))
        if err != nil {
            c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
            return
        }

        res, err := b.Authenticate(c.Request.Context(), bearer.AuthenticateInput{
            Token:          token,
            RequiredScopes: requiredScopes,
        })
        if err != nil {
            c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
            return
        }

        c.Request = c.Request.WithContext(auth.WithPrincipal(c.Request.Context(), res.Principal))
        c.Set("principal", res.Principal)
        c.Next()
    }
}
```

### 7.3 gRPC Interceptor
```go
func UnaryBearerInterceptor(b bearer.Bearer) grpc.UnaryServerInterceptor {
    return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
        md, ok := metadata.FromIncomingContext(ctx)
        if !ok {
            return nil, status.Error(codes.Unauthenticated, "missing metadata")
        }

        values := md.Get("authorization")
        if len(values) == 0 {
            return nil, status.Error(codes.Unauthenticated, "missing authorization header")
        }

        token, err := bearer.ExtractBearerToken(values[0])
        if err != nil {
            return nil, status.Error(codes.Unauthenticated, "invalid bearer token")
        }

        res, err := b.Authenticate(ctx, bearer.AuthenticateInput{Token: token})
        if err != nil {
            return nil, status.Error(codes.Unauthenticated, "unauthenticated")
        }

        ctx = auth.WithPrincipal(ctx, res.Principal)
        return handler(ctx, req)
    }
}
```

---

## 8. Persistence & Stores

The plugin decouples persistence through `store.Store`:

```go
type Store interface {
    Create(ctx context.Context, record *TokenRecord) error
    GetByID(ctx context.Context, id string) (*TokenRecord, error)
    GetByTokenHash(ctx context.Context, tokenHash string) (*TokenRecord, error)
    Update(ctx context.Context, record *TokenRecord) error
    Revoke(ctx context.Context, id string, revokedAt time.Time) error
    RevokeBySubject(ctx context.Context, subject string, revokedAt time.Time) error
    Delete(ctx context.Context, id string) error
    DeleteExpired(ctx context.Context, before time.Time) (int, error)
    ListBySubject(ctx context.Context, subject string) ([]*TokenRecord, error)
}
```

### Available Adapters:
1. **In-Memory Store (`store/memory`)**:
   Thread-safe in-process store with `sync.RWMutex`. Used for tests and ephemeral environments.
   ```go
   import "github.com/BladiCreator/go-modular-auth/plugins/bearer/store/memory"

   module := bearer.New(bearer.WithStore(memory.New()))
   ```
2. **PostgreSQL Store (`store/postgres`)**:
   Production-ready implementation compatible with `*sql.DB` and connection poolers (PgBouncer).
   ```go
   import "github.com/BladiCreator/go-modular-auth/plugins/bearer/store/postgres"

   module := bearer.New(bearer.WithStore(postgres.New(db)))
   ```

Database schema migrations are located in `migrations/001_create_bearer_tokens.sql`.

---

## 9. Cache Acceleration

When GoModularAuth has a Cache Adapter configured, `gomodularauth-bearer` automatically accelerates token lookups:
- **Key Namespacing**: Uses `cache.Key("bearer", "token", tokenHash)`.
- **Secret Safety**: Keys are derived exclusively from the SHA-256 hash. Plaintext tokens never appear in cache keys or values.
- **Cache Invalidation**: Automatically invalidated upon `Revoke`, `RevokeBySubject`, `Delete`, and `Update`.
- **Graceful Degradation**: If cache is unavailable or fails, lookups fall back seamlessly to `store.Store`.

---

## 10. Events & Observability

`gomodularauth-bearer` publishes domain events via `auth.Events`:

- `bearer.token.issued`: Emitted when a new token is generated.
- `bearer.token.revoked`: Emitted when a token is invalidated.
- `bearer.authenticated`: Emitted on successful authentication.
- `bearer.token.expired`: Emitted when authentication fails due to expired TTL.

```go
authApp.Events().Subscribe(bearer.EventBearerAuthenticated, func(ctx context.Context, e auth.Event) {
    payload := e.Payload.(bearer.AuthenticatedPayload)
    log.Printf("Token %s authenticated for %s", payload.TokenID, payload.Subject)
})
```

---

## 11. Security Model

| Threat / Vector | Mitigation |
| :--- | :--- |
| **Credential Leakage** | Plaintext tokens exist only in memory at creation. Persistent stores and caches store only SHA-256 digests. |
| **Logging Exposure** | Secret credentials are never printed to logs. Only IDs and subjects are logged. |
| **Error Enumeration** | All lookup failures return constant `ErrInvalidToken`. Never leaks whether token exists or what failed. |
| **Timing Attacks** | Token hashes are compared in constant time (`subtle.ConstantTimeCompare`). |
| **Brute Force** | 256 bits of entropy from `crypto/rand` makes offline or online guessing mathematically impossible. |
| **Cache Poisoning** | Cache entries are keyed by cryptographic hashes and verified against expiration/revocation timestamps. |
| **Privilege Escalation**| Scopes are strictly enforced before resolving credentials. |
| **Concurrency / Races** | Stores use atomic database queries / read-write locks for safe concurrent verification and revocation. |

---

## 12. Running Tests

```bash
go test -v -race ./...
```

---

## 13. License

MIT License. See [LICENSE](LICENSE) for details.
