# GoModularAuth API Keys Plugin (`gomodularauth-api-key`)

[![Go Reference](https://pkg.go.dev/badge/github.com/BladiCreator/go-modular-auth/plugins/api-keys.svg)](https://pkg.go.dev/github.com/BladiCreator/go-modular-auth/plugins/api-keys)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Production-grade API key authentication, lifecycle management, and identity resolution plugin for **[GoModularAuth](https://github.com/BladiCreator/go-modular-auth)**.

---

## 1. Overview

The `gomodularauth-api-key` plugin provides high-performance, cryptographic API key authentication for machine identities, background services, developers, and multi-tenant organizations.

### Key Highlights
- **Cryptographic Token Hygiene**: API keys are generated using CSPRNG (`crypto/rand`) with 256 bits of entropy. Plaintext keys are returned strictly once during creation and **never** stored. Only SHA-256 digests and display prefixes are persisted.
- **Core Principal Resolution**: Successfully authenticated API keys resolve directly to `auth.Principal` (`Type: "api_key"`). API keys **do not** create or pollute user sessions.
- **Brute-Force & Timing Attack Defense**: Integrated failed-attempt rate limiting via Core Cache or in-memory fallback, constant-time hash verification (`subtle.ConstantTimeCompare`), and dummy hash simulation for missing records.
- **Full Lifecycle**: Complete support for creation, listing, rotation (immediate or with grace period), revocation, scopes, permissions, metadata, and debounced telemetry (`LastUsedAt`, `IP`, `User-Agent`).
- **Immediate Cache Invalidation**: Revoking or rotating a key immediately purges cache entries.

---

## 2. Installation

```bash
go get github.com/BladiCreator/go-modular-auth/plugins/api-keys
```

---

## 3. Configuration & Registration

Register the plugin when bootstrapping GoModularAuth:

```go
package main

import (
	"log"

	apikeys "github.com/BladiCreator/go-modular-auth/plugins/api-keys"
	"github.com/BladiCreator/go-modular-auth/plugins/api-keys/plugins"
	apikeystore "github.com/BladiCreator/go-modular-auth/plugins/api-keys/store/memory"
	"github.com/BladiCreator/go-modular-auth/auth"
	corecache "github.com/BladiCreator/go-modular-auth/cache/memory"
	corestore "github.com/BladiCreator/go-modular-auth/store/memory"
)

func main() {
	keyStore := apikeystore.New() // or postgres.New(db)

	engine, err := auth.New(auth.Config{
		Store: corestore.New(),
		Cache: corecache.New(),
		Plugins: []auth.PluginModule{
			apikeys.New(
				apikeys.WithStore(keyStore),
				apikeys.WithKeyPrefix("gma_live_"),
				apikeys.WithSubjectStrategy(apikeys.SubjectStrategyKeyID),
			),
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	// Consume capability using strong typing:
	apiKeyService, err := auth.Get[plugins.APIKeys](engine)
	if err != nil {
		log.Fatal(err)
	}

	_ = apiKeyService
}
```

---

## 4. Public API

### Capability Interface

```go
type APIKeys interface {
	Create(ctx context.Context, in CreateInput) (*CreateResult, error)
	Get(ctx context.Context, id string) (*APIKey, error)
	List(ctx context.Context, filter ListFilter) ([]*APIKey, error)
	Revoke(ctx context.Context, id string) error
	Rotate(ctx context.Context, id string, opts ...RotateOption) (*RotateResult, error)
	Authenticate(ctx context.Context, rawKey string, opts ...AuthOption) (*AuthResult, error)
	Delete(ctx context.Context, id string) error
	PurgeExpired(ctx context.Context) (int, error)
	Hooks() *Hooks
}
```

---

## 5. Usage Examples

### 5.1 Creating an API Key

```go
res, err := apiKeyService.Create(ctx, apikeys.CreateInput{
	Name:           "Billing Sync Worker",
	UserID:         "usr_01HXYZ",
	OrganizationID: "org_01HABC",
	Scopes:         []string{"billing:read", "billing:write"},
	Permissions:    []string{"invoices.create"},
	Metadata:       map[string]string{"env": "production", "version": "v2"},
	ExpiresIn:      90 * 24 * time.Hour,
})
if err != nil {
	log.Fatalf("create failed: %v", err)
}

// Display the plaintext key once:
fmt.Println("API Key:", res.RawKey) // e.g. gma_live_92kd84js02kd...
fmt.Println("Key ID:", res.Key.ID)
fmt.Println("Prefix:", res.Key.Prefix) // e.g. gma_live_92kd (safe for display)
```

### 5.2 Authenticating an API Key (Middleware Integration)

```go
authRes, err := apiKeyService.Authenticate(ctx, incomingRawKey,
	apikeys.WithIPAddress(r.RemoteAddr),
	apikeys.WithUserAgent(r.UserAgent()),
	apikeys.WithRequiredScopes("billing:read"),
)
if err != nil {
	switch {
	case errors.Is(err, apikeys.ErrInvalidKey):
		http.Error(w, "Invalid API key", http.StatusUnauthorized)
	case errors.Is(err, apikeys.ErrKeyRevoked):
		http.Error(w, "API key revoked", http.StatusUnauthorized)
	case errors.Is(err, apikeys.ErrKeyExpired):
		http.Error(w, "API key expired", http.StatusUnauthorized)
	case errors.Is(err, apikeys.ErrInsufficientScope):
		http.Error(w, "Forbidden: insufficient scope", http.StatusForbidden)
	case errors.Is(err, apikeys.ErrRateLimited):
		http.Error(w, "Too many failed attempts", http.StatusTooManyRequests)
	default:
		http.Error(w, "Internal error", http.StatusInternalServerError)
	}
	return
}

// Attach principal & API key to request context:
ctx = auth.WithPrincipal(r.Context(), authRes.Principal)
ctx = apikeys.WithAPIKey(ctx, authRes.Key)
```

### 5.3 Rotating an API Key

```go
// Option A: Immediate revocation of old key
rot, err := apiKeyService.Rotate(ctx, keyID)

// Option B: Grace period for zero-downtime credential deployment
rotGrace, err := apiKeyService.Rotate(ctx, keyID,
	apikeys.WithGracePeriod(48 * time.Hour), // Old key remains valid for 48 hours
	apikeys.WithNewName("Rotated Billing Worker"),
)
```

### 5.4 Revoking an API Key

```go
if err := apiKeyService.Revoke(ctx, keyID); err != nil {
	log.Fatalf("revocation failed: %v", err)
}
// Cache is immediately invalidated. Future authentication calls reject instantly.
```

---

## 6. Persistence & Store Adapters

The plugin defines a clear, domain-specific persistence contract:

```go
type Store interface {
	Create(ctx context.Context, key *APIKey) error
	GetByID(ctx context.Context, id string) (*APIKey, error)
	GetByHash(ctx context.Context, keyHash string) (*APIKey, error)
	Update(ctx context.Context, key *APIKey) error
	Revoke(ctx context.Context, id string, revokedAt time.Time) error
	TouchLastUsed(ctx context.Context, id string, at time.Time, ip string, ua string) error
	List(ctx context.Context, filter ListFilter) ([]*APIKey, error)
	Delete(ctx context.Context, id string) error
	DeleteExpired(ctx context.Context, before time.Time) (int, error)
}
```

### Available Implementations:
- `store/memory`: Fully thread-safe, concurrency-tested memory store for tests and development.
- `store/postgres`: Production-ready PostgreSQL adapter using `database/sql`.

---

## 7. Caching & Abuse Prevention

- **Namespaced Cache Keys**: `gomodularauth:apikeys:hash:<key_hash>` and `gomodularauth:apikeys:id:<id>`.
- **Immediate Invalidation**: Calling `Revoke`, `Rotate`, or `Delete` clears both the ID mapping and key hash cache entries.
- **Brute Force Protection**: Failed authentications increment an attempt counter per client identifier. Exceeding `MaxFailedAttempts` throttles verification attempts with `ErrRateLimited`.
- **Timing Defense**: Constant-time hash equality via `subtle.ConstantTimeCompare`, plus simulated dummy hashing on missing keys to prevent user enumeration or timing side-channels.

---

## 8. Events & Hooks

### Observational Events:
- `apikeys.created`
- `apikeys.revoked`
- `apikeys.rotated`
- `apikeys.authenticated`
- `apikeys.deleted`

### Lifecycle Hooks:
- `BeforeCreate` / `AfterCreate`
- `BeforeAuthenticate` / `AfterAuthenticate`
- `BeforeRevoke` / `AfterRevoke`
- `BeforeRotate` / `AfterRotate`

---

## 9. Testing

Run all unit, integration, and security tests:

```bash
go test -v ./...
go vet ./...
```
