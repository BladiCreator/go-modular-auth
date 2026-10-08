# GoModularAuth Username Plugin (`gomodularauth-username`)

[![Go Reference](https://pkg.go.dev/badge/github.com/BladiCreator/go-modular-auth-username.svg)](https://pkg.go.dev/github.com/BladiCreator/go-modular-auth-username)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

An optional, production-ready identity plugin for [GoModularAuth](https://github.com/BladiCreator/go-modular-auth) that provides username-based authentication, normalization, validation, and lifecycle management without polluting the Core `user.User` entity.

---

## Table of Contents

- [Overview](#overview)
- [Architecture & Design Principles](#architecture--design-principles)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Public API](#public-api)
- [Persistence & Store Contract](#persistence--store-contract)
- [Cache Acceleration](#cache-acceleration)
- [Events](#events)
- [Security Model](#security-model)
- [Migrations](#migrations)
- [Testing](#testing)
- [License](#license)

---

## Overview

GoModularAuth Core focuses strictly on a minimal authentication core (`User + Account + Credential + Session`) using email addresses.

Many applications require users to claim unique handles (usernames) for public identification, URLs, mentions, or alternative sign-in methods. Rather than modifying the Core `User` model, `gomodularauth-username` decouples usernames into an authoritative identity link keyed by `user_id`:

- **Decoupled from Core**: Never alters the Core schema or entities.
- **Timing Equalization**: Prevents username enumeration by matching the response timing of missing users to wrong passwords via Core's Argon2id dummy verification.
- **Configurable Normalization & Validation**: Restricts character sets (preventing Unicode homoglyph attacks) and offers case-insensitive uniqueness with case-preserving display.
- **Cache-Aside Acceleration**: Integrates with Core cache adapters for fast lookups with automatic invalidation on updates.
- **Transactional & Race-Condition Safe**: Guarantees atomic registrations and updates through storage uniqueness constraints and Core transactions.

---

## Architecture & Design Principles

```text
Application Code
      │
      ▼
auth.Get[username.Capability]() / auth.Get[username.Username]()
      │
      ▼
┌────────────────────────────────────────────────────────┐
│           gomodularauth-username (Plugin)              │
│                                                        │
│  - Validation (length, characters, reserved words)     │
│  - Normalization (case-folding, trim)                  │
│  - Timing Equalization                                 │
└──────────────┬──────────────────────────┬──────────────┘
               │                          │
               ▼                          ▼
┌──────────────────────────────┐  ┌──────────────────────┐
│ username.Store (Source of    │  │ Core auth.Auth Host  │
│ Truth: Memory / SQL Adapter) │  │  - Core Store Tx     │
└──────────────┬───────────────┘  │  - Hasher Verification│
               │                  │  - Session Issuance  │
               ▼                  │  - Events Dispatcher │
┌──────────────────────────────┐  └──────────────────────┘
│ cache.Cache (Namespaced      │
│ Acceleration: Optional)      │
└──────────────────────────────┘
```

---

## Installation

```bash
go get github.com/BladiCreator/go-modular-auth-username
```

---

## Quick Start

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/BladiCreator/go-modular-auth/auth"
	memcache "github.com/BladiCreator/go-modular-auth/cache/memory"
	memstore "github.com/BladiCreator/go-modular-auth/store/memory"
	"github.com/BladiCreator/go-modular-auth-username"
)

func main() {
	ctx := context.Background()

	// 1. Initialize GoModularAuth with the Username plugin
	app, err := auth.New(auth.Config{
		Store: memstore.New(),
		Cache: memcache.New(),
		Plugins: []auth.PluginModule{
			username.New(), // Uses in-memory username store by default
		},
	})
	if err != nil {
		log.Fatalf("auth initialization failed: %v", err)
	}

	// 2. Retrieve the typed username capability
	userPlugin, err := app.Get[username.Capability]()
	if err != nil {
		log.Fatalf("plugin lookup failed: %v", err)
	}

	// 3. Register a user with email + username + password
	result, err := userPlugin.Register(ctx, username.RegisterInput{
		Email:    "alice@example.com",
		Username: "AliceSmith",
		Password: "SuperSecretPassword123!",
	})
	if err != nil {
		log.Fatalf("registration failed: %v", err)
	}
	fmt.Printf("Registered user: %s with session token: %s\n", result.User.ID, result.Token)

	// 4. Authenticate using username (case-insensitive by default)
	authRes, err := userPlugin.Authenticate(ctx, username.AuthenticateInput{
		Username: "alicesmith",
		Password: "SuperSecretPassword123!",
	})
	if err != nil {
		log.Fatalf("authentication failed: %v", err)
	}
	fmt.Printf("Authenticated user %s, issued session %s\n", authRes.User.ID, authRes.Session.ID)
}
```

---

## Configuration

Configure the plugin using functional options in `username.New(...)`:

```go
uMod := username.New(
    username.WithStore(customStore),              // Custom persistence store adapter
    username.WithMinLength(4),                   // Minimum length (default: 3)
    username.WithMaxLength(20),                  // Maximum length (default: 30)
    username.WithCaseSensitive(false),           // Case sensitivity (default: false)
    username.WithReserved("admin", "root", "me"), // Additional reserved usernames
    username.WithCacheTTL(10 * time.Minute),      // Cache expiration (default: 5m)
)
```

---

## Public API

### Capability Interface

Applications access the capability via `auth.Get[username.Capability]()` or `auth.Get[username.Username]()`:

```go
type Capability interface {
    // Authenticate validates the username and password, issuing an opaque session.
    // Applies timing equalization to prevent username enumeration if user does not exist.
    Authenticate(ctx context.Context, in AuthenticateInput) (*auth.AuthResult, error)

    // Register atomically creates a new Core User, Account, Credential, and Username mapping.
    Register(ctx context.Context, in RegisterInput) (*auth.AuthResult, error)

    // Set assigns a username to an existing Core user.
    Set(ctx context.Context, userID, rawUsername string) error

    // Change modifies an existing username for a user, invalidating caches.
    Change(ctx context.Context, userID, newRawUsername string) error

    // Delete removes the username assignment for a user.
    Delete(ctx context.Context, userID string) error

    // GetByUserID retrieves the username record for a given Core user ID.
    GetByUserID(ctx context.Context, userID string) (*Record, error)

    // GetByUsername retrieves the username record for a raw username.
    GetByUsername(ctx context.Context, rawUsername string) (*Record, error)

    // Lookup returns the Core user ID associated with the username.
    Lookup(ctx context.Context, rawUsername string) (string, error)

    // Validate checks if a raw username satisfies validation rules.
    Validate(rawUsername string) error

    // Normalize computes the canonical representation of a raw username.
    Normalize(rawUsername string) (string, error)
}
```

### Domain Errors

Sentinel errors allow explicit error handling:

- `username.ErrNotFound`: Username or user mapping does not exist.
- `username.ErrTaken`: Username is already claimed by another user.
- `username.ErrAlreadyAssigned`: User already has an assigned username.
- `username.ErrInvalidFormat`: Username fails character or pattern validation.
- `username.ErrTooShort`: Username is shorter than minimum allowed length.
- `username.ErrTooLong`: Username exceeds maximum allowed length.
- `username.ErrReserved`: Username is in the reserved list (e.g. `admin`, `api`).
- `username.ErrUserNotFound`: Corresponding Core user was not found.
- `username.ErrInvalidCredentials`: Invalid username or password (enumeration-safe).

---

## Persistence & Store Contract

The Store interface provides strict separation of storage mechanisms:

```go
type Store interface {
    Create(ctx context.Context, rec *Record) error
    GetByNormalized(ctx context.Context, normalized string) (*Record, error)
    GetByUserID(ctx context.Context, userID string) (*Record, error)
    Update(ctx context.Context, rec *Record) error
    Delete(ctx context.Context, userID string) error
}
```

An in-memory implementation (`github.com/BladiCreator/go-modular-auth-username/store/memory`) is provided for testing and lightweight development.

---

## Cache Acceleration

When GoModularAuth has a Cache configured (`Config.Cache != nil`), `gomodularauth-username` automatically accelerates lookups using cache-aside semantics:

- **Keyspace**:
  - `gomodularauth:username:norm:<normalized>` -> `*Record`
  - `gomodularauth:username:user:<userID>` -> `*Record`
- **Cache Invalidation**:
  - `Set` / `Register`: Populates cache entries after successful store commit.
  - `Change`: Deletes previous normalized key, stores new normalized key, and refreshes user key.
  - `Delete`: Deletes both cache keys upon removal.

If the cache fails or is disabled, the plugin degrades gracefully to the Store without interrupting authentication flows.

---

## Events

The plugin publishes observational events through the GoModularAuth event bus:

- `username.created` (`CreatedPayload`): Emitted when a username is assigned.
- `username.updated` (`UpdatedPayload`): Emitted when a username is changed.
- `username.deleted` (`DeletedPayload`): Emitted when a username is removed.

Event payloads contain no secrets or passwords.

---

## Security Model

1. **Username Enumeration Defense**: During `Authenticate`, queries against non-existent usernames trigger an Argon2id dummy hash verification inside Core, matching the computation time of valid accounts with invalid passwords.
2. **Homoglyph & Confusable Attack Prevention**: By default, username characters are strictly restricted to ASCII alphanumeric characters (`[a-zA-Z0-9_-]`), disallowing lookalike Unicode runes.
3. **Squatting Prevention**: Pre-configured reserved keywords safeguard system routing paths (`/admin`, `/api`, `/login`, etc.).
4. **Concurrency & Race Conditions**: Uniqueness is enforced at the Store level. Concurrent registration requests for the same username result in exactly one success and `ErrTaken` for all competing transactions.

---

## Migrations

See [`migrations/001_create_usernames.sql`](migrations/001_create_usernames.sql) for SQL migrations compatible with PostgreSQL, SQLite, and MySQL.

---

## Testing

Run tests across the entire module:

```bash
go test -v ./...
go vet ./...
```

---

## License

MIT License. See [LICENSE](LICENSE) for details.
