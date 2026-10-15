# gomodularauth-anonymous

[![Go Reference](https://pkg.go.dev/badge/github.com/BladiCreator/go-modular-auth/plugins/anonymous.svg)](https://pkg.go.dev/github.com/BladiCreator/go-modular-auth/plugins/anonymous)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

An official production-ready plugin for **GoModularAuth** that provides anonymous user identities, session issuance, lifecycle expiration, in-place conversion to permanent authenticated accounts, and account linking/merging with explicit authentication and privilege escalation prevention.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Installation](#installation)
- [Configuration](#configuration)
- [Registration](#registration)
- [Public API](#public-api)
- [Conversion and Account Linking](#conversion-and-account-linking)
- [Security Model](#security-model)
- [Persistence and Stores](#persistence-and-stores)
- [Cache](#cache)
- [Events](#events)
- [Hooks](#hooks)
- [Cleanup and Expiration](#cleanup-and-expiration)
- [Testing](#testing)
- [License](#license)

---

## Overview

Modern web and mobile applications often require users to interact immediately (e.g. adding items to a cart, drafting a document, trying out a service) without forcing upfront registration. 

`gomodularauth-anonymous` fulfills this requirement by:
- Generating temporary **Core User** and **Session** records with an explicit anonymous identity tracking record.
- Tagging the identity with an explicit `PrincipalType` (`"anonymous"`) to strictly prevent anonymous users from obtaining privileges intended for permanent users.
- Providing seamless **in-place conversion** to a permanent email/password account or external OAuth/passkey account while preserving all existing user IDs and application data.
- Enabling **account linking/merging** into an existing permanent account, requiring explicit target account authentication to prevent privilege escalation.
- Defining lifecycle expiration and transactional cleanup mechanics to purge stale unauthenticated sessions and orphaned anonymous data.

---

## Architecture

```text
Application
    ↓
GoModularAuth Core (auth.Auth)
    ↓
gomodularauth-anonymous (PluginModule)
    ↓
Capability: anonymous.Anonymous (or plugins.Anonymous)
    ↓
Plugin Store (Memory / PostgreSQL) + Optional Cache
```

- **Reuses Core Entities**: Integrates directly with Core `User`, `Account`, and `Session`.
- **Decoupled**: Does not depend on concrete database drivers or HTTP frameworks.
- **Authoritative Persistence**: State is authoritatively managed in the store; cache serves purely as acceleration.

---

## Installation

```bash
go get github.com/BladiCreator/go-modular-auth/plugins/anonymous
```

---

## Configuration

The plugin provides functional options through `anonymous.New(opts...)`:

| Option | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `WithIdentityTTL(d)` | `time.Duration` | `30 * 24 * time.Hour` | Expiration lifespan for unconverted anonymous identities |
| `WithSessionTTL(d)` | `time.Duration` | `30 * 24 * time.Hour` | Lifetime granted to anonymous user sessions |
| `WithCacheTTL(d)` | `time.Duration` | `5 * time.Minute` | TTL for cached anonymous identity records |
| `WithEmailDomain(domain)`| `string` | `"anonymous.invalid"` | Domain used for synthetic placeholder emails (RFC 2606) |
| `WithPasswordPolicy(min, max)` | `int, int` | `8, 128` | Password length policy during conversion |
| `WithHasher(h)` | `password.Hasher` | Core Argon2id | Password hasher for permanent credentials |
| `WithHooks(hooks)` | `*Hooks` | Initialized empty | Lifecycle interceptors |

---

## Registration

Register the plugin during GoModularAuth initialization:

```go
package main

import (
	"log"

	"github.com/BladiCreator/go-modular-auth/auth"
	corecache "github.com/BladiCreator/go-modular-auth/cache/memory"
	adaptermem "github.com/BladiCreator/go-modular-auth/adapter/memory"

	"github.com/BladiCreator/go-modular-auth/plugins/anonymous"
	"github.com/BladiCreator/go-modular-auth/plugins/anonymous/plugins"
)

func main() {
	storeAdapter := corestore.New()
	cacheAdapter := corecache.New()

	engine, err := auth.New(auth.Config{
		Adapter: adaptermem.New(),
		Cache: cacheAdapter,
		Plugins: []auth.PluginModule{
			anonymous.New(
				anonymous.WithIdentityTTL(14 * 24 * time.Hour),
			),
		},
	})
	if err != nil {
		log.Fatalf("failed to initialize auth: %v", err)
	}

	// Retrieve capability
	anon, err := auth.Get[plugins.Anonymous](engine)
	if err != nil {
		log.Fatalf("failed to retrieve Anonymous plugin: %v", err)
	}
}
```

---

## Public API

The `Anonymous` capability defines:

```go
type Anonymous interface {
	// Authenticate issues a new anonymous User, Session, and Identity.
	Authenticate(ctx context.Context, in AuthenticateInput) (*AuthResult, error)

	// GetIdentity retrieves the anonymous identity metadata for a Core User ID.
	GetIdentity(ctx context.Context, userID string) (*Identity, error)

	// IsAnonymous checks if the user is an active, unexpired, and unconverted anonymous identity.
	IsAnonymous(ctx context.Context, userID string) (bool, error)

	// Principal returns PrincipalAnonymous ("anonymous") or auth.PrincipalUser ("user").
	Principal(ctx context.Context, userID string) (auth.Principal, error)

	// Convert converts an active anonymous user in-place to email & password credentials.
	Convert(ctx context.Context, in ConvertInput) (*ConvertResult, error)

	// ConvertWithAccount converts an anonymous user by linking an external provider (OAuth, passkey).
	ConvertWithAccount(ctx context.Context, in ConvertAccountInput) (*ConvertResult, error)

	// Link merges an anonymous identity into an existing permanent account after authentication.
	Link(ctx context.Context, in LinkInput) (*LinkResult, error)

	// Cleanup deletes expired and unconverted identities and their orphaned core records.
	Cleanup(ctx context.Context, before time.Time) (CleanupResult, error)
}
```

---

## Conversion and Account Linking

### 1. In-Place Conversion

When an anonymous user signs up, their existing `User.ID` is retained. All shopping carts, preferences, or draft files already created by the anonymous user remain attached to the user:

```go
res, err := anon.Convert(ctx, anonymous.ConvertInput{
    AnonymousUserID: anonUserID,
    AnonymousToken:  sessionToken, // verifies caller owns active session
    Email:           "jane.doe@example.com",
    Password:        "SecurePassword123!",
})
```

### 2. Merging into an Existing Permanent Account

If an anonymous visitor decides to log in using an existing account:

```go
linkRes, err := anon.Link(ctx, anonymous.LinkInput{
    AnonymousUserID:          anonUserID,
    PermanentEmail:           "existing@example.com",
    PermanentPassword:        "Password123!",
    RevokeAnonymousSessions: true,
})
// linkRes.PermanentUser contains the target user
```

---

## Security Model

1. **Privilege Separation**:
   - `anon.Principal(ctx, userID)` yields `auth.Principal{Type: "anonymous"}`. Middleware checks this type to reject access to privileged routes (billing, account management, administration).
2. **Privilege Escalation Prevention**:
   - Merging (`Link`) requires **explicit authentication** of the permanent account.
   - Linking to another anonymous user is prohibited (`ErrTargetIsAnonymous`).
   - Linking an account to itself is prohibited (`ErrSameAccount`).
3. **Synthetic Email Guard**:
   - Core `BeforeSignIn` hook prevents attackers from attempting direct password sign-in against synthetic placeholder emails (`*@anonymous.invalid`).
4. **Single Conversion Guarantee**:
   - Conversion is an atomic transition; converted records reject second conversions with `ErrAlreadyConverted`.

---

## Persistence & Schema

The plugin registers its database model `anonymous_identities` via `RegisterSchema(s *schema.Schema)` and accesses persistence through `sdk.Model[AnonymousIdentity]` on the configured `adapter.Adapter` (PostgreSQL, SQLite, MySQL, SurrealDB, or In-Memory).

---

## Cache

When a core cache adapter is supplied, anonymous identities are cached using the namespaced key pattern:

```text
gomodularauth:anonymous:user:<userID>
```

Cache is invalidated on conversion, linking, and deletion.

---

## Events

The plugin publishes observational domain events to `host.Events()`:

- `anonymous.created` (`CreatedPayload`)
- `anonymous.converted` (`ConvertedPayload`)
- `anonymous.linked` (`LinkedPayload`)
- `anonymous.cleaned_up` (`CleanedUpPayload`)

---

## Hooks

Workflow hooks allow intercepting operations:

```go
hooks := anonymous.NewHooks()
hooks.BeforeCreate(func(ctx context.Context, in *anonymous.AuthenticateInput) error {
    // Custom rate limiting or device fingerprinting
    return nil
})
hooks.AfterConvert(func(ctx context.Context, res *anonymous.ConvertResult) {
    // Notify CRM or onboarding service
})
```

---

## Cleanup and Expiration

Expired anonymous records can be cleaned up on a schedule (e.g. cron job):

```go
result, err := anon.Cleanup(ctx, time.Now())
if err != nil {
    log.Printf("cleanup error: %v", err)
}
log.Printf("purged %d identities, %d users, %d sessions", 
    result.IdentitiesDeleted, result.UsersDeleted, result.SessionsRevoked)
```

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
