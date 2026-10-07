<p align="center">
  <img src="assets/logo.png" alt="Go Modular Auth Logo" width="200" />
</p>

<h1 align="center">Go Modular Auth</h1>

<p align="center">
  <strong>Server-only, transport-agnostic, modular authentication engine for Go.</strong>
</p>

<p align="center">
  <a href="https://pkg.go.dev/github.com/BladiCreator/go-modular-auth"><img src="https://pkg.go.dev/badge/github.com/BladiCreator/go-modular-auth.svg" alt="Go Reference"></a>
  <a href="https://github.com/BladiCreator/go-modular-auth/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>
  <a href="https://golang.org/"><img src="https://img.shields.io/badge/Go-1.27+-00ADD8?logo=go" alt="Go Version"></a>
</p>

---

## 1. Objective & Principles

**GoModularAuth** is a server-only authentication engine designed to keep the core small, secure, and extensible. It avoids monolith framework assumptions and leaves transport and infrastructure completely decoupled.

- **Server-only**: Pure domain operations.
- **Transport-agnostic**: The core never imports `net/http`, `grpc`, `fiber`, or `gin`. Transport adapters bridge HTTP/gRPC requests to core operations.
- **Function-first & Composition**: Small, explicit interfaces, no global state.
- **Authentication separated from Authorization**: Authentication verifies identity (`who`), while authorization plugins consume `Principal` (`what`).
- **Store = Source of Truth**: Persistent state (Users, Accounts, Credentials, Sessions, Verification Tokens) lives exclusively in the Store Adapter.
- **Cache = Performance / Ephemeral State**: Optional, non-authoritative acceleration (Cache-Aside, explicit TTLs, post-commit invalidation, graceful degradation to Store).
- **Extensible via Plugins**: Optional capabilities (OAuth, Passkeys, 2FA, Organizations, Rate Limiting) are isolated plugins consuming the core runtime.

> 📚 **Complete Documentation**: In-depth guides, architectural patterns, and adapter contracts are available in the [**`doc/`**](doc/README.md) directory.

---

## 2. Architecture

```text
                              GoModularAuth
                                   │
            ┌──────────────────────┼──────────────────────┐
            │                      │                      │
       Transport                Core                  Plugins
       Adapters                   │                      │
            │                     │                      │
     ┌──────┼──────┐       ┌─────┼─────┐        ┌──────┼─────────┐
     │      │      │       │     │     │        │      │         │
    HTTP   gRPC   CLI    Store  Cache Events   OAuth  Org       2FA
                           │      │              │      │         │
                           │      │           Passkeys Admin     OTP
                           │      │           SSO      SCIM      ...
                           │      │
                           ▼      ▼
                       Database  Redis/
                                Valkey/
                                Memory
```

---

## 3. Core Entities

- **`User`** (`user.User`): The user identity (`ID`, `Email`, `EmailVerified`, timestamps).
- **`Account`** (`account.Account`): Links a user to an auth provider (e.g. `password`, `google`, `github`, `passkey`).
- **`Credential`** (`credential.Credential`): Stored secret material (Argon2id password hash, passkey credentials, etc.). Plaintext secrets are never stored.
- **`Session`** (`session.Session`): Server-side opaque session. Client tokens are high-entropy random tokens; the database only stores cryptographic SHA-256 hashes (`TokenHash`).
- **`VerificationToken`** (`verification.Token`): Reusable single-use token primitive with atomic consumption, used for email verification, password reset, and plugins (Magic Links, OTPs).
- **`Principal`** (`auth.Principal`): The authenticated subject passed to authorization logic.

---

## 4. Installation

```bash
go get github.com/BladiCreator/go-modular-auth
```

Requires **Go 1.27+**.

---

## 5. Quickstart

### Minimal Setup (Store Only)

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/BladiCreator/go-modular-auth/auth"
	memstore "github.com/BladiCreator/go-modular-auth/store/memory"
)

func main() {
	ctx := context.Background()

	// 1. Initialize store (in-memory adapter for development/tests)
	store := memstore.New()

	// 2. Initialize Auth Core
	app, err := auth.New(auth.Config{
		Store: store,
	})
	if err != nil {
		log.Fatal(err)
	}

	// 3. Sign Up
	res, err := app.SignUp(ctx, auth.SignUpInput{
		Email:    "alice@example.com",
		Password: "SuperSecretPassword123!",
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("User created: %s, Session Token: %s\n", res.User.ID, res.Token)

	// 4. Validate Session
	sessionRes, err := app.RequireSession(ctx, res.Token)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Authenticated Principal: %s\n", sessionRes.Principal().Subject)

	// 5. Sign Out
	if err := app.SignOut(ctx, auth.SignOutInput{Token: res.Token}); err != nil {
		log.Fatal(err)
	}
}
```

---

## 6. Cache Adapter (Optional Performance Layer)

When configuring a Cache Adapter (e.g., Redis, Valkey, or Memory):

```go
import (
	"github.com/BladiCreator/go-modular-auth/auth"
	memcache "github.com/BladiCreator/go-modular-auth/cache/memory"
	memstore "github.com/BladiCreator/go-modular-auth/store/memory"
)

app, err := auth.New(auth.Config{
	Store: memstore.New(),
	Cache: memcache.New(),
})
```

- **Read Path**: Checks cache -> on miss loads from Store -> stores in cache with explicit TTL.
- **Write Path**: Commits mutation to Store -> invalidates cache key.
- **Resilience**: If the cache adapter fails, GoModularAuth automatically degrades gracefully to the Store without breaking user authentication.

---

## 7. Workflow Hooks & Events

- **Hooks** (`app.Hooks()`): Intervene in execution flows synchronously. `Before*` hooks can validate, mutate inputs, or abort operations before transaction commit.
- **Events** (`app.Events()`): Observational post-commit notifications (`user.created`, `user.signed_in`, `password.changed`, etc.) for audit logging and external messaging.

```go
// Hook: Block or transform sign-ups
app.Hooks().BeforeSignUp(func(ctx context.Context, in *auth.SignUpInput) error {
	// Custom business validations...
	return nil
})

// Event: Observational audit logging
app.Events().Subscribe(auth.EventUserSignedIn, func(ctx context.Context, e auth.Event) {
	fmt.Printf("User signed in: %s at %v\n", e.Subject, e.Time)
})
```

---

## 8. Plugin System

Plugins extend core functionality by implementing `auth.PluginModule`:

```go
type MyPlugin struct{}

func (p *MyPlugin) ID() string { return "myplugin" }

func (p *MyPlugin) Init(h *auth.Host) error {
	// Register capabilities, hooks, or event subscribers
	return auth.Provide[MyCapability](h, &myCapabilityImpl{auth: h.Auth()})
}
```

Applications retrieve plugin capabilities in a strongly typed manner using Go generic methods:

```go
capability, err := app.Get[MyCapability]()
```

---

## 9. License

MIT License. See [LICENSE](LICENSE) for details.
