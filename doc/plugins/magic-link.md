# GoModularAuth Magic Link Plugin (`gomodularauth-magic-link`)

[![Go Reference](https://pkg.go.dev/badge/github.com/BladiCreator/go-modular-auth/plugins/magic-link.svg)](https://pkg.go.dev/github.com/BladiCreator/go-modular-auth/plugins/magic-link)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

`gomodularauth-magic-link` provides passwordless authentication through secure, single-use, expiring email magic links for [GoModularAuth](https://github.com/BladiCreator/go-modular-auth).

---

## Table of Contents

- [1. Overview](#1-overview)
- [2. Installation](#2-installation)
- [3. Registration](#3-registration)
- [4. Capability API](#4-capability-api)
- [5. Configuration Options](#5-configuration-options)
- [6. Events](#6-events)
- [7. Security Architecture](#7-security-architecture)
- [8. License](#8-license)

---

## 1. Overview

Passwordless authentication using email magic links eliminates passwords while providing a secure sign-in experience. This plugin integrates directly into the GoModularAuth runtime by leveraging Core's `VerificationToken` primitive.

### Key Features
- **Cryptographically Secure Tokens**: Issued via GoModularAuth Core's CSPRNG with 256 bits of entropy.
- **No Plaintext Token Persistence**: Only SHA-256 digests are stored in the database.
- **Single-Use Semantics**: Atomically verified and marked used using check-and-set queries; replay attacks and concurrent redemptions are strictly prevented.
- **User Enumeration Prevention**: Requesting a magic link for an unregistered email address returns success without leaking account existence.
- **Email Adapter Integration**: Decoupled from SMTP transport by using the GoModularAuth `email.Sender` interface.
- **Session Integration**: Automatically establishes opaque, server-side sessions through Core's `CreateSession`.
- **Configurable Lifetime & Rate Limiting**: Built-in cooldown, sliding-window rate limiting (backed by Cache Counter), and custom security hooks.
- **Observability**: Emits non-sensitive `magiclink.requested` and `magiclink.consumed` events.

---

## 2. Installation

```bash
go get github.com/BladiCreator/go-modular-auth/plugins/magic-link
```

---

## 3. Registration

Install the plugin module into GoModularAuth during engine initialization:

```go
package main

import (
    "log"
    "time"

    auth "github.com/BladiCreator/go-modular-auth"
    adaptermem "github.com/BladiCreator/go-modular-auth/adapters/memory"
    magiclink "github.com/BladiCreator/go-modular-auth/plugins/magic-link"
)

func main() {
    a, err := auth.New(auth.Config{
        Adapter: adaptermem.NewAdapter(),
        Cache:   adaptermem.NewCache(),
        Email:   adaptermem.NewEmail(),

        Plugins: []auth.PluginModule{
            magiclink.New(
                magiclink.WithTTL(15 * time.Minute),
                magiclink.WithBaseURL("https://myapp.com/auth/magiclink/verify"),
                magiclink.WithAllowSignUp(true),
                magiclink.WithRateLimit(magiclink.RateLimitConfig{
                    Enabled:  true,
                    Max:      5,
                    Window:   15 * time.Minute,
                    Cooldown: 60 * time.Second,
                }),
            ),
        },
    })
    if err != nil {
        log.Fatalf("failed to initialize auth: %v", err)
    }

    // Retrieve capability
    ml, err := auth.Get[magiclink.MagicLink](a)
    if err != nil {
        log.Fatalf("magiclink plugin not installed: %v", err)
    }
}
```

---

## 4. Capability API

Applications interact with the typed `magiclink.MagicLink` interface:

```go
type MagicLink interface {
    // Request initiates passwordless authentication for an email.
    // If the email does not exist and AllowSignUp is false, it returns nil to prevent user enumeration.
    Request(ctx context.Context, in RequestInput) error

    // Authenticate validates and atomically consumes the token, establishes a session,
    // and returns the authentication outcome.
    Authenticate(ctx context.Context, in AuthenticateInput) (*auth.AuthResult, error)

    // Revoke deletes all active magic link tokens for the given email address.
    Revoke(ctx context.Context, email string) error
}
```

### Requesting a Magic Link
```go
err := ml.Request(ctx, magiclink.RequestInput{
    Email: "user@example.com",
})
if err != nil {
    // Handle validation or rate limit error
}
// Present a generic success message: "If an account exists, a link has been sent."
```

### Authenticating with a Token
```go
result, err := ml.Authenticate(ctx, magiclink.AuthenticateInput{
    Token: tokenFromQueryOrBody,
    Session: auth.SessionOptions{
        IPAddress: r.RemoteAddr,
        UserAgent: r.UserAgent(),
    },
})
if err != nil {
    // Handle ErrInvalidToken
}

// User is authenticated: result.User, result.Session, result.Token
```

---

## 5. Configuration Options

| Option | Type | Default | Description |
|---|---|---|---|
| `WithTTL` | `time.Duration` | `15m` | Token validity duration. |
| `WithAllowSignUp` | `bool` | `false` | Whether unknown emails create new accounts upon redemption. |
| `WithRevokePreviousOnRequest` | `bool` | `true` | Revokes existing outstanding tokens when a new one is requested. |
| `WithBaseURL` | `string` | `""` | Base URL used to build direct links (`?token=...`). |
| `WithRateLimit` | `RateLimitConfig` | Disabled | Configures request rate limits and cooldown intervals. |
| `WithMessageBuilder` | `MessageBuilder` | Default email | Customizes email subject and text/HTML template. |
| `WithHooks` | `*Hooks` | None | Attaches `BeforeRequest` and `BeforeConsume` security hooks. |
| `WithEmailSender` | `email.Sender` | Host Email | Overrides the host's email delivery adapter. |

---

## 6. Events

The plugin emits observational events after store operations commit:

| Event Name | Subject | Payload |
|---|---|---|
| `magiclink.requested` | User ID or Email | `MagicLinkRequestedPayload{Email, Subject, ExpiresAt}` |
| `magiclink.consumed` | User ID | `MagicLinkConsumedPayload{UserID, Email, SessionID, ConsumedAt}` |

*Note: In compliance with GoModularAuth security principles, plaintext tokens and session secrets are never published in events.*

---

## 7. Security Architecture

1. **Atomic Single-Use**: Consuming a token uses Core's conditional update (`WHERE used_at IS NULL`). Concurrent requests attempting to use the same token result in an atomic conflict (`store.ErrConflict`), ensuring only one consumer succeeds while all others receive `ErrInvalidToken`.
2. **Timing & Enumeration Resistance**: `Request` returns identical results regardless of whether an email address exists in the database.
3. **No Database Pollution**: Does not define redundant token entities or migrations; fully utilizes Core's `verification_tokens` table.
4. **Key Namespacing**: Cache rate-limiting keys follow `gomodularauth:magiclink:<resource>:<hash>` format using SHA-256 digests.

---

## 8. License

MIT License. See [LICENSE](LICENSE) for details.
