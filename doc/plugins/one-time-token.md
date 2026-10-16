# GoModularAuth One-Time Token Plugin (`gomodularauth-one-time-token`)

[![Go Reference](https://pkg.go.dev/badge/github.com/BladiCreator/go-modular-auth/plugins/one-time-token.svg)](https://pkg.go.dev/github.com/BladiCreator/go-modular-auth/plugins/one-time-token)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

The **One-Time Token Plugin** (`gomodularauth-one-time-token`, package `ott`) generates, consumes, and revokes cryptographically secure, single-use tokens bound to specific subjects and purposes. It serves as the foundational building block for email verification, password reset flows, magic links, step-up authentication, and transaction confirmations.

---

## Table of Contents

- [Overview & Problem Solved](#overview--problem-solved)
- [Architecture & Design Principles](#architecture--design-principles)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration Options](#configuration-options)
- [Primary Capability API](#primary-capability-api)
- [Persistence & Unified Schema](#persistence--unified-schema)
- [Cache Semantics](#cache-semantics)
- [Observational Events](#observational-events)
- [Security Model & Invariants](#security-model--invariants)
- [Testing & Examples](#testing--examples)
- [License](#license)

---

## Overview & Problem Solved

Modern authentication architectures frequently need short-lived, single-use tokens to authorize high-risk actions outside standard session cookies:

- **Password Resets**: Grant temporary permission to reset a forgotten credential.
- **Email Verification**: Confirm ownership of an email address upon registration.
- **Magic Links**: Frictionless passwordless login via emailed tokens.
- **Step-Up Authorizations**: Authorize sensitive actions (such as wire transfers or API key generations).

The `one-time-token` plugin solves this cleanly by:
- Wrapping Core's robust `verification` subsystem in a high-level, fluent capability.
- Enforcing **atomic consumption**: once a token is read, it cannot be reused.
- Publishing structured audit events (`created`, `consumed`, `revoked`) to Core's event bus.
- Supporting fine-grained TTL and purpose overrides on a per-call basis.

---

## Architecture & Design Principles

```text
Application Flow (Password Reset / Magic Link)
            │
            ▼
auth.Get[ott.OneTimeToken](engine)
            │
            ▼
┌────────────────────────────────────────────────────────┐
│        gomodularauth-one-time-token (Plugin)           │
│                                                        │
│  - High-Entropy Token Generation                       │
│  - Purpose-Scoped Validation Boundaries                │
│  - Single-Use Consumption Semantics                    │
│  - Observational Event Publication                     │
└──────────────┬──────────────────────────┬──────────────┘
               │                          │
               ▼                          ▼
┌──────────────────────────────┐  ┌──────────────────────┐
│ Core Verification Subsystem  │  │ Core Events Bus      │
│ ctx.Core().IssueToken()      │  │ ctx.Events().Publish │
│ ctx.Core().ConsumeToken()    │  │                      │
└──────────────┬───────────────┘  └──────────────────────┘
               │
               ▼
┌──────────────────────────────┐
│ adapter.Adapter              │
│ (Tokens storage)             │
└──────────────────────────────┘
```

The plugin adheres strictly to GoModularAuth's architectural principles:
- **No Schema Duplication**: Reuses Core's verification token storage tables and indexes.
- **Clock Mocking**: Uses `sdk.Context.Now()` to enable deterministic and freeze-frame testing.
- **Event-Driven**: Emits observable domain events on token lifecycle transitions.

---

## Installation

```bash
go get github.com/BladiCreator/go-modular-auth/plugins/one-time-token
```

---

## Quick Start

```go
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	adaptermem "github.com/BladiCreator/go-modular-auth/adapters/memory"
	ott "github.com/BladiCreator/go-modular-auth/plugins/one-time-token"
)

func main() {
	ctx := context.Background()

	// 1. Initialize GoModularAuth with the One-Time Token plugin
	engine, err := auth.New(auth.Config{
		Adapter: adaptermem.NewAdapter(),
		Plugins: []auth.PluginModule{
			ott.New(
				ott.WithTTL(15 * time.Minute),
				ott.WithPurpose("auth:magic-link"),
			),
		},
	})
	if err != nil {
		log.Fatalf("failed to initialize auth: %v", err)
	}

	// 2. Resolve OneTimeToken capability
	tokens, err := auth.Get[ott.OneTimeToken](engine)
	if err != nil {
		log.Fatalf("failed to resolve OneTimeToken: %v", err)
	}

	// 3. Generate a token bound to a user ID
	rawToken, err := tokens.Generate(ctx, "usr_12345")
	if err != nil {
		log.Fatalf("failed to generate token: %v", err)
	}
	fmt.Printf("Generated OTT: %s\n", rawToken)

	// 4. Consume token atomically
	consumed, err := tokens.Consume(ctx, rawToken)
	if err != nil {
		log.Fatalf("failed to consume token: %v", err)
	}
	fmt.Printf("Successfully consumed token for subject: %s (Purpose: %s)\n",
		consumed.Subject, consumed.Purpose)

	// 5. Replay attempt immediately fails
	_, err = tokens.Consume(ctx, rawToken)
	if err != nil {
		fmt.Println("Expected replay failure: token already consumed or expired!")
	}
}
```

---

## Configuration Options

Plugin-level configuration is passed to `ott.New(opts ...Option)`:

```go
ottMod := ott.New(
    ott.WithTTL(30 * time.Minute),
    ott.WithPurpose("user:password-reset"),
)
```

| Option | Default | Description |
| :--- | :--- | :--- |
| `WithTTL(ttl time.Duration)` | `10 * time.Minute` | Sets the default expiration lifetime for generated tokens. |
| `WithPurpose(p verification.Purpose)` | `"ott:token"` | Sets the default verification purpose partition. |

### Per-Invocation Options

Both `Generate`, `Consume`, and `Revoke` accept per-invocation overrides:

```go
// Override TTL for a specific token
token, err := tokens.Generate(ctx, "usr_123", ott.WithCustomTTL(2*time.Minute))

// Consume with a specific purpose
vt, err := tokens.Consume(ctx, tokenStr, ott.WithCustomPurpose("transaction:wire-transfer"))
```

| GenerateOption | Description |
| :--- | :--- |
| `WithCustomTTL(ttl time.Duration)` | Overrides the TTL for a single token generation. |
| `WithCustomPurpose(p verification.Purpose)` | Overrides the token purpose boundary for that invocation. |

---

## Primary Capability API

The primary capability is exposed through `ott.OneTimeToken`, resolved via `auth.Get[ott.OneTimeToken](engine)`.

### Interface Definition

```go
package ott

import (
	"context"

	"github.com/BladiCreator/go-modular-auth/verification"
)

type OneTimeToken interface {
	// Generate creates a secure, single-use token bound to subject.
	Generate(ctx context.Context, subject string, opts ...GenerateOption) (string, error)

	// Consume atomically consumes the token and returns the underlying verification token.
	Consume(ctx context.Context, token string, opts ...GenerateOption) (*verification.Token, error)

	// Revoke invalidates all active tokens for the given subject and purpose.
	Revoke(ctx context.Context, subject string, opts ...GenerateOption) error
}
```

### Sentinel Errors

| Error | Description |
| :--- | :--- |
| `ErrInvalidSubject` | The `subject` string supplied to `Generate` or `Revoke` is empty. |
| `ErrInvalidToken` | The token string is empty, expired, already consumed, or not found. |
| `ErrInvalidTTL` | The TTL supplied to `Generate` is non-positive (`<= 0`). |

---

## Persistence & Unified Schema

- **No Standalone Database Tables**: The plugin delegates storage directly to Core's verification table via `ctx.Core().IssueToken(...)`, `ctx.Core().ConsumeToken(...)`, and `ctx.Core().RevokeTokens(...)`.
- The storage guarantees transactional isolation and row-level locking during token consumption to prevent race conditions.

---

## Cache Semantics

- Verification tokens require atomic write-through or transactional storage. Caching token validity outside the database is discouraged to prevent replay vulnerabilities during distributed race conditions.

---

## Observational Events

The plugin publishes structured audit events to Core's event bus:

| Event Name | Constant | Payload Struct | Description |
| :--- | :--- | :--- | :--- |
| `one_time_token.created` | `events.EventTokenCreated` | `TokenCreatedPayload` | Emitted immediately after successful token creation. |
| `one_time_token.consumed` | `events.EventTokenConsumed` | `TokenConsumedPayload` | Emitted when a token is verified and consumed. |
| `one_time_token.revoked` | `events.EventTokenRevoked` | `TokenCreatedPayload` | Emitted when tokens for a subject are revoked. |

### Payload Types

```go
type TokenCreatedPayload struct {
	Subject string `json:"subject"`
	Purpose string `json:"purpose"`
}

type TokenConsumedPayload struct {
	TokenID string `json:"token_id"`
	Subject string `json:"subject"`
	Purpose string `json:"purpose"`
}
```

---

## Security Model & Invariants

1. **Atomic Consumption**: Tokens can only be consumed once. Parallel consumption requests for the same token will result in exactly one success and subsequent failures with `ErrInvalidToken`.
2. **Purpose Separation**: Tokens generated under purpose `"ott:token"` cannot be consumed under purpose `"user:password-reset"`. This prevents cross-protocol token substitution attacks.
3. **Entropy**: Core generates tokens using CSPRNG (`crypto/rand`) with high entropy to ensure infeasibility of brute-force enumeration attacks.

---

## Testing & Examples

Unit test demonstrating atomic consumption and replay protection:

```go
func TestOTTReplayProtection(t *testing.T) {
	ctx := context.Background()
	engine, _ := auth.New(auth.Config{
		Adapter: adaptermem.NewAdapter(),
		Plugins: []auth.PluginModule{ott.New()},
	})

	tokens, _ := auth.Get[ott.OneTimeToken](engine)

	rawToken, err := tokens.Generate(ctx, "usr_test")
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	vt, err := tokens.Consume(ctx, rawToken)
	if err != nil || vt.Subject != "usr_test" {
		t.Fatalf("failed to consume valid token: %v", err)
	}

	// Replay must fail
	_, err = tokens.Consume(ctx, rawToken)
	if err == nil {
		t.Fatal("expected replay attempt to fail")
	}
}
```

---

## License

MIT License. See [LICENSE](file:///media/vladimir/Storage/Projects/Go/go-modular-auth/LICENSE) for details.
