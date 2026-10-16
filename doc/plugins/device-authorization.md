# GoModularAuth Device Authorization Plugin (`gomodularauth-device-authorization`)

[![Go Reference](https://pkg.go.dev/badge/github.com/BladiCreator/go-modular-auth/plugins/device-authorization.svg)](https://pkg.go.dev/github.com/BladiCreator/go-modular-auth/plugins/device-authorization)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

`gomodularauth-device-authorization` implements the **RFC 8628 OAuth 2.0 Device Authorization Grant** for [GoModularAuth](https://github.com/BladiCreator/go-modular-auth). It enables authentication on internet-connected devices with limited user input capabilities (Smart TVs, CLI tools, media streamers, game consoles, IoT devices) through a secondary browser session.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Public API (`DeviceAuthorization`)](#public-api-deviceauthorization)
- [Protocol Error Codes (RFC 8628 §3.5)](#protocol-error-codes-rfc-8628-35)
- [Audit Events](#audit-events)
- [Security Invariants](#security-invariants)
- [License](#license)

---

## Features

- **RFC 8628 Standard Compliance**: Supports Device Code, User Code, Verification URI, Polling, Expiration, and Token Issuance.
- **Unambiguous Human-Friendly Codes**: Generates user codes using an unambiguous alphanumeric character set (omits `0`, `O`, `1`, `I`) in formatted chunks (`WDJB-MJHT`).
- **Store as Source of Truth**: All grant state transitions (`pending` -> `authorized`/`denied` -> `consumed`) are persisted authoritatively in the database. Cache is **never** used as source of truth.
- **Atomic Single-Use Semantics**: Device codes can only be exchanged once for a session token. Subsequent polls are permanently rejected (`invalid_grant`), preventing replay attacks.
- **Slow-Down Throttling**: Automatically detects aggressive device polling and emits `slow_down` (incrementing required interval by 5 seconds per RFC 8628 §3.5).
- **Brute-Force & Rate Limiting Protection**: Enforces rate limiting per IP and tracks failed user-code submission attempts to lock grants before exhaustive search attacks succeed.
- **No Hardcoded HTTP Endpoints**: Exposes pure Go domain functions suitable for HTTP, gRPC, CLI, or WebSocket transport adapters.
- **Structured Audit Events**: Publishes observational audit events (`deviceauth.started`, `deviceauth.authorized`, `deviceauth.denied`, `deviceauth.consumed`) without leaking raw device codes.
- **Capability Discovery**: Resolves via `auth.Get[plugins.DeviceAuthorization]()`.

---

## Architecture

```text
                  +--------------------------------------+
                  |         Client Application           |
                  +--------------------------------------+
                                     |
                                     v
                  auth.Get[plugins.DeviceAuthorization]()
                                     |
                                     v
+-------------------------------------------------------------------------+
|                  GoModularAuth Core Authentication Engine               |
|  - Principal Context Boundary (auth.Principal)                          |
|  - Core EventBus (auth.Events)                                          |
|  - Session Issuance (Core CreateSession)                                |
+-------------------------------------------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
|             gomodularauth-device-authorization (Plugin Module)          |
|                                                                         |
|  [DeviceAuthorization Service]                                          |
|    |---> Start()           -> Genera device_code & user_code             |
|    |---> Poll()            -> Evalúa estado, slow_down e emite sesión   |
|    |---> VerifyUserCode()  -> Valida código para pantalla de consent     |
|    |---> Authorize()       -> Aprueba petición con Principal            |
|    |---> Deny()            -> Rechaza petición                          |
|                                                                         |
|  [Persistence Contract: store.Store]     [Rate Limiter: cache.Cache]    |
|    |-- PostgreSQL Adapter                   |-- Cache-backed Counter    |
|    |-- Memory Adapter                       \-- In-Memory Fallback      |
+-------------------------------------------------------------------------+
```

---

## Installation

```bash
go get github.com/BladiCreator/go-modular-auth/plugins/device-authorization
```

---

## Quick Start

```go
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	deviceauth "github.com/BladiCreator/go-modular-auth/plugins/device-authorization"
	"github.com/BladiCreator/go-modular-auth/plugins/device-authorization/plugins"
	adaptermem "github.com/BladiCreator/go-modular-auth/adapters/memory"
)

func main() {
	ctx := context.Background()

	// 1. Initialize storage adapters

	// 2. Configure GoModularAuth with Device Authorization Plugin
	a, err := auth.New(auth.Config{
		Adapter: adaptermem.NewAdapter(),
		Plugins: []auth.PluginModule{
			deviceauth.New(
				deviceauth.WithVerificationURI("https://auth.example.com/device"),
				deviceauth.WithExpiresIn(10*time.Minute),
				deviceauth.WithPollingInterval(5*time.Second),
			),
		},
	})
	if err != nil {
		log.Fatalf("failed to initialize auth: %v", err)
	}

	// 3. Resolve DeviceAuthorization Capability
	devAuth, err := auth.Get[plugins.DeviceAuthorization](a)
	if err != nil {
		log.Fatalf("failed to resolve capability: %v", err)
	}

	// 4. Device starts authorization flow (CLI or Smart TV)
	resp, err := devAuth.Start(ctx, deviceauth.DeviceAuthorizationRequestInput{
		ClientID: "smart_tv_app",
		Scope:    "read_profile stream_video",
	})
	if err != nil {
		log.Fatalf("failed to start device flow: %v", err)
	}

	fmt.Printf("Please visit: %s\n", resp.VerificationURI)
	fmt.Printf("Enter Code:   %s\n", resp.UserCode)

	// 5. Device polls token endpoint
	for {
		time.Sleep(time.Duration(resp.Interval) * time.Second)

		pollResp, err := devAuth.Poll(ctx, deviceauth.PollInput{
			DeviceCode: resp.DeviceCode,
			ClientID:   "smart_tv_app",
		})
		if errors.Is(err, deviceauth.ErrAuthorizationPending) {
			fmt.Println("Waiting for user authorization...")
			continue
		}
		if errors.Is(err, deviceauth.ErrSlowDown) {
			fmt.Println("Polling too quickly; slowing down...")
			resp.Interval += 5
			continue
		}
		if err != nil {
			log.Fatalf("polling failed: %v", err)
		}

		fmt.Printf("Authorization successful! Session Token: %s\n", pollResp.Token)
		break
	}
}
```

---

## Public API (`DeviceAuthorization`)

```go
type DeviceAuthorization interface {
    // Start initiates the device flow and returns device and user codes.
    Start(ctx context.Context, in DeviceAuthorizationRequestInput) (*DeviceAuthorizationResponse, error)

    // Poll checks device authorization status and issues tokens upon user approval.
    Poll(ctx context.Context, in PollInput) (*PollResponse, error)

    // VerifyUserCode inspects a user code submitted by the user on the verification page.
    VerifyUserCode(ctx context.Context, in VerifyUserCodeInput) (*UserCodeVerificationResult, error)

    // Authorize records user consent and associates the grant with the authorizing user.
    Authorize(ctx context.Context, in AuthorizeInput) error

    // Deny records user rejection of the authorization request.
    Deny(ctx context.Context, in DenyInput) error
}
```

---

## Protocol Error Codes (RFC 8628 §3.5)

| Sentinel Error | OAuth Error Code | Meaning |
| :--- | :--- | :--- |
| `ErrAuthorizationPending` | `authorization_pending` | Request is awaiting user approval; client should continue polling. |
| `ErrSlowDown` | `slow_down` | Client polled too fast; client must increase interval by 5 seconds. |
| `ErrAccessDenied` | `access_denied` | End user explicitly rejected the request. |
| `ErrExpiredToken` | `expired_token` | Device grant validity window expired. |
| `ErrInvalidGrant` | `invalid_grant` | Device code is invalid or already consumed (replay prevented). |
| `ErrMaxAttemptsExceeded` | - | Too many failed attempts on user code (anti brute-force lockout). |

---

## Audit Events

| Event Name | Description |
| :--- | :--- |
| `deviceauth.started` | Emitted when a new device flow is initiated (never includes raw device code). |
| `deviceauth.authorized` | Emitted when the end user approves the grant. |
| `deviceauth.denied` | Emitted when the end user rejects the grant. |
| `deviceauth.consumed` | Emitted when the device exchanges the grant for session credentials. |

---

## Security Invariants

1. **Replay Prevention**: When a device exchanges an authorized grant, the grant transition to `consumed` occurs inside an atomic transaction. Further poll attempts return `invalid_grant`.
2. **Device Code Hashing**: Only the SHA-256 hash of `device_code` is stored in the database.
3. **User Code Entropy & Locking**: Codes are generated with 8 unambiguous characters (`WDJB-MJHT`). Exceeding `MaxFailedAttempts` permanently invalidates the grant.
4. **Authoritative Persistence**: Polling timestamps, intervals, and statuses commit to database transactions so distributed server clusters maintain consistent throttling state.

---

## License

MIT License. See [LICENSE](file:///media/vladimir/Storage/Projects/Go/Go%20Modular%20Auth/go-modular-auth/plugins/device-authorization/LICENSE) for details.
