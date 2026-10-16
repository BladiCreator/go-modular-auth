# GoModularAuth LastLogin Plugin (`gomodularauth-lastlogin`)

[![Go Reference](https://pkg.go.dev/badge/github.com/BladiCreator/go-modular-auth/plugins/lastlogin.svg)](https://pkg.go.dev/github.com/BladiCreator/go-modular-auth/plugins/lastlogin)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

The **LastLogin Plugin** (`gomodularauth-lastlogin`) tracks and records user authentication activity, timestamps, authentication methods (passwords, OAuth, passkeys, magic links), and originating IP/User-Agent metadata.

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

Security-conscious applications and enterprise compliance frameworks require tracking authentication metadata:

- **Suspicious Activity & Anomaly Detection**: Identifying logins from unexpected IP ranges or geographic locations.
- **Account Stale Detection**: Identifying inactive user accounts eligible for de-provisioning.
- **User Transparency**: Showing users their "Last seen from IP: X at Time: Y" on security profile pages.
- **Decoupled User Model**: Storing login metadata in a dedicated model (`last_logins`) ensures that high-frequency write operations on authentication do not lock or bloat Core `users` table rows.

---

## Architecture & Design Principles

```text
Application / Auth Handlers
            │
            ▼
auth.Get[lastlogin.LastLogin](engine)
            │
            ▼
┌────────────────────────────────────────────────────────┐
│          gomodularauth-lastlogin (Plugin)              │
│                                                        │
│  - Captures Authentication Metadata (IP, UA, Method)   │
│  - Upsert Semantics keyed by user_id                   │
│  - Clock-aware timestamp recording (sdk.Context.Now)   │
└──────────────┬──────────────────────────┬──────────────┘
               │                          │
               ▼                          ▼
┌──────────────────────────────┐  ┌──────────────────────┐
│ Model: last_logins           │  │ Core auth.Host       │
│ (schema.RegisterSchema)      │  │  - Engine Context    │
│ Primary Key: user_id         │  │  - Time Mocking      │
└──────────────┬───────────────┘  └──────────────────────┘
               │
               ▼
┌──────────────────────────────┐
│ adapter.Adapter              │
│ (PostgreSQL, SQLite, Memory) │
└──────────────────────────────┘
```

The plugin adheres strictly to GoModularAuth's architectural principles:
- **Core Decoupling**: Core identity remains minimal; login activity is stored in an independent schema model.
- **Idempotent Upsert Semantics**: If a record already exists for a `user_id`, the plugin updates it in-place; otherwise, it creates a new record.
- **Zero Framework Ties**: Operates purely on Go standard library types (`context.Context`, `time.Time`, `string`).

---

## Installation

```bash
go get github.com/BladiCreator/go-modular-auth/plugins/lastlogin
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
	"github.com/BladiCreator/go-modular-auth/plugins/lastlogin"
)

func main() {
	ctx := context.Background()

	// 1. Initialize GoModularAuth with LastLogin plugin
	engine, err := auth.New(auth.Config{
		Adapter: adaptermem.NewAdapter(),
		Plugins: []auth.PluginModule{
			lastlogin.New(),
		},
	})
	if err != nil {
		log.Fatalf("failed to initialize auth: %v", err)
	}

	// 2. Resolve LastLogin capability
	tracker, err := auth.Get[lastlogin.LastLogin](engine)
	if err != nil {
		log.Fatalf("failed to resolve LastLogin: %v", err)
	}

	// 3. Record authentication event
	err = tracker.Record(ctx, &lastlogin.Record{
		UserID:     "usr_12345",
		AccountID:  "acc_passkey_99",
		Method:     "passkey",
		IP:         "198.51.100.42",
		UserAgent:  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
		LoggedInAt: time.Now().UTC(),
	})
	if err != nil {
		log.Fatalf("failed to record login: %v", err)
	}

	// 4. Retrieve login activity
	rec, err := tracker.Get(ctx, "usr_12345")
	if err != nil {
		log.Fatalf("failed to retrieve login record: %v", err)
	}

	fmt.Printf("User %s last logged in via %s from IP %s at %s\n",
		rec.UserID,
		rec.Method,
		rec.IP,
		rec.LoggedInAt.Format(time.RFC3339),
	)
}
```

---

## Configuration Options

The plugin constructor `lastlogin.New(opts ...Option)` accepts functional configuration options:

```go
lastLoginMod := lastlogin.New(
    // Extensible options pattern
)
```

| Type / Constructor | Description |
| :--- | :--- |
| `lastlogin.New(opts ...Option) *Module` | Instantiates the LastLogin module and registers unified schema models. |
| `lastlogin.Config` | Internal configuration structure. |
| `lastlogin.Option` | Functional option closure modifying `*Config`. |

---

## Primary Capability API

The primary capability is exposed through `lastlogin.LastLogin`, resolved via `auth.Get[lastlogin.LastLogin](engine)`.

### Interface Definition

```go
package lastlogin

import (
	"context"
)

// LastLogin defines the capability to track and query authentication history.
type LastLogin interface {
	// Record stores or updates the latest authentication metadata for a user.
	Record(ctx context.Context, rec *Record) error

	// Get retrieves the last login record for a user. Returns ErrNotFound if never logged in.
	Get(ctx context.Context, userID string) (*Record, error)
}
```

### Domain Entities

```go
type Record struct {
	UserID     string    `json:"user_id"`
	AccountID  string    `json:"account_id,omitempty"`
	Method     string    `json:"method"`
	IP         string    `json:"ip,omitempty"`
	UserAgent  string    `json:"user_agent,omitempty"`
	LoggedInAt time.Time `json:"logged_in_at"`
}
```

### Sentinel Errors

| Error | Description |
| :--- | :--- |
| `ErrNotFound` | No login activity record found for the provided `user_id`. |
| `ErrInvalidUserID` | The `user_id` provided is empty. |
| `ErrInvalidMethod` | The authentication method string is empty. |

---

## Persistence & Unified Schema

The plugin registers a single model via `schema.RegisterSchema`:

### Model `last_logins` (`ModelLastLogins`)
- **Primary Key**: `user_id`
- **Fields**:
  - `user_id` (TypeString, Required, Unique)
  - `account_id` (TypeString)
  - `method` (TypeString, Required)
  - `ip` (TypeString)
  - `user_agent` (TypeString)
  - `logged_in_at` (TypeTime, Required)

---

## Cache Semantics

- Since `user_id` is the primary key and lookups are 1:1, database reads are optimized through primary key index scans.
- If high-traffic environments cache `Get(ctx, userID)` results, cache invalidation must be triggered inside or immediately after `Record(...)` executions.

---

## Observational Events

Recording a login typically occurs within authentication lifecycle hooks (`AfterSignIn`). Listening to login events allows systems to trigger:
- Security notification emails on logins from new IP addresses or new user agents.
- Geolocation enrichment pipelines.
- SIEM ingestion for compliance audit logging.

---

## Security Model & Invariants

1. **Required Identifiers**: `UserID` and `Method` are mandatory; missing fields immediately trigger validation errors (`ErrInvalidUserID`, `ErrInvalidMethod`).
2. **Clock Source Invariance**: If `LoggedInAt` is not provided (zero value), the plugin automatically populates it using `sdk.Context.Now()` to guarantee monotonic and testable time.
3. **Upsert Idempotency**: Repeated calls to `Record` for the same user update existing rows without duplicate key errors.

---

## Testing & Examples

Unit tests execute without database dependencies using `adapters/memory`:

```go
func TestLastLoginLifecycle(t *testing.T) {
	ctx := context.Background()
	engine, _ := auth.New(auth.Config{
		Adapter: adaptermem.NewAdapter(),
		Plugins: []auth.PluginModule{lastlogin.New()},
	})

	tracker, _ := auth.Get[lastlogin.LastLogin](engine)

	err := tracker.Record(ctx, &lastlogin.Record{
		UserID: "usr_alice",
		Method: "password",
		IP:     "127.0.0.1",
	})
	if err != nil {
		t.Fatalf("unexpected record error: %v", err)
	}

	rec, err := tracker.Get(ctx, "usr_alice")
	if err != nil || rec.Method != "password" {
		t.Fatalf("unexpected retrieval result: %v", err)
	}
}
```

---

## License

MIT License. See [LICENSE](file:///media/vladimir/Storage/Projects/Go/go-modular-auth/LICENSE) for details.
