# GoModularAuth Service Accounts Plugin (`gomodularauth-service-accounts`)

[![Go Reference](https://pkg.go.dev/badge/github.com/BladiCreator/go-modular-auth/plugins/service-accounts.svg)](https://pkg.go.dev/github.com/BladiCreator/go-modular-auth/plugins/service-accounts)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

The **Service Accounts Plugin** (`gomodularauth-service-accounts`, package `serviceaccounts`) provides first-class identities for machine-to-machine (M2M) communication, background daemons, cron jobs, microservices, and CI/CD pipelines.

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

Non-human actors (microservices, ingestion pipelines, automated runners) require authentication mechanisms different from human users:

- **No Human Credentials**: Daemons cannot perform MFA prompts, email verification, or captcha challenges.
- **Overprivileged User Impersonation**: Sharing real user accounts or admin credentials with automated scripts creates severe auditing and credential leakage hazards.
- **Rotatable Secrets**: Automated systems need predictable secret rotation without service disruption.

The `service-accounts` plugin solves this by:
- Creating dedicated machine identities (`ServiceAccount`) with an assigned `OwnerID` and fine-grained `Scopes`.
- Generating high-entropy secrets (prefixed with `sec_`) that are hashed using SHA-256; raw secrets are returned only upon initial generation and rotation.
- Timing-attack safe credential verification using `crypto/subtle.ConstantTimeCompare`.
- Zero-downtime secret rotation and instant revocation.

---

## Architecture & Design Principles

```text
Microservice / Daemon / Pipeline
            │
            ▼ Credentials (id: sa_..., secret: sec_...)
auth.Get[serviceaccounts.ServiceAccountManager](engine)
            │
            ▼
┌────────────────────────────────────────────────────────┐
│     gomodularauth-service-accounts (Plugin)            │
│                                                        │
│  - M2M Identity Lifecycle (Create, List, Revoke)       │
│  - CSPRNG Secret Generation (sec_<hex>)                │
│  - Constant-Time Secret Verification (subtle)          │
│  - Atomic Secret Rotation                              │
└──────────────┬──────────────────────────┬──────────────┘
               │                          │
               ▼                          ▼
┌──────────────────────────────┐  ┌──────────────────────┐
│ Model: service_accounts      │  │ Core auth.Host       │
│ (schema.RegisterSchema)      │  │  - Context Clock     │
└──────────────┬───────────────┘  └──────────────────────┘
               │
               ▼
┌──────────────────────────────┐
│ adapter.Adapter              │
│ (PostgreSQL, SQLite, Memory) │
└──────────────────────────────┘
```

The plugin adheres strictly to GoModularAuth's architectural principles:
- **One-Way Secret Storage**: Raw secrets are never saved in the database; only SHA-256 hashes are persisted.
- **Timing Attack Resilience**: Verifications use `subtle.ConstantTimeCompare` to ensure constant-time comparisons.
- **Unified Schema**: Models register through `schema.RegisterSchema` ensuring native compatibility across all GoModularAuth storage adapters.

---

## Installation

```bash
go get github.com/BladiCreator/go-modular-auth/plugins/service-accounts
```

---

## Quick Start

```go
package main

import (
	"context"
	"fmt"
	"log"

	auth "github.com/BladiCreator/go-modular-auth"
	adaptermem "github.com/BladiCreator/go-modular-auth/adapters/memory"
	serviceaccounts "github.com/BladiCreator/go-modular-auth/plugins/service-accounts"
)

func main() {
	ctx := context.Background()

	// 1. Initialize GoModularAuth with Service Accounts plugin
	engine, err := auth.New(auth.Config{
		Adapter: adaptermem.NewAdapter(),
		Plugins: []auth.PluginModule{
			serviceaccounts.New(),
		},
	})
	if err != nil {
		log.Fatalf("failed to initialize auth: %v", err)
	}

	// 2. Resolve ServiceAccountManager capability
	mgr, err := auth.Get[serviceaccounts.ServiceAccountManager](engine)
	if err != nil {
		log.Fatalf("failed to resolve ServiceAccountManager: %v", err)
	}

	// 3. Create a new Service Account
	sa, secret, err := mgr.Create(ctx, serviceaccounts.CreateInput{
		Name:        "BillingExporter",
		Description: "Nightly cron job exporting invoice summaries",
		OwnerID:     "usr_lead_dev",
		Scopes:      []string{"invoices:read", "reports:export"},
	})
	if err != nil {
		log.Fatalf("failed to create service account: %v", err)
	}
	fmt.Printf("Created Service Account: %s (ID: %s)\n", sa.Name, sa.ID)
	fmt.Printf("Save this secret securely (shown only once): %s\n", secret)

	// 4. Authenticate service account request
	authenticatedSA, err := mgr.Authenticate(ctx, sa.ID, secret)
	if err != nil {
		log.Fatalf("authentication failed: %v", err)
	}
	fmt.Printf("Successfully authenticated machine identity: %s\n", authenticatedSA.Name)

	// 5. Rotate secret atomically
	newSecret, err := mgr.RotateSecret(ctx, sa.ID)
	if err != nil {
		log.Fatalf("failed to rotate secret: %v", err)
	}
	fmt.Printf("New rotated secret: %s\n", newSecret)
}
```

---

## Configuration Options

The plugin constructor `serviceaccounts.New(opts ...Option)` accepts functional configuration options:

```go
saMod := serviceaccounts.New(
    // Extensible options pattern
)
```

| Type / Constructor | Description |
| :--- | :--- |
| `serviceaccounts.New(opts ...Option) *Module` | Instantiates the Service Accounts module and registers unified schema models. |
| `serviceaccounts.Config` | Internal configuration structure. |
| `serviceaccounts.Option` | Functional option closure modifying `*Config`. |

---

## Primary Capability API

The primary capability is exposed through `serviceaccounts.ServiceAccountManager`, resolved via `auth.Get[serviceaccounts.ServiceAccountManager](engine)`.

### Interface Definition

```go
package serviceaccounts

import (
	"context"
)

type ServiceAccountManager interface {
	// Create provisions a new service account identity and returns the unhashed plaintext secret.
	Create(ctx context.Context, in CreateInput) (*ServiceAccount, string, error)

	// Authenticate checks an ID and plaintext secret in constant time. Returns ErrInvalidSecret if invalid or ErrInactive if deactivated.
	Authenticate(ctx context.Context, id, secret string) (*ServiceAccount, error)

	// RotateSecret generates a new secret for an existing account, invalidating previous secrets atomically.
	RotateSecret(ctx context.Context, id string) (string, error)

	// Get retrieves a service account record by ID.
	Get(ctx context.Context, id string) (*ServiceAccount, error)

	// List queries service accounts filtered by owner ID.
	List(ctx context.Context, ownerID string) ([]*ServiceAccount, error)

	// Revoke deactivates the account (Active = false), instantly blocking all future authentication.
	Revoke(ctx context.Context, id string) error
}
```

### Domain Entities

```go
type ServiceAccount struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	OwnerID     string    `json:"owner_id"`
	Scopes      []string  `json:"scopes"`
	SecretHash  string    `json:"secret_hash"`
	Active      bool      `json:"active"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type CreateInput struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	OwnerID     string   `json:"owner_id"`
	Scopes      []string `json:"scopes,omitempty"`
}
```

### Sentinel Errors

| Error | Description |
| :--- | :--- |
| `ErrNotFound` | The requested service account does not exist. |
| `ErrInactive` | The service account is deactivated (`Active == false`). |
| `ErrInvalidSecret` | The credentials provided do not match or are malformed. |
| `ErrInvalidName` | The service account name is empty. |
| `ErrInvalidOwnerID` | The owner ID is empty. |

---

## Persistence & Unified Schema

The plugin registers a single model via `schema.RegisterSchema`:

### Model `service_accounts` (`ModelServiceAccounts`)
- **Primary Key**: `id` (string, prefixed `sa_<hex>`)
- **Fields**:
  - `id` (TypeString, Required)
  - `name` (TypeString, Required)
  - `description` (TypeString)
  - `owner_id` (TypeString, Required)
  - `scopes` (TypeJSON)
  - `secret_hash` (TypeString, Required)
  - `active` (TypeBool, Required)
  - `created_at` (TypeTime, Required)
  - `updated_at` (TypeTime, Required)
- **Indexes**:
  - `idx_service_accounts_owner_id` on `owner_id`

---

## Cache Semantics

- Lookups by `id` use primary key index queries.
- When wrapping authentication in a caching layer, positive validations can be cached briefly; invoking `Revoke` or `RotateSecret` must invalidate any cached authorization decisions immediately.

---

## Observational Events

- Service account operations are high-impact security actions. Typical monitoring pipelines observe:
  - Account provisioning (`Create`) and owner attribution.
  - Secret rotations (`RotateSecret`).
  - Account revocations (`Revoke`).
  - Failed machine authentication attempts (`ErrInvalidSecret`).

---

## Security Model & Invariants

1. **One-Way Hashing**: Secrets are 32 bytes of CSPRNG entropy (`crypto/rand`) prefixed with `sec_`. Only `sha256.Sum256(secret)` is stored.
2. **Timing Attack Protection**: Hash comparisons in `Authenticate` use `crypto/subtle.ConstantTimeCompare` to avoid timing side-channel attacks.
3. **Instant Revocation**: Calling `Revoke(ctx, id)` sets `Active = false`. Any subsequent calls to `Authenticate` fail immediately with `ErrInactive`.

---

## Testing & Examples

Unit test demonstrating service account creation, authentication, and secret rotation:

```go
func TestServiceAccountLifecycle(t *testing.T) {
	ctx := context.Background()
	engine, _ := auth.New(auth.Config{
		Adapter: adaptermem.NewAdapter(),
		Plugins: []auth.PluginModule{serviceaccounts.New()},
	})

	mgr, _ := auth.Get[serviceaccounts.ServiceAccountManager](engine)

	sa, secret, err := mgr.Create(ctx, serviceaccounts.CreateInput{
		Name:    "worker",
		OwnerID: "usr_admin",
	})
	if err != nil {
		t.Fatalf("failed to create: %v", err)
	}

	// Validate secret
	authed, err := mgr.Authenticate(ctx, sa.ID, secret)
	if err != nil || authed.ID != sa.ID {
		t.Fatalf("authentication failed: %v", err)
	}

	// Rotate secret
	newSecret, err := mgr.RotateSecret(ctx, sa.ID)
	if err != nil {
		t.Fatalf("rotation failed: %v", err)
	}

	// Old secret must fail
	_, err = mgr.Authenticate(ctx, sa.ID, secret)
	if err == nil {
		t.Fatal("expected old secret to be rejected")
	}

	// New secret must pass
	_, err = mgr.Authenticate(ctx, sa.ID, newSecret)
	if err != nil {
		t.Fatalf("expected new secret to pass: %v", err)
	}
}
```

---

## License

MIT License. See [LICENSE](file:///media/vladimir/Storage/Projects/Go/go-modular-auth/LICENSE) for details.
