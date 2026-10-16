# GoModularAuth SCIM Plugin (`gomodularauth-scim`)

[![Go Reference](https://pkg.go.dev/badge/github.com/BladiCreator/go-modular-auth/plugins/scim.svg)](https://pkg.go.dev/github.com/BladiCreator/go-modular-auth/plugins/scim)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

The **SCIM Plugin** (`gomodularauth-scim`) implements the **System for Cross-domain Identity Management (SCIM 2.0)** protocol (RFC 7643 and RFC 7644). It allows enterprise identity systems (Okta, Microsoft Entra ID / Azure AD, PingIdentity, OneLogin) to automatically provision, update, and de-provision users and groups into your GoModularAuth application.

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

In enterprise B2B SaaS deployments, enterprise IT departments require automated lifecycle management for employee access:

- **Automated Onboarding**: When a new employee is added in Okta or Azure AD, their account is instantly provisioned in your app via SCIM.
- **Instant Offboarding**: When an employee leaves the company, their identity provider sends a deactivation request, terminating their access and revoking permissions immediately.
- **Group Synchronization**: Provision and synchronize departmental teams and role groups directly from corporate directories.

The `scim` plugin provides a complete, RFC-compliant SCIM 2.0 service provider implementation that bridges incoming directory operations directly with GoModularAuth Core users while storing SCIM metadata (`externalId`, `given_name`, `family_name`) and group memberships.

---

## Architecture & Design Principles

```text
Enterprise IdP (Okta / Entra ID)
            │
            ▼ SCIM 2.0 HTTP Requests (/scim/v2/Users, /scim/v2/Groups)
auth.Get[scim.SCIMProvider](engine)
            │
            ▼
┌────────────────────────────────────────────────────────┐
│             gomodularauth-scim (Plugin)                │
│                                                        │
│  - SCIM 2.0 Schema Serialization (RFC 7643)            │
│  - User Provisioning & De-provisioning                 │
│  - Group Management & Membership Synchronization       │
│  - ExternalID Resolution                               │
└──────────────┬──────────────────────────┬──────────────┘
               │                          │
               ▼                          ▼
┌──────────────────────────────┐  ┌──────────────────────┐
│ Model: scim_user_metadata    │  │ Core Users Store     │
│ Model: scim_groups           │  │ ctx.Store().Users()  │
│ (schema.RegisterSchema)      │  │                      │
└──────────────┬───────────────┘  └──────────────────────┘
               │
               ▼
┌──────────────────────────────┐
│ adapter.Adapter              │
│ (PostgreSQL, SQLite, Memory) │
└──────────────────────────────┘
```

The plugin adheres strictly to GoModularAuth's architectural principles:
- **Core User Alignment**: SCIM users map 1:1 with Core `user.User` entities. Core stores the primary identity (`id`, `email`), while the plugin stores SCIM-specific attributes (`external_id`, `given_name`, `family_name`, `active`).
- **Clean RFC Types**: Strong types located in subpackage `v2` match the official JSON structures defined by RFC 7643.

---

## Installation

```bash
go get github.com/BladiCreator/go-modular-auth/plugins/scim
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
	"github.com/BladiCreator/go-modular-auth/plugins/scim"
	v2 "github.com/BladiCreator/go-modular-auth/plugins/scim/v2"
)

func main() {
	ctx := context.Background()

	// 1. Initialize GoModularAuth with SCIM plugin
	engine, err := auth.New(auth.Config{
		Adapter: adaptermem.NewAdapter(),
		Plugins: []auth.PluginModule{
			scim.New(),
		},
	})
	if err != nil {
		log.Fatalf("failed to initialize auth: %v", err)
	}

	// 2. Resolve SCIMProvider capability
	provider, err := auth.Get[scim.SCIMProvider](engine)
	if err != nil {
		log.Fatalf("failed to resolve SCIMProvider: %v", err)
	}

	// 3. Provision a user as received from an Okta SCIM payload
	newUser, err := provider.CreateUser(ctx, &v2.UserResource{
		UserName:   "alice.smith@enterprise.com",
		ExternalID: "okta_user_99812",
		Active:     true,
		Name: &v2.Name{
			GivenName:  "Alice",
			FamilyName: "Smith",
		},
		Emails: []v2.Email{
			{Value: "alice.smith@enterprise.com", Primary: true},
		},
	})
	if err != nil {
		log.Fatalf("failed to provision SCIM user: %v", err)
	}
	fmt.Printf("Provisioned User ID: %s (External ID: %s)\n", newUser.ID, newUser.ExternalID)

	// 4. Create and synchronize a SCIM group
	group, err := provider.CreateGroup(ctx, &v2.GroupResource{
		DisplayName: "Security Engineers",
		Members: []v2.GroupMember{
			{Value: newUser.ID, Display: newUser.UserName},
		},
	})
	if err != nil {
		log.Fatalf("failed to create SCIM group: %v", err)
	}
	fmt.Printf("Created SCIM Group: %s (Members: %d)\n", group.DisplayName, len(group.Members))
}
```

---

## Configuration Options

The plugin constructor `scim.New(opts ...Option)` accepts functional configuration options:

```go
scimMod := scim.New(
    // Extensible options pattern
)
```

| Type / Constructor | Description |
| :--- | :--- |
| `scim.New(opts ...Option) *Module` | Instantiates the SCIM module and registers unified schema models. |
| `scim.Config` | Internal configuration structure. |
| `scim.Option` | Functional option closure modifying `*Config`. |

---

## Primary Capability API

The primary capability is exposed through `scim.SCIMProvider`, resolved via `auth.Get[scim.SCIMProvider](engine)`.

### Interface Definition

```go
package scim

import (
	"context"

	v2 "github.com/BladiCreator/go-modular-auth/plugins/scim/v2"
)

type SCIMProvider interface {
	// User Operations
	CreateUser(ctx context.Context, res *v2.UserResource) (*v2.UserResource, error)
	GetUser(ctx context.Context, id string) (*v2.UserResource, error)
	UpdateUser(ctx context.Context, res *v2.UserResource) (*v2.UserResource, error)
	DeleteUser(ctx context.Context, id string) error
	ListUsers(ctx context.Context, startIndex, count int) (*v2.ListResponse, error)

	// Group Operations
	CreateGroup(ctx context.Context, res *v2.GroupResource) (*v2.GroupResource, error)
	GetGroup(ctx context.Context, id string) (*v2.GroupResource, error)
	UpdateGroup(ctx context.Context, res *v2.GroupResource) (*v2.GroupResource, error)
	DeleteGroup(ctx context.Context, id string) error
	ListGroups(ctx context.Context, startIndex, count int) (*v2.ListResponse, error)
}
```

### Sentinel Errors

| Error | Description |
| :--- | :--- |
| `ErrNotFound` | The requested SCIM user or group does not exist. |
| `ErrConflict` | Resource conflict (e.g., duplicate `userName` or `externalId`). |
| `ErrInvalidRequest` | SCIM payload does not meet RFC requirements. |
| `ErrSchemaMismatch` | Requested operation does not match supported SCIM schemas. |

---

## Persistence & Unified Schema

The plugin registers two models via `schema.RegisterSchema`:

### Model `scim_user_metadata` (`ModelSCIMUserMetadata`)
- **Primary Key**: `user_id` (foreign key to Core `users.id`)
- **Fields**:
  - `user_id` (TypeString, Required)
  - `external_id` (TypeString)
  - `active` (TypeBool, Required)
  - `given_name` (TypeString)
  - `family_name` (TypeString)
  - `created_at` (TypeTime, Required)
  - `updated_at` (TypeTime, Required)
- **Indexes**:
  - `idx_scim_user_metadata_ext` on `external_id`

### Model `scim_groups` (`ModelSCIMGroups`)
- **Primary Key**: `id`
- **Fields**:
  - `id` (TypeString, Required)
  - `display_name` (TypeString, Required)
  - `member_ids` (TypeJSON)
  - `created_at` (TypeTime, Required)
  - `updated_at` (TypeTime, Required)

---

## Cache Semantics

- Lookups by `id` or `external_id` go through indexed store operations.
- SCIM endpoints are typically low-to-medium write volume (triggered only during HR changes), making database-direct operations optimal without caching lag.

---

## Observational Events

- SCIM operations represent high-impact corporate lifecycle events. Integration with Core's audit stream or external SIEM logging captures:
  - Account provisioning and initial assignment.
  - Deactivation events triggered by corporate HR departures.
  - Group privilege changes and role assignments.

---

## Security Model & Invariants

1. **Authentication Gate**: SCIM endpoints must always be protected by an authentication middleware (typically Bearer tokens or OAuth client credentials configured at the HTTP layer).
2. **Deactivation Semantics**: Updating a user with `Active: false` immediately marks the user as inactive and revokes active sessions.
3. **Core Integrity**: SCIM operations validate email formatting and prevent duplicate accounts using Core user uniqueness constraints.

---

## Testing & Examples

Unit test demonstrating user creation and retrieval via SCIM:

```go
func TestSCIMUserProvisioning(t *testing.T) {
	ctx := context.Background()
	engine, _ := auth.New(auth.Config{
		Adapter: adaptermem.NewAdapter(),
		Plugins: []auth.PluginModule{scim.New()},
	})

	provider, _ := auth.Get[scim.SCIMProvider](engine)

	created, err := provider.CreateUser(ctx, &v2.UserResource{
		UserName:   "bob@example.com",
		ExternalID: "ext_123",
		Active:     true,
	})
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	fetched, err := provider.GetUser(ctx, created.ID)
	if err != nil || fetched.UserName != "bob@example.com" {
		t.Fatalf("unexpected fetched user: %v", err)
	}
}
```

---

## License

MIT License. See [LICENSE](file:///media/vladimir/Storage/Projects/Go/go-modular-auth/LICENSE) for details.
