# GoModularAuth Admin Plugin (`gomodularauth-admin`)

[![Go Reference](https://pkg.go.dev/badge/github.com/BladiCreator/go-modular-auth/plugins/admin.svg)](https://pkg.go.dev/github.com/BladiCreator/go-modular-auth/plugins/admin)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

`gomodularauth-admin` is a high-security administrative management plugin for [GoModularAuth](https://github.com/BladiCreator/go-modular-auth). It provides privileged operations over Core authentication identities, accounts, credentials, sessions, and multi-tenant organization state.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Public API (`Admin`)](#public-api-admin)
- [Organization-Scoped Administration](#organization-scoped-administration)
- [Audit Events](#audit-events)
- [Security Invariants](#security-invariants)
- [License](#license)

---

## Features

- **User Inspection & Lookup**: Retrieve full administrative details for any user by UserID or normalized Email.
- **Paginated User Listings**: Search and filter accounts across status (`all`, `active`, `disabled`) with offset pagination.
- **Disable & Enable Users**: Instant suspension and reactivation of user access. Disabling revokes all active sessions immediately.
- **Workflow Interception**: Installs a `BeforeSignIn` hook to reject authentication attempts for disabled users with `ErrUserDisabled`.
- **Session Revocation**: Forcefully terminate all active sessions for targeted users.
- **Password Reset Initiation**: Issues secure, single-use, time-limited verification tokens without exposing current credentials.
- **Email Verification Override**: Manually mark email addresses as verified.
- **Account & Credential Inspection**: Inspect external provider linkages and credential metadata while strictly enforcing zero secret leakage.
- **User Deletion**: Atomically purges user records, sessions, credentials, accounts, tokens, and admin metadata.
- **Self-Lockout & Self-Deletion Protection**: Prevents administrators from accidentally disabling or deleting their own accounts.
- **Audit Logging**: Emits structured, observational events for every administrative action.
- **Multi-Tenant Administration**: Natively integrates with `gomodularauth-organizations` to support organization-scoped administration.
- **Capability Discovery**: Resolves via `auth.Get[plugins.Admin]()`.

---

## Architecture

```text
Application
    ↓
GoModularAuth Core (Principal, Events, Hooks, Stores)
    ↓
gomodularauth-admin (Capability: Admin, ScopedAdmin)
    ├── store.Store (PostgreSQL, Memory)
    └── cache.Cache (Cache-Aside for IsUserDisabled / IsAdmin)
```

The plugin adheres strictly to GoModularAuth's architectural principles:
- **Core Independence**: Core does not depend on this plugin.
- **Store as Source of Truth**: All state transitions occur through atomic store transactions.
- **Zero Framework Bloat**: No hard dependencies on HTTP routers, ORMs, or concrete databases.

---

## Installation

```bash
go get github.com/BladiCreator/go-modular-auth/plugins/admin
```

---

## Quick Start

```go
package main

import (
	"context"
	"log"

	auth "github.com/BladiCreator/go-modular-auth"
	"github.com/BladiCreator/go-modular-auth/adapters/memory"
	admin "github.com/BladiCreator/go-modular-auth/plugins/admin"
	"github.com/BladiCreator/go-modular-auth/plugins/admin/plugins"
)

func main() {
	ctx := context.Background()

	// 1. Initialize Adapter
	ad := memory.NewAdapter()

	// 2. Configure GoModularAuth with Admin Plugin
	a, err := auth.New(auth.Config{
		Adapter: ad,
		Plugins: []auth.PluginModule{
			admin.New(
				// Optional: Configure authorization policy
				admin.WithAuthorizerFunc(func(ctx context.Context, p auth.Principal, action, targetUserID string) error {
					if p.Subject == "admin_user_id" {
						return nil // authorized
					}
					return admin.ErrUnauthorized
				}),
			),
		},
	})
	if err != nil {
		log.Fatalf("failed to initialize auth: %v", err)
	}

	// 3. Resolve Admin Capability
	adm, err := auth.Get[plugins.Admin](a)
	if err != nil {
		log.Fatalf("failed to resolve Admin capability: %v", err)
	}

	// 4. Perform Administrative Operations
	adminPrincipal := auth.Principal{Subject: "admin_user_id", Type: auth.PrincipalUser}

	// Disable a user
	err = adm.DisableUser(ctx, adminPrincipal, "usr_target_123", "Terms of Service violation")
	if err != nil {
		log.Fatalf("failed to disable user: %v", err)
	}
}
```

---

## Public API (`Admin`)

```go
type Admin interface {
    LookupUser(ctx context.Context, p auth.Principal, userID string) (*UserDetail, error)
    LookupUserByEmail(ctx context.Context, p auth.Principal, email string) (*UserDetail, error)
    ListUsers(ctx context.Context, p auth.Principal, filter ListFilter) (*UserListResult, error)
    DisableUser(ctx context.Context, p auth.Principal, targetUserID string, reason string) error
    EnableUser(ctx context.Context, p auth.Principal, targetUserID string) error
    RevokeUserSessions(ctx context.Context, p auth.Principal, targetUserID string) error
    InitiatePasswordReset(ctx context.Context, p auth.Principal, targetUserID string) (string, error)
    VerifyUserEmail(ctx context.Context, p auth.Principal, targetUserID string) error
    InspectAccounts(ctx context.Context, p auth.Principal, targetUserID string) ([]AccountDetail, error)
    InspectCredentials(ctx context.Context, p auth.Principal, targetUserID string) ([]CredentialDetail, error)
    DeleteUser(ctx context.Context, p auth.Principal, targetUserID string) error
    SetAdminStatus(ctx context.Context, p auth.Principal, targetUserID string, isAdmin bool, role string) error
    IsUserDisabled(ctx context.Context, userID string) (bool, error)
    ForOrg(orgID string) ScopedAdmin
}
```

---

## Organization-Scoped Administration

When used alongside `gomodularauth-organizations`, `ForOrg(orgID)` returns a `ScopedAdmin` capability that isolates operations to a specific tenant:

```go
orgAdmin := adm.ForOrg("org_marketing_dept")

// Verifies caller has RoleAdmin or RoleOwner in 'org_marketing_dept'
// and target user belongs to that organization
err := orgAdmin.DisableUser(ctx, callerPrincipal, "usr_member_456", "Suspension")
```

---

## Audit Events

Every administrative action publishes an observational event to Core's `Events` dispatcher:

| Event Name | Description |
| :--- | :--- |
| `admin.user.disabled` | Published when an account is disabled and sessions are revoked |
| `admin.user.enabled` | Published when an account is reactivated |
| `admin.user.deleted` | Published when an account is permanently purged |
| `admin.session.revoked` | Published when active sessions are terminated |
| `admin.password_reset.initiated` | Published when a reset token is generated |
| `admin.email.verified` | Published when email verification is manually granted |
| `admin.role.assigned` | Published when administrative status/roles are assigned |

---

## Security Invariants

1. **Explicit Authorization**: Every administrative method mandates an `auth.Principal`. Unauthorized calls return `admin.ErrUnauthorized`.
2. **Never Expose Secrets**: `InspectCredentials` and `LookupUser` return sanitized `CredentialDetail` views that exclude hashes, salts, and secret keys.
3. **Self-Protection**: Administrators cannot disable or delete their own accounts, mitigating accidental lockout vulnerabilities.
4. **Cache-Aside Security**: Disabling a user invalidates cache entries immediately to prevent race conditions during sign-in verification.

---

## License

MIT License. See [LICENSE](file:///media/vladimir/Storage/Projects/Go/Go%20Modular%20Auth/go-modular-auth/plugins/admin/LICENSE) for details.
