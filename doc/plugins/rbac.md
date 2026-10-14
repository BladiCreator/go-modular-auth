# GoModularAuth RBAC Plugin

`gomodularauth-rbac` provides decoupled, deterministic role-based access control (RBAC) authorization for GoModularAuth applications. It operates purely over Core `Principal` identities independently of authentication mechanisms and transport protocols.

## Features

- **Decoupled Authorization**: Consumes `auth.Principal` without binding to sessions, passwords, or HTTP layers.
- **Multidimensional Scopes**: Supports `global`, `organization`, and `service` scopes for role assignments.
- **Flexible Permission Matching**: Deterministic exact matching and wildcard patterns (`*`, `users:*`, `billing:invoices:*`).
- **Targeted Resources**: Evaluates access against structured `Resource` entities (supporting optional organization and service namespaces).
- **Fast Authorization Cache**: Caches derived decisions with automatic invalidation upon role or assignment mutations.
- **Event-Driven Observability**: Emits structured audit events (`rbac.role.created`, `rbac.role.assigned`, `rbac.access.evaluated`).
- **Pluggable Persistence**: Decoupled `store.Store` contract with included in-memory store and production PostgreSQL schema.

## Installation

```bash
go get github.com/BladiCreator/go-modular-auth/plugins/rbac
```

## Quick Start

```go
package main

import (
	"context"
	"log"

	auth "github.com/BladiCreator/go-modular-auth"
	adaptermem "github.com/BladiCreator/go-modular-auth/adapters/memory"
	rbac "github.com/BladiCreator/go-modular-auth/plugins/rbac"
	"github.com/BladiCreator/go-modular-auth/plugins/rbac/plugins"
)

func main() {
	ctx := context.Background()

	// 1. Initialize plugin
	rbacPlugin := rbac.New()

	// 2. Initialize Core with RBAC plugin
	a, err := auth.New(auth.Config{
		Store:   adaptermem.NewStore(),
		Plugins: []auth.PluginModule{rbacPlugin},
	})
	if err != nil {
		log.Fatalf("failed to initialize auth: %v", err)
	}

	// 3. Resolve strongly typed capability
	authz, err := auth.Get[plugins.RBAC](a)
	if err != nil {
		log.Fatalf("failed to resolve rbac capability: %v", err)
	}

	// 4. Define role
	err = authz.CreateRole(ctx, &rbac.Role{
		ID:          "role-editor",
		Name:        "editor",
		Scope:       rbac.ScopeGlobal,
		Permissions: []string{"articles:*", "media:upload"},
	})
	if err != nil {
		log.Fatalf("failed to create role: %v", err)
	}

	// 5. Assign role to principal
	principal := auth.Principal{
		Subject: "usr_12345",
		Type:    auth.PrincipalUser,
	}
	err = authz.AssignRole(ctx, &rbac.RoleAssignment{
		RoleID:           "role-editor",
		PrincipalSubject: principal.Subject,
		PrincipalType:    principal.Type,
		Scope:            rbac.ScopeGlobal,
	})
	if err != nil {
		log.Fatalf("failed to assign role: %v", err)
	}

	// 6. Authorize action
	res := rbac.NewResource("article", "art_987")
	err = authz.Authorize(ctx, principal, "articles:publish", res)
	if err != nil {
		log.Printf("access denied: %v", err)
		return
	}

	log.Println("principal authorized to publish article!")
}
```

## Scopes & Target Resources

The plugin evaluates whether an assigned role matches the target resource:

| Scope | Role Scope | Target Resource Matching Rule |
| :--- | :--- | :--- |
| `ScopeGlobal` | `"global"` | Applies to any resource across the system. |
| `ScopeOrganization` | `"organization"` | Applies only when `resource.OrganizationID == assignment.ScopeID`. |
| `ScopeService` | `"service"` | Applies only when `resource.ServiceID == assignment.ScopeID`. |

### Multi-Tenant Example

```go
// Organization role
err := authz.CreateRole(ctx, &rbac.Role{
    ID:          "org-admin",
    Name:        "organization_admin",
    Scope:       rbac.ScopeOrganization,
    Permissions: []string{"org:*"},
})

// Assign to Org 123
err = authz.AssignRole(ctx, &rbac.RoleAssignment{
    RoleID:           "org-admin",
    PrincipalSubject: "usr_alice",
    PrincipalType:    auth.PrincipalUser,
    Scope:            rbac.ScopeOrganization,
    ScopeID:          "org_123",
})

// Access in Org 123 is allowed
res123 := rbac.NewOrganizationResource("document", "doc_1", "org_123")
err = authz.Authorize(ctx, principal, "org:view", res123) // returns nil

// Access in Org 456 is forbidden
res456 := rbac.NewOrganizationResource("document", "doc_2", "org_456")
err = authz.Authorize(ctx, principal, "org:view", res456) // returns rbac.ErrForbidden
```

## Cache & Invalidation

When GoModularAuth Core Cache is configured, derived authorization decisions are automatically cached using namespaced keys (`gomodularauth:rbac:eval:...`).

Cache is invalidated automatically when:
- A role definition is updated or deleted.
- A role assignment is created or revoked.
- Explicitly via `authz.InvalidatePrincipalCache(ctx, subject)`.

## Events

The plugin emits observational audit events via GoModularAuth Core:

- `rbac.role.created`
- `rbac.role.updated`
- `rbac.role.deleted`
- `rbac.role.assigned`
- `rbac.role.revoked`
- `rbac.access.evaluated`
