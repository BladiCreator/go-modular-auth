# GoModularAuth RBAC Plugin

`gomodularauth-rbac` provides decoupled, deterministic role-based access control (RBAC) authorization for GoModularAuth applications. It operates purely over Core `Principal` identities independently of authentication mechanisms and transport protocols.

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
		Adapter: adaptermem.NewAdapter(),
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

Detailed guide: [**`doc/plugins/rbac.md`**](../../doc/plugins/rbac.md).
