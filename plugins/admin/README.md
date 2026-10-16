# GoModularAuth Admin Plugin (`gomodularauth-admin`)

`gomodularauth-admin` is a high-security administrative management plugin for [GoModularAuth](https://github.com/BladiCreator/go-modular-auth). It provides privileged operations over Core authentication identities, accounts, credentials, sessions, and multi-tenant organization state.

## Installation

```bash
go get github.com/BladiCreator/go-modular-auth/plugins/admin
```

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

Detailed guide: [**`doc/plugins/admin.md`**](../../doc/plugins/admin.md).
