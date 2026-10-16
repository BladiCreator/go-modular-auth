# GoModularAuth Policy Plugin

`gomodularauth-policy` provides composable policy-based and attribute-based access control (ABAC) for GoModularAuth applications. It evaluates complex multidimensional authorization requirements over `Principal`, `User`, `Organization`, `Resource`, `Action`, and `Context` attributes using idiomatic Go constructs without forcing a proprietary policy language.

## Installation

```bash
go get github.com/BladiCreator/go-modular-auth/plugins/policy
```

## Quick Start

```go
package main

import (
	"context"
	"log"

	auth "github.com/BladiCreator/go-modular-auth"
	adaptermem "github.com/BladiCreator/go-modular-auth/adapters/memory"
	policy "github.com/BladiCreator/go-modular-auth/plugins/policy"
	"github.com/BladiCreator/go-modular-auth/plugins/policy/plugins"
)

func main() {
	ctx := context.Background()

	// 1. Define composable rules
	ownerOnly := policy.AllOf(
		"doc:manage",
		"Requires authenticated principal and resource ownership",
		policy.RequireAuthenticated(),
		policy.RequireResourceOwner(),
	)

	// 2. Initialize Policy plugin
	policyPlugin := policy.New(
		policy.WithInitialPolicies(ownerOnly),
	)

	// 3. Register with GoModularAuth
	a, err := auth.New(auth.Config{
		Adapter: adaptermem.NewAdapter(),
		Plugins: []auth.PluginModule{policyPlugin},
	})
	if err != nil {
		log.Fatalf("failed to init auth: %v", err)
	}

	// 4. Resolve typed capability
	authz, err := auth.Get[plugins.Policy](a)
	if err != nil {
		log.Fatalf("failed to get policy capability: %v", err)
	}

	// 5. Authorize request
	principal := auth.Principal{Subject: "user_123", Type: auth.PrincipalUser}
	res := policy.NewResource("document", "doc_999").WithOwner("user_123")

	err = authz.Authorize(ctx, policy.Request{
		Principal: principal,
		Resource:  res,
		Action:    "edit",
	})
	if err != nil {
		log.Printf("access denied: %v", err)
		return
	}

	log.Println("Access granted!")
}
```

Detailed guide: [**`doc/plugins/policy.md`**](../../doc/plugins/policy.md).
