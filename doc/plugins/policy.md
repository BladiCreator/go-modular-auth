# GoModularAuth Policy Plugin

`gomodularauth-policy` provides composable policy-based and attribute-based access control (ABAC) for GoModularAuth applications. It evaluates complex multidimensional authorization requirements over `Principal`, `User`, `Organization`, `Resource`, `Action`, and `Context` attributes using idiomatic Go constructs without forcing a proprietary policy language.

## Features

- **Multi-Factor Context Evaluation**: Evaluates Principal, User, Organization, Resource, Action, and contextual Attributes.
- **Three-State Authorization**: Supports `Allow`, `Deny`, and `Challenge` (e.g. step-up MFA or re-authentication requirements).
- **Zero Proprietary DSL**: Formulates rules as explicit, type-safe Go functions and composable combinators (`AllOf`, `AnyOf`, `DenyOverrides`, `Not`).
- **Authentication Safeguard**: Enforces that policies cannot bypass core authentication invariants.
- **Derived Authorization Caching**: Caches authorization decisions with targeted invalidation by principal, resource, or rule registration.
- **Observability**: Emits structured audit events (`policy.evaluated`, `policy.registered`, `policy.removed`).
- **Pluggable Persistence**: Includes in-memory stores and PostgreSQL schema for policy definitions and audit logging.

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

## Step-Up Challenge Decisions

Policies can return an `EffectChallenge` decision when high-risk operations require step-up authentication:

```go
stepUpRule := policy.NewRule("wire:transfer", "Requires MFA above threshold", func(_ context.Context, req policy.Request) (policy.Decision, error) {
    if req.Attributes.GetInt("amount") > 5000 && !req.Attributes.GetBool("mfa_active") {
        return policy.Challenge("wire:transfer", policy.ChallengeInfo{
            Type:    "step_up_mfa",
            Message: "Wire transfers above $5000 require step-up MFA verification",
        }), nil
    }
    return policy.Allow("wire:transfer", "transfer approved"), nil
})
```

When evaluated, `authz.Authorize(ctx, req)` returns `policy.ErrChallengeRequired`, and `authz.Evaluate(ctx, req)` yields the detailed challenge payload for the transport layer.

## Policy Composition Combinators

- `AllOf(id, desc, ...rules)`: AND composition. Denies if any sub-rule denies; challenges if any challenges and none denies; allows if all allow.
- `AnyOf(id, desc, ...rules)`: OR composition. Allows immediately if any sub-rule allows.
- `DenyOverrides(id, desc, ...rules)`: Standard ABAC combination algorithm. Denies if any denies, challenges if any challenges, allows if at least one allows.
- `Not(id, desc, rule)`: Logical inversion of rule output.

## Cache Invalidation Semantics

- **By Principal**: `authz.InvalidatePrincipalCache(ctx, principalSubject)` evicts cached decisions for that identity.
- **By Resource**: `authz.InvalidateResourceCache(ctx, resourceType, resourceID)` evicts cached decisions referencing that resource.
- **On Mutation**: Registering or removing policies automatically purges the entire derived decision cache.
