# GoModularAuth Service Accounts Plugin (`gomodularauth-service-accounts`)

[![Go Reference](https://pkg.go.dev/badge/github.com/BladiCreator/go-modular-auth/plugins/service-accounts.svg)](https://pkg.go.dev/github.com/BladiCreator/go-modular-auth/plugins/service-accounts)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

The **Service Accounts Plugin** provides first-class identities, hashed secrets, and constant-time authentication for machine-to-machine (M2M) communication, microservices, and automated daemons.

## Installation

```bash
go get github.com/BladiCreator/go-modular-auth/plugins/service-accounts
```

## Quick Start

```go
package main

import (
	"context"

	auth "github.com/BladiCreator/go-modular-auth"
	adaptermem "github.com/BladiCreator/go-modular-auth/adapters/memory"
	serviceaccounts "github.com/BladiCreator/go-modular-auth/plugins/service-accounts"
)

func main() {
	ctx := context.Background()

	engine, _ := auth.New(auth.Config{
		Adapter: adaptermem.NewAdapter(),
		Plugins: []auth.PluginModule{serviceaccounts.New()},
	})

	mgr, _ := auth.Get[serviceaccounts.ServiceAccountManager](engine)

	// Create machine identity
	sa, secret, _ := mgr.Create(ctx, serviceaccounts.CreateInput{
		Name:    "worker-daemon",
		OwnerID: "usr_admin",
	})
	_ = secret

	// Authenticate machine identity (constant-time compare)
	authed, _ := mgr.Authenticate(ctx, sa.ID, secret)
	_ = authed
}
```

Detailed guide: [**`doc/plugins/service-accounts.md`**](../../doc/plugins/service-accounts.md).
