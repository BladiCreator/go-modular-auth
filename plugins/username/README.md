# GoModularAuth Username Plugin (`gomodularauth-username`)

An optional, production-ready identity plugin for [GoModularAuth](https://github.com/BladiCreator/go-modular-auth) that provides username-based authentication, normalization, validation, and lifecycle management without polluting the Core `user.User` entity.

## Installation

```bash
go get github.com/BladiCreator/go-modular-auth/plugins/username
```

## Quick Start

```go
package main

import (
	"context"
	"fmt"
	"log"

	auth "github.com/BladiCreator/go-modular-auth"
	adaptermem "github.com/BladiCreator/go-modular-auth/adapters/memory"
	"github.com/BladiCreator/go-modular-auth/plugins/username"
)

func main() {
	ctx := context.Background()

	// 1. Initialize GoModularAuth with the Username plugin
	app, err := auth.New(auth.Config{
		Adapter: adaptermem.NewAdapter(),
		Cache:   adaptermem.NewCache(),
		Plugins: []auth.PluginModule{
			username.New(),
		},
	})
	if err != nil {
		log.Fatalf("auth initialization failed: %v", err)
	}

	// 2. Retrieve the typed username capability
	userPlugin, err := auth.Get[username.Capability](app)
	if err != nil {
		log.Fatalf("plugin lookup failed: %v", err)
	}

	// 3. Register a user with email + username + password
	result, err := userPlugin.Register(ctx, username.RegisterInput{
		Email:    "alice@example.com",
		Username: "AliceSmith",
		Password: "SuperSecretPassword123!",
	})
	if err != nil {
		log.Fatalf("registration failed: %v", err)
	}
	fmt.Printf("Registered user: %s with session token: %s\n", result.User.ID, result.Token)

	// 4. Authenticate using username (case-insensitive by default)
	authRes, err := userPlugin.Authenticate(ctx, username.AuthenticateInput{
		Username: "alicesmith",
		Password: "SuperSecretPassword123!",
	})
	if err != nil {
		log.Fatalf("authentication failed: %v", err)
	}
	fmt.Printf("Authenticated user %s, issued session %s\n", authRes.User.ID, authRes.Session.ID)
}
```

Detailed guide: [**`doc/plugins/username.md`**](../../doc/plugins/username.md).
