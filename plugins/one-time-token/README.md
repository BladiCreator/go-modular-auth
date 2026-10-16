# GoModularAuth One-Time Token Plugin (`gomodularauth-one-time-token`)

[![Go Reference](https://pkg.go.dev/badge/github.com/BladiCreator/go-modular-auth/plugins/one-time-token.svg)](https://pkg.go.dev/github.com/BladiCreator/go-modular-auth/plugins/one-time-token)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

The **One-Time Token Plugin** generates, consumes, and revokes cryptographically secure, single-use tokens for password resets, email verification, and magic links.

## Installation

```bash
go get github.com/BladiCreator/go-modular-auth/plugins/one-time-token
```

## Quick Start

```go
package main

import (
	"context"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	adaptermem "github.com/BladiCreator/go-modular-auth/adapters/memory"
	ott "github.com/BladiCreator/go-modular-auth/plugins/one-time-token"
)

func main() {
	ctx := context.Background()

	engine, _ := auth.New(auth.Config{
		Adapter: adaptermem.NewAdapter(),
		Plugins: []auth.PluginModule{
			ott.New(ott.WithTTL(15 * time.Minute)),
		},
	})

	tokens, _ := auth.Get[ott.OneTimeToken](engine)

	// Generate single-use token
	token, _ := tokens.Generate(ctx, "usr_alice")

	// Consume token atomically
	vt, _ := tokens.Consume(ctx, token)
	_ = vt
}
```

Detailed guide: [**`doc/plugins/one-time-token.md`**](../../doc/plugins/one-time-token.md).
