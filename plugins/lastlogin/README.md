# GoModularAuth LastLogin Plugin (`gomodularauth-lastlogin`)

[![Go Reference](https://pkg.go.dev/badge/github.com/BladiCreator/go-modular-auth/plugins/lastlogin.svg)](https://pkg.go.dev/github.com/BladiCreator/go-modular-auth/plugins/lastlogin)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

The **LastLogin Plugin** tracks and records user authentication activity, timestamps, authentication methods, and originating IP/User-Agent metadata.

## Installation

```bash
go get github.com/BladiCreator/go-modular-auth/plugins/lastlogin
```

## Quick Start

```go
package main

import (
	"context"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	adaptermem "github.com/BladiCreator/go-modular-auth/adapters/memory"
	"github.com/BladiCreator/go-modular-auth/plugins/lastlogin"
)

func main() {
	ctx := context.Background()

	engine, _ := auth.New(auth.Config{
		Adapter: adaptermem.NewAdapter(),
		Plugins: []auth.PluginModule{lastlogin.New()},
	})

	tracker, _ := auth.Get[lastlogin.LastLogin](engine)

	// Record authentication activity
	_ = tracker.Record(ctx, &lastlogin.Record{
		UserID:     "usr_alice",
		Method:     "password",
		IP:         "192.0.2.1",
		UserAgent:  "Mozilla/5.0",
		LoggedInAt: time.Now().UTC(),
	})

	// Query last login details
	rec, _ := tracker.Get(ctx, "usr_alice")
	_ = rec
}
```

Detailed guide: [**`doc/plugins/lastlogin.md`**](../../doc/plugins/lastlogin.md).
