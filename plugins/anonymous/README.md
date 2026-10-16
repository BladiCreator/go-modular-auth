# gomodularauth-anonymous

An official production-ready plugin for **GoModularAuth** that provides anonymous user identities, session issuance, lifecycle expiration, in-place conversion to permanent authenticated accounts, and account linking/merging with explicit authentication and privilege escalation prevention.

## Installation

```bash
go get github.com/BladiCreator/go-modular-auth/plugins/anonymous
```

## Quick Start

```go
package main

import (
	"log"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	adaptermem "github.com/BladiCreator/go-modular-auth/adapters/memory"
	"github.com/BladiCreator/go-modular-auth/plugins/anonymous"
	"github.com/BladiCreator/go-modular-auth/plugins/anonymous/plugins"
)

func main() {
	engine, err := auth.New(auth.Config{
		Adapter: adaptermem.NewAdapter(),
		Cache:   adaptermem.NewCache(),
		Plugins: []auth.PluginModule{
			anonymous.New(
				anonymous.WithIdentityTTL(14 * 24 * time.Hour),
			),
		},
	})
	if err != nil {
		log.Fatalf("failed to initialize auth: %v", err)
	}

	// Retrieve capability
	anon, err := auth.Get[plugins.Anonymous](engine)
	if err != nil {
		log.Fatalf("failed to retrieve Anonymous plugin: %v", err)
	}
}
```

Detailed guide: [**`doc/plugins/anonymous.md`**](../../doc/plugins/anonymous.md).
