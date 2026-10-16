# GoModularAuth - Passkey Plugin (`gomodularauth-passkey`)

Provides WebAuthn and Passkey registration and authentication as an optional server-side authentication mechanism for [GoModularAuth](https://github.com/BladiCreator/go-modular-auth).

## Installation

```bash
go get github.com/BladiCreator/go-modular-auth/plugins/passkeys
```

## Quick Start

```go
package main

import (
	"log"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	adaptermem "github.com/BladiCreator/go-modular-auth/adapters/memory"
	passkey "github.com/BladiCreator/go-modular-auth/plugins/passkeys"
	"github.com/BladiCreator/go-modular-auth/plugins/passkeys/plugins"
)

func main() {
	passkeyMod := passkey.New(
		passkey.WithRP("localhost", "My App", []string{"http://localhost:3000"}),
		passkey.WithTimeout(60 * time.Second),
	)

	authEngine, err := auth.New(auth.Config{
		Adapter: adaptermem.NewAdapter(),
		Plugins: []auth.PluginModule{passkeyMod},
	})
	if err != nil {
		log.Fatalf("failed to initialize auth: %v", err)
	}

	// Retrieve typed capability
	pk, err := auth.Get[plugins.Passkeys](authEngine)
	if err != nil {
		log.Fatalf("failed to retrieve passkey capability: %v", err)
	}

	_ = pk
}
```

Detailed guide: [**`doc/plugins/passkeys.md`**](../../doc/plugins/passkeys.md).
