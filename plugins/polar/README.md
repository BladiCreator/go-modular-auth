# GoModularAuth Polar Billing Plugin

`plugins/polar` provides subscription billing, automated customer provisioning, customer portal sessions, and license benefit checks integrated with [Polar.sh](https://polar.sh) for **GoModularAuth**.

## Installation

```bash
go get github.com/BladiCreator/go-modular-auth/plugins/polar
```

## Quick Start

```go
package main

import (
    "log"

    auth "github.com/BladiCreator/go-modular-auth"
    "github.com/BladiCreator/go-modular-auth/adapters/memory"
    "github.com/BladiCreator/go-modular-auth/plugins/polar"
)

func main() {
    ad := memory.NewAdapter()

    polarModule := polar.New(
        polar.WithAccessToken("polar_at_..."),
        polar.WithWebhookSecret("whsec_..."),
    )

    engine, err := auth.New(auth.Config{
        Adapter: ad,
        Plugins: []auth.PluginModule{polarModule},
    })
    if err != nil {
        log.Fatalf("failed to initialize auth: %v", err)
    }

    billing, err := auth.Get[polar.Polar](engine)
    if err != nil {
        log.Fatalf("failed to resolve Polar capability: %v", err)
    }

    _ = billing
}
```

Detailed guide: [**`doc/plugins/polar.md`**](../../doc/plugins/polar.md).
