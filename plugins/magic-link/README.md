# gomodularauth-magic-link

`gomodularauth-magic-link` provides passwordless authentication through secure, single-use, expiring email magic links for [GoModularAuth](https://github.com/BladiCreator/go-modular-auth).

## Installation

```bash
go get github.com/BladiCreator/go-modular-auth/plugins/magic-link
```

## Quick Start

```go
package main

import (
    "log"
    "time"

    auth "github.com/BladiCreator/go-modular-auth"
    adaptermem "github.com/BladiCreator/go-modular-auth/adapters/memory"
    magiclink "github.com/BladiCreator/go-modular-auth/plugins/magic-link"
)

func main() {
    a, err := auth.New(auth.Config{
        Adapter: adaptermem.NewAdapter(),
        Cache:   adaptermem.NewCache(),
        Email:   adaptermem.NewEmail(),

        Plugins: []auth.PluginModule{
            magiclink.New(
                magiclink.WithTTL(15 * time.Minute),
                magiclink.WithBaseURL("https://myapp.com/auth/magiclink/verify"),
                magiclink.WithAllowSignUp(true),
                magiclink.WithRateLimit(magiclink.RateLimitConfig{
                    Enabled:  true,
                    Max:      5,
                    Window:   15 * time.Minute,
                    Cooldown: 60 * time.Second,
                }),
            ),
        },
    })
    if err != nil {
        log.Fatalf("failed to initialize auth: %v", err)
    }

    // Retrieve capability
    ml, err := auth.Get[magiclink.MagicLink](a)
    if err != nil {
        log.Fatalf("magiclink plugin not installed: %v", err)
    }
}
```

Detailed guide: [**`doc/plugins/magic-link.md`**](../../doc/plugins/magic-link.md).
