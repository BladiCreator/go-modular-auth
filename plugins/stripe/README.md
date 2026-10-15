# GoModularAuth Stripe Billing Plugin

`plugins/stripe` provides enterprise subscription billing, customer provisioning, checkout sessions, customer portal sessions, and webhook synchronization with [Stripe](https://stripe.com) for **GoModularAuth**.

## Installation

```bash
go get github.com/BladiCreator/go-modular-auth/plugins/stripe
```

## Quick Start

```go
package main

import (
    "log"

    auth "github.com/BladiCreator/go-modular-auth"
    "github.com/BladiCreator/go-modular-auth/adapters/memory"
    "github.com/BladiCreator/go-modular-auth/plugins/stripe"
)

func main() {
    ad := memory.NewAdapter()

    stripeModule := stripe.New(
        stripe.WithAPIKey("sk_test_..."),
        stripe.WithWebhookSecret("whsec_..."),
    )

    engine, err := auth.New(auth.Config{
        Adapter: ad,
        Plugins: []auth.PluginModule{stripeModule},
    })
    if err != nil {
        log.Fatalf("failed to initialize auth: %v", err)
    }

    billing, err := auth.Get[stripe.Stripe](engine)
    if err != nil {
        log.Fatalf("failed to resolve Stripe capability: %v", err)
    }

    _ = billing
}
```

Detailed guide: [**`doc/plugins/stripe.md`**](../../doc/plugins/stripe.md).
