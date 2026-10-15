# GoModularAuth SurrealDB Storage Adapter

`adapters/surrealdb` provides a production-grade implementation of `adapter.Adapter` for [SurrealDB](https://surrealdb.com).

## Installation

```bash
go get github.com/BladiCreator/go-modular-auth/adapters/surrealdb
```

## Quick Start

```go
package main

import (
    "context"
    "log"

    auth "github.com/BladiCreator/go-modular-auth"
    "github.com/BladiCreator/go-modular-auth/adapters/surrealdb"
)

func main() {
    ctx := context.Background()

    ad, err := surrealdb.NewFromConfig(ctx, surrealdb.Config{
        Endpoint:  "ws://localhost:8000/rpc",
        Namespace: "production",
        Database:  "auth",
        Username:  "root",
        Password:  "root",
    })
    if err != nil {
        log.Fatalf("failed to connect to surrealdb: %v", err)
    }
    defer ad.Close(ctx)

    engine, err := auth.New(auth.Config{
        Adapter: ad,
    })
    if err != nil {
        log.Fatalf("failed to initialize auth: %v", err)
    }

    _ = engine
}
```

Detailed documentation is available in [**`doc/adapters/surrealdb.md`**](../../doc/adapters/surrealdb.md).
