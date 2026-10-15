# SurrealDB Database Adapter

`adapters/surrealdb` provides a production-ready implementation of `adapter.Adapter` for [SurrealDB](https://surrealdb.com), supporting both WebSocket (`ws://`, `wss://`) and HTTP protocols.

It operates dynamically over the compiled schema (Core + Plugins), handling SurrealQL DDL generation, parameterized query building, transactional atomicity, and SurrealDB error mapping.

---

## 1. Features

- **Schema-Driven DDL**: Automatically generates `DEFINE TABLE ... SCHEMAFULL`, typed fields (`DEFINE FIELD`), unique indexes (`DEFINE INDEX ... UNIQUE`), and assert constraints based on `schema.Schema`.
- **Flexible Protocols**: Supports WebSocket connections for low-latency RPC and HTTP endpoints.
- **Atomic Transactions**: Full support for `Adapter.Transaction` mapped to SurrealDB's transaction blocks (`BEGIN TRANSACTION ... COMMIT TRANSACTION`).
- **Normalized Error Mapping**: Translates record collisions and constraint failures to `adapter.ErrConflict`, and missing records to `adapter.ErrNotFound`.
- **Native Go Driver**: Uses the official `github.com/surrealdb/surrealdb.go` v1.0.0+ client.

---

## 2. Installation

```bash
go get github.com/BladiCreator/go-modular-auth/adapters/surrealdb
```

---

## 3. Configuration & Initialization

### Option A: From Configuration Object

```go
package main

import (
    "context"
    "log"
    "time"

    auth "github.com/BladiCreator/go-modular-auth"
    "github.com/BladiCreator/go-modular-auth/adapters/surrealdb"
)

func main() {
    ctx := context.Background()

    // 1. Initialize SurrealDB Adapter
    ad, err := surrealdb.NewFromConfig(ctx, surrealdb.Config{
        Endpoint:  "ws://localhost:8000/rpc",
        Namespace: "production",
        Database:  "authdb",
        Username:  "root",
        Password:  "rootpassword",
        Timeout:   10 * time.Second,
    })
    if err != nil {
        log.Fatalf("failed to connect to surrealdb: %v", err)
    }
    defer ad.Close(ctx)

    // 2. Initialize GoModularAuth Engine
    engine, err := auth.New(auth.Config{
        Adapter: ad,
    })
    if err != nil {
        log.Fatalf("failed to initialize auth: %v", err)
    }

    _ = engine
}
```

### Option B: Wrapping an Existing SurrealDB Client

```go
import (
    surreal "github.com/surrealdb/surrealdb.go"
    "github.com/BladiCreator/go-modular-auth/adapters/surrealdb"
)

// db was already initialized and authenticated
ad := surrealdb.New(db)
```

---

## 4. SurrealQL DDL Mapping

When `engine` starts, `ad.Migrate(ctx, schema)` translates the GoModularAuth schema definitions into SurrealQL:

| GoModularAuth Schema Type | SurrealQL Field Definition |
| :--- | :--- |
| `schema.TypeString` | `DEFINE FIELD <name> ON <table...> TYPE string` |
| `schema.TypeInt`, `TypeInt64` | `DEFINE FIELD <name> ON <table...> TYPE int` |
| `schema.TypeBool` | `DEFINE FIELD <name> ON <table...> TYPE bool` |
| `schema.TypeTime` | `DEFINE FIELD <name> ON <table...> TYPE datetime` |
| `schema.TypeJSON` | `DEFINE FIELD <name> ON <table...> TYPE object OR array` |
| `schema.TypeBytes` | `DEFINE FIELD <name> ON <table...> TYPE bytes OR string` |
| Unique constraints | `DEFINE INDEX <idx_name> ON <table...> FIELDS <cols...> UNIQUE` |

---

## 5. Transactions

SurrealDB transactions are executed atomically:

```go
err := ad.Transaction(ctx, func(txCtx context.Context, tx adapter.Adapter) error {
    // All queries using tx operate within the active transaction
    return nil
})
```
