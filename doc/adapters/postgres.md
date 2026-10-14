# PostgreSQL Database Adapter

The **PostgreSQL Adapter** (`adapters/postgres`) provides a production-grade implementation of `adapter.Adapter` backed by PostgreSQL. It dynamically handles the compiled schema (Core + Plugins), manages DDL generation and migrations, translates SQLSTATE errors to domain sentinels, and enables cross-module transaction propagation via `sqltx`.

---

## Installation

```bash
go get github.com/BladiCreator/go-modular-auth/adapters/postgres
```

Supported drivers:
- `github.com/jackc/pgx/v5/stdlib` (Recommended)
- `github.com/lib/pq`

---

## Quickstart

```go
package main

import (
    "context"
    "database/sql"
    "log"

    _ "github.com/jackc/pgx/v5/stdlib"
    auth "github.com/BladiCreator/go-modular-auth"
    "github.com/BladiCreator/go-modular-auth/adapters/postgres"
)

func main() {
    ctx := context.Background()

    // 1. Connect to PostgreSQL
    db, err := sql.Open("pgx", "postgres://user:password@localhost:5432/auth_db?sslmode=disable")
    if err != nil {
        log.Fatal(err)
    }

    // Recommended pool tuning
    db.SetMaxOpenConns(25)
    db.SetMaxIdleConns(10)

    // 2. Instantiate PostgreSQL Database Adapter
    pgAdapter := postgres.New(db)

    // 3. Instantiate Auth Engine (automatically compiles schema and registers it in the adapter)
    engine, err := auth.New(auth.Config{
        Adapter: pgAdapter,
    })
    if err != nil {
        log.Fatal(err)
    }

    // 4. Run automated DDL migrations across Core & Plugin tables
    if err := pgAdapter.Migrate(ctx); err != nil {
        log.Fatalf("failed to apply migrations: %v", err)
    }

    _ = engine
}
```

---

## Schema & Tables

Calling `pgAdapter.Migrate(ctx)` dynamically creates tables, foreign keys, and indexes for all registered models:

1. **`users`** (`auth_users`): User identities with normalized unique emails.
2. **`accounts`** (`auth_accounts`): Provider linkages with foreign key to `users` and cascade deletes.
3. **`credentials`** (`auth_credentials`): Secret material, credential type, and revocation timestamps.
4. **`sessions`** (`auth_sessions`): Server-side sessions indexed by `token_hash`.
5. **`verifications`** (`auth_verifications`): Single-use tokens and OTPs.
6. **Plugin Tables & Extended Fields**: Any models registered by active plugins (e.g. `passkeys`, `organizations`) or extended user columns (e.g. `two_factor_enabled`).

---

## Cross-Module Atomic Transactions

The adapter provides atomic transactions via `Transaction(ctx, fn)`. All database operations executed within the transaction function share the same `*sql.Tx`:

```go
err := pgAdapter.Transaction(ctx, func(txCtx context.Context, tx adapter.Adapter) error {
    // 1. Insert or update core entity
    _, err := tx.Create(txCtx, "users", userData)
    if err != nil {
        return err
    }

    // 2. Insert plugin entity in the same transaction
    _, err = tx.Create(txCtx, "organizations", orgData)
    if err != nil {
        return err // Entire transaction rolls back atomically
    }

    return nil
})
```
