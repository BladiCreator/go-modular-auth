# SQLite Database Adapter

The **SQLite Adapter** (`adapters/sqlite`) provides a lightweight, embedded implementation of `adapter.Adapter` backed by SQLite. It is ideal for self-hosted instances, edge deployments, CLI applications, and local development.

---

## Installation

```bash
go get github.com/BladiCreator/go-modular-auth/adapters/sqlite
```

Supported drivers:
- `modernc.org/sqlite` (Pure Go, no CGO required — recommended)
- `github.com/mattn/go-sqlite3` (CGO)

---

## Quickstart

```go
package main

import (
    "context"
    "database/sql"
    "log"

    _ "modernc.org/sqlite"
    auth "github.com/BladiCreator/go-modular-auth"
    "github.com/BladiCreator/go-modular-auth/adapters/sqlite"
)

func main() {
    ctx := context.Background()

    // 1. Open SQLite database with Write-Ahead Logging (WAL) and busy timeout
    dsn := "file:auth.db?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)"
    db, err := sql.Open("sqlite", dsn)
    if err != nil {
        log.Fatal(err)
    }

    // Set connection pool limits for SQLite to prevent file lock contention
    db.SetMaxOpenConns(1)

    // 2. Instantiate SQLite Adapter
    sqliteAdapter := sqlite.New(db)

    // 3. Initialize Auth Engine (registers schema into adapter)
    engine, err := auth.New(auth.Config{
        Adapter: sqliteAdapter,
    })
    if err != nil {
        log.Fatal(err)
    }

    // 4. Apply schema migrations
    if err := sqliteAdapter.Migrate(ctx); err != nil {
        log.Fatalf("failed to apply migrations: %v", err)
    }

    _ = engine
}
```

---

## Best Practices for SQLite in Production

1. **Enable WAL Mode**: Write-Ahead Logging (`_pragma=journal_mode(WAL)`) allows concurrent readers while a write is occurring.
2. **Busy Timeout**: Set `_pragma=busy_timeout(5000)` so queries wait up to 5 seconds before returning a `busy` error when the database is locked.
3. **Foreign Keys**: Always enable `_pragma=foreign_keys(ON)` to enforce cascade deletions across users, accounts, and credentials.
4. **Single Connection Pool**: If using file-based storage under high write concurrency, configure `db.SetMaxOpenConns(1)` to serialize writes deterministically.
