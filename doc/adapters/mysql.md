# MySQL Database Adapter

The **MySQL Adapter** (`adapters/mysql`) provides an enterprise-ready implementation of `adapter.Adapter` backed by MySQL 8.0+ or MariaDB 10.5+.

---

## Installation

```bash
go get github.com/BladiCreator/go-modular-auth/adapters/mysql
```

Driver:
- `github.com/go-sql-driver/mysql`

---

## Quickstart

```go
package main

import (
    "context"
    "database/sql"
    "log"

    _ "github.com/go-sql-driver/mysql"
    auth "github.com/BladiCreator/go-modular-auth"
    "github.com/BladiCreator/go-modular-auth/adapters/mysql"
)

func main() {
    ctx := context.Background()

    // 1. Connect to MySQL (parseTime=true is required for proper time.Time scanning)
    dsn := "auth_user:auth_password@tcp(127.0.0.1:3306)/auth_db?parseTime=true&charset=utf8mb4&collation=utf8mb4_unicode_ci"
    db, err := sql.Open("mysql", dsn)
    if err != nil {
        log.Fatal(err)
    }

    db.SetMaxOpenConns(25)
    db.SetMaxIdleConns(10)

    // 2. Instantiate MySQL Adapter
    mysqlAdapter := mysql.New(db)

    // 3. Initialize Auth Engine
    engine, err := auth.New(auth.Config{
        Adapter: mysqlAdapter,
    })
    if err != nil {
        log.Fatal(err)
    }

    // 4. Apply schema migrations
    if err := mysqlAdapter.Migrate(ctx); err != nil {
        log.Fatalf("failed to apply migrations: %v", err)
    }

    _ = engine
}
```

---

## Important Connection Flags

When constructing the MySQL connection string (DSN), ensure the following parameters are included:

- **`parseTime=true`**: Required so MySQL DATETIME and TIMESTAMP columns deserialize cleanly into Go `time.Time` structs.
- **`charset=utf8mb4`**: Required for full Unicode support (including emojis and international characters).
