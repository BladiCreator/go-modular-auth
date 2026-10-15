# Database Adapters & Schema-Driven Persistence

## 1. Principles of Persistence in GoModularAuth

Persistence in **GoModularAuth** is built around a generic, schema-driven storage model:

- **Database Adapter = Authoritative Truth**: All domain identities, credentials, sessions, and plugin-specific models persist in the configured database adapter.
- **Dynamic Schema Compilation**: The engine collects schema definitions from Core and all registered plugins (`schema.Schema`), ensuring tables, columns, indexes, and unique constraints are created automatically.
- **Engine Isolation**: The core engine and plugins are completely decoupled from SQL dialects, drivers, or specific databases.
- **Unified Query Layer**: Plugins query their own tables through strongly typed repositories using `sdk.Model[T](ctx, ModelName)`.

---

## 2. The `adapter.Adapter` Contract

All database adapters implement the `github.com/BladiCreator/go-modular-auth/adapter.Adapter` contract:

```go
type Adapter interface {
    // Schema lifecycle
    Migrate(ctx context.Context, s *schema.Schema) error

    // Query & Mutation operations
    Create(ctx context.Context, model string, record any) error
    FindOne(ctx context.Context, q Query) (Record, error)
    FindMany(ctx context.Context, q Query) ([]Record, error)
    Update(ctx context.Context, q Query, updates map[string]any) (int64, error)
    Delete(ctx context.Context, q Query) (int64, error)
    Count(ctx context.Context, q Query) (int64, error)

    // Transaction execution
    Transaction(ctx context.Context, fn func(ctx context.Context, tx Adapter) error) error
}
```

### 2.1 The Internal Core Bridge (`store.Store`)
Inside the core engine, authentication workflows (`SignIn`, `SignUp`, `CreateSession`) interact with the repository abstractions defined in `github.com/BladiCreator/go-modular-auth/store.Store`:
- `Users()`
- `Accounts()`
- `Credentials()`
- `Sessions()`
- `Tokens()`

This contract is fulfilled transparently by `core/adapter/bridge`, which wraps any `adapter.Adapter`. Application developers do not need to configure or instantiate `store.Store` directly.

---

## 3. Official Production Database Adapters

GoModularAuth ships with 5 official database adapters in `adapters/`:

### 3.1 PostgreSQL Adapter (`adapters/postgres`)
Production-grade PostgreSQL adapter utilizing `database/sql` (e.g. `pgx` stdlib):

```go
import (
    "database/sql"
    _ "github.com/jackc/pgx/v5/stdlib"
    "github.com/BladiCreator/go-modular-auth/adapters/postgres"
)

db, err := sql.Open("pgx", "postgres://user:pass@localhost:5432/authdb?sslmode=disable")
ad := postgres.New(db)

engine, err := auth.New(auth.Config{
    Adapter: ad,
})
```

### 3.2 SQLite Adapter (`adapters/sqlite`)
Production-grade SQLite adapter supporting WAL mode and busy timeouts:

```go
import (
    "database/sql"
    _ "modernc.org/sqlite"
    "github.com/BladiCreator/go-modular-auth/adapters/sqlite"
)

db, err := sql.Open("sqlite", "file:auth.db?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
ad := sqlite.New(db)

engine, err := auth.New(auth.Config{
    Adapter: ad,
})
```

### 3.3 MySQL Adapter (`adapters/mysql`)
Production-grade MySQL 8.0+ adapter:

```go
import (
    "database/sql"
    _ "github.com/go-sql-driver/mysql"
    "github.com/BladiCreator/go-modular-auth/adapters/mysql"
)

db, err := sql.Open("mysql", "user:pass@tcp(127.0.0.1:3306)/authdb?parseTime=true")
ad := mysql.New(db)

engine, err := auth.New(auth.Config{
    Adapter: ad,
})
```

### 3.4 SurrealDB Adapter (`adapters/surrealdb`)
Multi-model cloud-native database adapter generating dynamic SurrealQL schemas:

```go
import (
    "context"
    "github.com/BladiCreator/go-modular-auth/adapters/surrealdb"
)

ad, err := surrealdb.NewFromConfig(ctx, surrealdb.Config{
    Endpoint:  "ws://localhost:8000/rpc",
    Namespace: "production",
    Database:  "auth",
    Username:  "root",
    Password:  "root",
})

engine, err := auth.New(auth.Config{
    Adapter: ad,
})
```

### 3.5 In-Memory Database Adapter (`adapters/memory`)
Thread-safe in-memory adapter designed for unit tests and local development:

```go
import (
    "github.com/BladiCreator/go-modular-auth/adapters/memory"
)

ad := memory.NewAdapter()

engine, err := auth.New(auth.Config{
    Adapter: ad,
})
```

---

## 4. How Plugins Persist Data: `sdk.Model[T]`

Plugins define their database models declaratively and query them through the `plugin-sdk`:

1. **Register the Schema** in the plugin module:
```go
func (m *Module) RegisterSchema(s *schema.Schema) error {
    model := schema.NewModel("my_custom_records", "custom_records", "id")
    _ = model.AddField(schema.Field{Name: "id", Type: schema.TypeString, Required: true})
    _ = model.AddField(schema.Field{Name: "user_id", Type: schema.TypeString, Required: true})
    _ = model.AddField(schema.Field{Name: "data", Type: schema.TypeJSON})
    return s.RegisterModel(model)
}
```

2. **Access Model Repository** in plugin services:
```go
type service struct {
    repo *sdk.Repository[CustomRecord]
}

func newService(ctx *sdk.Context) *service {
    return &service{
        repo: sdk.Model[CustomRecord](ctx, "my_custom_records"),
    }
}
```

3. **Perform Queries and Mutations**:
```go
// Create record
err := s.repo.Create(ctx, record)

// Find record
rec, err := s.repo.FindOne(ctx, adapter.Eq("user_id", userID))

// Update
count, err := s.repo.Update(ctx, []adapter.Condition{adapter.Eq("id", rec.ID)}, map[string]any{"data": updated})
```

---

## 5. Cross-Module Atomic Transactions

Database transactions execute via `Adapter.Transaction`:

```go
err := ad.Transaction(ctx, func(txCtx context.Context, tx adapter.Adapter) error {
    // All operations executed with txCtx participate in the active transaction.
    // Core identity and plugin records commit or roll back together atomically.
    return nil
})
```

