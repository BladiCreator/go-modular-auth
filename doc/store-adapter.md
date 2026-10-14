# Store Adapter (Persistence)

## 1. Principles of the Store Adapter

The **Store Adapter** is the authoritative source of truth in GoModularAuth.

- **Store = Source of Truth**: All domain invariants, entity lifetimes, credentials, and sessions originate from the Store.
- **Engine Isolation**: The store adapter owns SQL schemas, foreign keys, indexes, table structures, and driver-specific error translation. The core engine never imports SQL drivers or ORM libraries.
- **Explicit Typed Contracts**: Strongly typed repository sub-stores rather than arbitrary unstructured key-value queries.

---

## 2. The `store.Store` Contract

```go
type Store interface {
    Users() UserStore
    Accounts() AccountStore
    Credentials() CredentialStore
    Sessions() SessionStore
    Tokens() TokenStore

    // Transaction executes fn atomically. Nested calls must join the outer transaction.
    Transaction(ctx context.Context, fn func(ctx context.Context) error) error
}
```

### 2.1 Sub-Store Interfaces

#### `UserStore`
- `Create(ctx, u)`: Inserts user. Must return `store.ErrConflict` on duplicate email or ID.
- `GetByID(ctx, id)`: Returns user or `store.ErrNotFound`.
- `GetByEmail(ctx, email)`: Returns user or `store.ErrNotFound`. Email must be normalized prior to query.
- `Update(ctx, u)`: Updates user; returns `store.ErrConflict` if updated email collides with another user.
- `Delete(ctx, id)`: Permanently deletes user.

#### `AccountStore`
- `Create(ctx, a)`: Inserts account. The composite tuple `(Provider, ProviderID)` must be unique (`store.ErrConflict`).
- `GetByID(ctx, id)`: Returns account or `store.ErrNotFound`.
- `GetByProvider(ctx, provider, providerID)`: Resolves external provider link.
- `ListByUser(ctx, userID)`: Returns all linked accounts for a user.
- `Delete(ctx, id)`: Removes an account link.

#### `CredentialStore`
- `Create(ctx, c)`: Persists credential secrets (Argon2id hashes, public keys). Plaintext secrets are never stored.
- `GetByID(ctx, id)`: Returns credential or `store.ErrNotFound`.
- `GetActiveByAccount(ctx, accountID, type)`: Returns the current non-revoked credential (`RevokedAt == nil`).
- `ListByUser(ctx, userID)`: Lists credentials for a user.
- `Update(ctx, c)`: Updates credential secret or metadata.
- `Revoke(ctx, id, at)`: Sets `RevokedAt` timestamp.

#### `SessionStore`
- `Create(ctx, s)`: Inserts session. `TokenHash` must be unique (`store.ErrConflict`).
- `GetByID(ctx, id)`: Resolves session by ID.
- `GetByTokenHash(ctx, tokenHash)`: Resolves session by SHA-256 token hash.
- `ListByUser(ctx, userID)`: Lists active and historical sessions for a user.
- `Revoke(ctx, id, at)`: Sets `RevokedAt` timestamp on a specific session.
- `RevokeByUser(ctx, userID, at)`: Revokes all active sessions for a user and returns them for cache invalidation.
- `DeleteExpired(ctx, before)`: Garbage collects expired sessions.

#### `TokenStore`
- `Create(ctx, t)`: Persists single-use verification token with hashed value.
- `GetByHash(ctx, tokenHash)`: Resolves verification token by SHA-256 hash.
- `MarkUsed(ctx, id, at)`: **Atomic single-use guarantee**. Executes `UPDATE ... SET used_at = ? WHERE id = ? AND used_at IS NULL`. Returns `store.ErrConflict` if already consumed.
- `DeleteBySubject(ctx, purpose, subject)`: Revokes pending tokens for a user/subject.
- `DeleteExpired(ctx, before)`: Garbage collects expired verification tokens.

---

## 3. Official Production Store Adapters

GoModularAuth ships with 4 official store adapters:

### 3.1 PostgreSQL Adapter (`adapters/postgres`)
Compatible with standard `database/sql` pools via `github.com/lib/pq` or `github.com/jackc/pgx/v5/stdlib`:

```go
import (
    "database/sql"
    _ "github.com/jackc/pgx/v5/stdlib"
    "github.com/BladiCreator/go-modular-auth/adapters/postgres"
)

db, err := sql.Open("pgx", "postgres://user:pass@localhost:5432/authdb?sslmode=disable")
store := postgres.New(db)

// Automatically create tables and indexes
if err := store.Migrate(ctx); err != nil {
    log.Fatal(err)
}
```

### 3.2 SQLite Adapter (`adapters/sqlite`)
Compatible with pure Go SQLite (`modernc.org/sqlite`) or CGO SQLite (`github.com/mattn/go-sqlite3`):

```go
import (
    "database/sql"
    _ "modernc.org/sqlite"
    "github.com/BladiCreator/go-modular-auth/adapters/sqlite"
)

db, err := sql.Open("sqlite", "file:auth.db?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
store := sqlite.New(db)

if err := store.Migrate(ctx); err != nil {
    log.Fatal(err)
}
```

### 3.3 MySQL Adapter (`adapters/mysql`)
Compatible with `github.com/go-sql-driver/mysql`:

```go
import (
    "database/sql"
    _ "github.com/go-sql-driver/mysql"
    "github.com/BladiCreator/go-modular-auth/adapters/mysql"
)

db, err := sql.Open("mysql", "user:pass@tcp(127.0.0.1:3306)/authdb?parseTime=true")
store := mysql.New(db)

if err := store.Migrate(ctx); err != nil {
    log.Fatal(err)
}
```

### 3.4 In-Memory Adapter (`adapters/memory`)
Thread-safe reference implementation designed for tests, ephemeral workers, and local development:

```go
import (
    "github.com/BladiCreator/go-modular-auth/adapters/memory"
)

store := memory.NewStore()
```

---

## 4. Cross-Module Transactions via `sqltx`

GoModularAuth bridges transactions between the core and plugins using the `github.com/BladiCreator/go-modular-auth/store/sqltx` package:

```text
               Store.Transaction(ctx, fn)
                           │
                sqltx.Run(ctx, db, fn)
                           │
             ctx with *sql.Tx injected
                           │
        ┌──────────────────┴──────────────────┐
        ▼                                     ▼
Core Sub-Stores                        Plugin SQL Stores
sqltx.Executor(ctx, db)                sqltx.Executor(ctx, db)
(uses active *sql.Tx)                  (joins the same *sql.Tx)
```

If any operation within `fn` returns an error, the entire transaction rolls back across all tables, ensuring ACID guarantees between core authentication entities and plugin extensions.
