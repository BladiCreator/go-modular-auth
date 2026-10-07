# Store Adapter (Persistence)

## 1. Principles of the Store Adapter

The **Store Adapter** is the authoritative source of truth in GoModularAuth.

- **Store = Source of Truth**: All domain invariants, entity lifetimes, and authorization records originate from the Store.
- **Engine Isolation**: The store adapter owns SQL schemas, foreign keys, constraints, table structures, and database driver errors. The core engine never imports SQL drivers or ORM libraries.
- **Explicit Typed Interfaces**: Avoids unstructured `Get(table, id)` key-value APIs in favor of strongly typed repositories.

---

## 2. The `store.Store` Contract

```go
type Store interface {
    Users() UserStore
    Accounts() AccountStore
    Credentials() CredentialStore
    Sessions() SessionStore
    Tokens() TokenStore

    Transaction(ctx context.Context, fn func(ctx context.Context) error) error
}
```

### 2.1 Sub-Stores
- **`UserStore`**:
  - `Create(ctx, u)`: Inserts user; must return `store.ErrConflict` on duplicate email or ID.
  - `GetByID(ctx, id)`: Returns user or `store.ErrNotFound`.
  - `GetByEmail(ctx, email)`: Returns user or `store.ErrNotFound`.
  - `Update(ctx, u)`: Updates user; returns `store.ErrConflict` if updated email collides.
  - `Delete(ctx, id)`: Removes user record.
- **`AccountStore`**:
  - `Create(ctx, a)`: Inserts account; composite `(Provider, ProviderID)` must be unique (`store.ErrConflict`).
  - `GetByID(ctx, id)`: Returns account or `store.ErrNotFound`.
  - `GetByProvider(ctx, provider, providerID)`: Looks up linked account.
  - `ListByUser(ctx, userID)`: Returns all linked accounts for a user.
  - `Delete(ctx, id)`: Deletes an account.
- **`CredentialStore`**:
  - `Create(ctx, c)`: Persists credential material.
  - `GetByID(ctx, id)`: Returns credential or `store.ErrNotFound`.
  - `GetActiveByAccount(ctx, accountID, type)`: Returns non-revoked credential (`RevokedAt == nil`).
  - `ListByUser(ctx, userID)`: Returns credentials for a user.
  - `Update(ctx, c)`: Updates credential record.
  - `Revoke(ctx, id, at)`: Sets `RevokedAt` timestamp.
- **`SessionStore`**:
  - `Create(ctx, s)`: Inserts session; `TokenHash` must be unique.
  - `GetByID(ctx, id)`: Resolves session by internal ID.
  - `GetByTokenHash(ctx, tokenHash)`: Resolves session by SHA-256 token hash.
  - `ListByUser(ctx, userID)`: Lists active and historical sessions for a user.
  - `Revoke(ctx, id, at)`: Revokes a specific session.
  - `RevokeByUser(ctx, userID, at)`: Revokes all active sessions for a user and returns them for cache invalidation.
  - `DeleteExpired(ctx, before)`: Garbage collects expired sessions.
- **`TokenStore`**:
  - `Create(ctx, t)`: Persists verification token with hashed value.
  - `GetByHash(ctx, tokenHash)`: Resolves token by hash.
  - `MarkUsed(ctx, id, at)`: **Atomic single-use guarantee**. Must update `used_at = at` ONLY where `used_at IS NULL`. Returns `store.ErrConflict` if already consumed.
  - `DeleteBySubject(ctx, purpose, subject)`: Revokes pending tokens for a user/subject.
  - `DeleteExpired(ctx, before)`: Garbage collects expired tokens.

---

## 3. Transaction Model

Atomic multi-entity workflows (e.g. `SignUp` writing `User + Account + Credential + Session`) rely on `Transaction`:

```go
err := store.Transaction(ctx, func(txCtx context.Context) error {
    if err := store.Users().Create(txCtx, u); err != nil {
        return err
    }
    return store.Accounts().Create(txCtx, a)
})
```

### Invariants for Store Implementers
1. **Context Propagation**: The transaction must be bound to the context (`txCtx`) passed into the callback function. Sub-store calls with `txCtx` participate in the active transaction.
2. **Rollback on Error**: Returning any non-nil error from `fn` must automatically roll back the transaction.
3. **Re-entrant / Nested Transactions**: If `Transaction` is called with a context already participating in a transaction, it must participate in the existing transaction without failing.

---

## 4. In-Memory Store (`store/memory`)

GoModularAuth includes a full-featured in-memory implementation in `store/memory`:
- Thread-safe using `sync.RWMutex`.
- Transactional via state snapshot and rollback on error.
- Defensive copy-on-read and copy-on-write to prevent memory aliasing.
- Ideal for unit testing, CI pipelines, and prototyping.

```go
import memstore "github.com/BladiCreator/go-modular-auth/store/memory"

store := memstore.New()
```

---

## 5. Guide: Implementing a Database Adapter (PostgreSQL / SQLite / MySQL)

To implement a persistent Store adapter (e.g. `gomodularauth-postgres` using `pgx` or `database/sql`), follow this architectural guide.

### 5.1 Recommended Database Schema (DDL)

Here is the standard DDL schema (PostgreSQL syntax):

```sql
-- 1. Users
CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(64) PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(LOWER(email));

-- 2. Accounts
CREATE TABLE IF NOT EXISTS accounts (
    id VARCHAR(64) PRIMARY KEY,
    user_id VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider VARCHAR(64) NOT NULL,
    provider_id VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT uq_accounts_provider UNIQUE (provider, provider_id)
);
CREATE INDEX IF NOT EXISTS idx_accounts_user_id ON accounts(user_id);

-- 3. Credentials
CREATE TABLE IF NOT EXISTS credentials (
    id VARCHAR(64) PRIMARY KEY,
    user_id VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    account_id VARCHAR(64) NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    type VARCHAR(64) NOT NULL,
    secret TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_credentials_account ON credentials(account_id, type);
CREATE INDEX IF NOT EXISTS idx_credentials_user ON credentials(user_id);

-- 4. Sessions
CREATE TABLE IF NOT EXISTS sessions (
    id VARCHAR(64) PRIMARY KEY,
    user_id VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(128) NOT NULL UNIQUE,
    ip_address VARCHAR(45) NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT '',
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

-- 5. Verification Tokens
CREATE TABLE IF NOT EXISTS verification_tokens (
    id VARCHAR(64) PRIMARY KEY,
    purpose VARCHAR(64) NOT NULL,
    subject VARCHAR(255) NOT NULL,
    token_hash VARCHAR(128) NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_verification_tokens_subject ON verification_tokens(purpose, subject);
CREATE INDEX IF NOT EXISTS idx_verification_tokens_expires ON verification_tokens(expires_at);
```

---

### 5.2 Error Mapping Requirements

The Core relies on standard sentinel errors to make security decisions. The adapter **must translate driver-specific errors** to `store` sentinels:

| Driver Condition | PostgreSQL (`pgconn.PgError`) | SQLite / MySQL | Mapped Store Sentinel |
| :--- | :--- | :--- | :--- |
| Row not found | `sql.ErrNoRows` / `pgx.ErrNoRows` | `sql.ErrNoRows` | `store.ErrNotFound` |
| Unique constraint violation | Code `23505` (`unique_violation`) | `SQLITE_CONSTRAINT_UNIQUE` (2067) / `1062` | `store.ErrConflict` |
| Foreign key violation | Code `23503` (`foreign_key_violation`) | `SQLITE_CONSTRAINT_FOREIGNKEY` (787) / `1452` | `store.ErrConflict` |

Example mapping helper:
```go
func mapSQLError(err error) error {
    if err == nil {
        return nil
    }
    if errors.Is(err, sql.ErrNoRows) {
        return store.ErrNotFound
    }
    var pgErr *pgconn.PgError
    if errors.As(err, &pgErr) {
        if pgErr.Code == "23505" { // unique_violation
            return store.ErrConflict
        }
    }
    return err
}
```

---

### 5.3 Context-Bound Transaction Management

The adapter must bind active transactions to `context.Context` so all sub-stores execute queries within the transaction if one is active:

```go
type txKey struct{}

type SQLStore struct {
    db *sql.DB
}

// DBTX is implemented by both *sql.DB and *sql.Tx
type DBTX interface {
    ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
    QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
    QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

func (s *SQLStore) getExecutor(ctx context.Context) DBTX {
    if tx, ok := ctx.Value(txKey{}).(*sql.Tx); ok {
        return tx
    }
    return s.db
}

func (s *SQLStore) Transaction(ctx context.Context, fn func(ctx context.Context) error) error {
    // Re-entrant: join parent transaction if already active
    if _, ok := ctx.Value(txKey{}).(*sql.Tx); ok {
        return fn(ctx)
    }

    tx, err := s.db.BeginTx(ctx, nil)
    if err != nil {
        return err
    }
    defer tx.Rollback()

    txCtx := context.WithValue(ctx, txKey{}, tx)
    if err := fn(txCtx); err != nil {
        return err
    }

    return tx.Commit()
}
```

---

### 5.4 Implementing Atomic Single-Use Tokens (`MarkUsed`)

The token consumption operation requires atomic single-use semantics to prevent replay attacks and race conditions:

```go
func (s *tokenStore) MarkUsed(ctx context.Context, id string, at time.Time) error {
    query := `
        UPDATE verification_tokens 
        SET used_at = $1 
        WHERE id = $2 AND used_at IS NULL
    `
    res, err := s.getExecutor(ctx).ExecContext(ctx, query, at, id)
    if err != nil {
        return mapSQLError(err)
    }

    rows, err := res.RowsAffected()
    if err != nil {
        return err
    }
    if rows == 0 {
        // Distinguish between already-used (conflict) and not-found
        var exists bool
        _ = s.getExecutor(ctx).QueryRowContext(ctx, 
            "SELECT EXISTS(SELECT 1 FROM verification_tokens WHERE id = $1)", id).Scan(&exists)
        if exists {
            return store.ErrConflict // already consumed
        }
        return store.ErrNotFound
    }
    return nil
}
```

---

### 5.5 Bulk Session Revocation (`RevokeByUser`)

When a user's password is changed or reset, `RevokeByUser` must revoke all active sessions and return them so the core can invalidate all corresponding cache entries:

```go
func (s *sessionStore) RevokeByUser(ctx context.Context, userID string, at time.Time) ([]*session.Session, error) {
    query := `
        UPDATE sessions
        SET revoked_at = $1
        WHERE user_id = $2 AND revoked_at IS NULL
        RETURNING id, user_id, token_hash, ip_address, user_agent, expires_at, revoked_at, created_at
    `
    rows, err := s.getExecutor(ctx).QueryContext(ctx, query, at, userID)
    if err != nil {
        return nil, mapSQLError(err)
    }
    defer rows.Close()

    var revoked []*session.Session
    for rows.Next() {
        var sess session.Session
        if err := rows.Scan(&sess.ID, &sess.UserID, &sess.TokenHash, &sess.IPAddress, 
            &sess.UserAgent, &sess.ExpiresAt, &sess.RevokedAt, &sess.CreatedAt); err != nil {
            return nil, err
        }
        revoked = append(revoked, &sess)
    }
    return revoked, rows.Err()
}
```

