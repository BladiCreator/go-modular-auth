# GoModularAuth Audit Plugin (`gomodularauth-audit`)

Structured, tamper-evident security audit logging for **GoModularAuth**.

The Audit plugin functions as a zero-trust observational event consumer across GoModularAuth Core and all installed plugins (such as `organizations`, `admin`, `api-keys`, `device-authorization`, and authentication methods). It captures security-relevant actions into an immutable ledger while strictly sanitizing passwords, authentication tokens, OTP codes, and sensitive secrets.

---

## Features

- **Observational Event Consumer**: Automatically subscribes to all Core and plugin events via `Host.Events().SubscribeAll(...)`.
- **Zero Secret Exposure**: Built-in recursive sanitization engine replaces all passwords, hashes, tokens, OTP codes, and private keys with `[REDACTED]`.
- **Multi-Tenant Scoping**: Automatically binds audit trails to organization context (`OrganizationID`) when tenant plugins are present.
- **Enterprise Ledger Contracts**: Complies with SOC 2, ISO 27001, and HIPAA append-only immutability requirements (no UPDATE/DELETE methods on audit records).
- **Flexible Storage Backends**: Ships with a thread-safe `store/memory` implementation and a high-performance PostgreSQL `store/postgres` adapter with JSONB metadata querying.
- **Synchronous & Asynchronous Modes**: Supports synchronous write guarantees or non-blocking buffered worker pools with batch flushing.
- **Typed Capability**: Exposes `auth.Get[plugins.Audit]()` for administrative log search, forensic queries, and manual event recording.

---

## Installation

```bash
go get github.com/BladiCreator/go-modular-auth-audit
```

---

## Architecture

```text
Application / HTTP Handler / Background Job
           ↓
     GoModularAuth Core (Events Dispatcher)
           ↓ (SubscribeAll)
gomodularauth-audit (Sanitizer & Consumer)
           ↓
   AuditStore Contract (store.Store)
           ↓
 PostgreSQL (JSONB) / In-Memory Store
```

---

## Registration and Configuration

```go
package main

import (
	"context"
	"database/sql"
	"log"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	audit "github.com/BladiCreator/go-modular-auth-audit"
	"github.com/BladiCreator/go-modular-auth-audit/plugins"
	auditpg "github.com/BladiCreator/go-modular-auth-audit/store/postgres"
	corememory "github.com/BladiCreator/go-modular-auth/store/memory"
)

func main() {
	db, err := sql.Open("postgres", "postgres://user:pass@localhost:5432/auth_db?sslmode=disable")
	if err != nil {
		log.Fatal(err)
	}

	auditStore := auditpg.New(db)

	auditModule := audit.New(
		audit.WithStore(auditStore),
		// Optional: Buffer events asynchronously with 2 workers and batch size of 50
		audit.WithAsync(2, 1024, 50, 250*time.Millisecond),
	)

	appAuth, err := auth.New(auth.Config{
		Store:   corememory.New(),
		Plugins: []auth.PluginModule{auditModule},
	})
	if err != nil {
		log.Fatal(err)
	}

	// Retrieve typed Capability
	auditService, err := auth.Get[plugins.Audit](appAuth)
	if err != nil {
		log.Fatal(err)
	}

	// Query recent records
	records, err := auditService.QueryByActor(context.Background(), "user_12345", 20)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Found %d audit records", len(records))
}
```

---

## Capability Public API

```go
type Audit interface {
    // Record manually registers an explicit audit entry, ensuring sanitization before persistence.
    Record(ctx context.Context, record *AuditRecord) error

    // Query searches the audit log with customizable filtering and pagination criteria.
    Query(ctx context.Context, filter ListFilter) (*ListResult, error)

    // GetByID retrieves a single audit entry by its unique identifier.
    GetByID(ctx context.Context, id string) (*AuditRecord, error)

    // QueryByActor returns audit entries performed by or associated with a specific actor subject.
    QueryByActor(ctx context.Context, subject string, limit int) ([]*AuditRecord, error)

    // QueryByTarget returns audit entries affecting a specific target resource type and identifier.
    QueryByTarget(ctx context.Context, targetType, targetID string, limit int) ([]*AuditRecord, error)

    // QueryByOrganization returns paginated audit records scoped to a multi-tenant organization.
    QueryByOrganization(ctx context.Context, orgID string, filter ListFilter) (*ListResult, error)
}
```

---

## Domain Model: `AuditRecord`

```go
type AuditRecord struct {
    ID             string         `json:"id"`
    Timestamp      time.Time      `json:"timestamp"`
    Event          string         `json:"event"`
    Action         string         `json:"action"`
    ActorSubject   string         `json:"actor_subject"`
    ActorType      string         `json:"actor_type"`
    TargetType     string         `json:"target_type"`
    TargetID       string         `json:"target_id"`
    Outcome        Outcome        `json:"outcome"`
    OrganizationID string         `json:"organization_id,omitempty"`
    IPAddress      string         `json:"ip_address,omitempty"`
    UserAgent      string         `json:"user_agent,omitempty"`
    Metadata       map[string]any `json:"metadata,omitempty"`
    ErrorMessage   string         `json:"error_message,omitempty"`
}
```

---

## Security Model and Sanitization

The audit plugin guarantees that **no sensitive credentials or authentication material are ever recorded**.
The recursive sanitization engine checks keys and sub-keys against:
- `password`, `passwd`, `pwd`
- `access_token`, `refresh_token`, `session_token`, `bearer`
- `otp`, `totp`, `user_code`, `device_code`
- `client_secret`, `private_key`, `key_hash`, `salt`

Any matching properties in metadata maps, structs, or slices are replaced with `[REDACTED]`.

---

## Persistence & SQL Schema

Audit records are append-only. Run the provided migration in `migrations/001_create_audit_tables.sql`:

```sql
CREATE TABLE IF NOT EXISTS auth_audit_records (
    id VARCHAR(64) PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL,
    event VARCHAR(255) NOT NULL,
    action VARCHAR(255) NOT NULL,
    actor_subject VARCHAR(255) NOT NULL DEFAULT '',
    actor_type VARCHAR(64) NOT NULL DEFAULT '',
    target_type VARCHAR(64) NOT NULL DEFAULT '',
    target_id VARCHAR(255) NOT NULL DEFAULT '',
    outcome VARCHAR(32) NOT NULL DEFAULT 'success',
    organization_id VARCHAR(255) NOT NULL DEFAULT '',
    ip_address VARCHAR(128) NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT '',
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    error_message TEXT NOT NULL DEFAULT ''
);
```

---

## Testing

Run tests with race detection:

```bash
go test -count=1 -race -v ./...
```

---

## License

MIT License. See [LICENSE](LICENSE) for details.
