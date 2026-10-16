# GoModularAuth Audit Plugin (`gomodularauth-audit`)

Structured, tamper-evident security audit logging for **GoModularAuth**. The Audit plugin functions as a zero-trust observational event consumer across GoModularAuth Core and all installed plugins (such as `organizations`, `admin`, `api-keys`, `device-authorization`, and authentication methods). It captures security-relevant actions into an immutable ledger while strictly sanitizing passwords, authentication tokens, OTP codes, and sensitive secrets.

## Installation

```bash
go get github.com/BladiCreator/go-modular-auth/plugins/audit
```

## Quick Start

```go
package main

import (
	"context"
	"database/sql"
	"log"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	audit "github.com/BladiCreator/go-modular-auth/plugins/audit"
	"github.com/BladiCreator/go-modular-auth/plugins/audit/plugins"
	adaptermem "github.com/BladiCreator/go-modular-auth/adapters/memory"
)

func main() {
	db, err := sql.Open("postgres", "postgres://user:pass@localhost:5432/auth_db?sslmode=disable")
	if err != nil {
		log.Fatal(err)
	}

	auditModule := audit.New(
		// Optional: Buffer events asynchronously with 2 workers and batch size of 50
		audit.WithAsync(2, 1024, 50, 250*time.Millisecond),
	)

	appAuth, err := auth.New(auth.Config{
		Adapter: adaptermem.NewAdapter(),
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

Detailed guide: [**`doc/plugins/audit.md`**](../../doc/plugins/audit.md).
