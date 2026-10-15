# GoModularAuth MultiSession Plugin

[![Go Reference](https://pkg.go.dev/badge/github.com/BladiCreator/go-modular-auth/plugins/multisession.svg)](https://pkg.go.dev/github.com/BladiCreator/go-modular-auth/plugins/multisession)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

`gomodularauth-multi-session` provides advanced management of multiple concurrent Core Sessions for GoModularAuth users while strictly preserving Core session semantics.

---

## Architecture & Design Principles

```text
┌────────────────────────────────────────────────────────┐
│                      Application                       │
└────────────────────────────────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│                   GoModularAuth Core                   │
│   (SessionStore, auth.Auth, Transaction, Events/Hooks) │
└────────────────────────────────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│             gomodularauth-multi-session                │
│   - MultiSession Capability Interface                  │
│   - Enforces Max Concurrent Sessions via Hooks         │
│   - Device & Session Metadata Management               │
│   - Store-First Atomic Revocations                     │
│   - Immediate Cache Invalidation                       │
└────────────────────────────────────────────────────────┘
```

- **Reuses Core Session Entities**: Never creates an alternative session model. Operates directly on `session.Session` from `github.com/BladiCreator/go-modular-auth/session`.
- **Core SessionStore as Source of Truth**: All session persistence and revocations use the Core `store.SessionStore`.
- **Store-First Revocation**: Revocations update the persistent store first before invalidating cache or emitting events.
- **Immediate Cache Purging**: Invalidation removes cached session tokens immediately upon successful store commit.
- **Concurrency Safe**: Handles simultaneous revocation requests and concurrency limit enforcement safely.
- **Zero Framework Bloat**: No HTTP or third-party web framework dependencies.

---

## Installation

```bash
go get github.com/BladiCreator/go-modular-auth/plugins/multisession
```

---

## Quick Start

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/BladiCreator/go-modular-auth/auth"
	memcache "github.com/BladiCreator/go-modular-auth/cache/memory"
	adaptermem "github.com/BladiCreator/go-modular-auth/adapter/memory"
	multisession "github.com/BladiCreator/go-modular-auth/plugins/multisession"
	"github.com/BladiCreator/go-modular-auth/plugins/multisession/plugins"
)

func main() {
	ctx := context.Background()

	// 1. Initialize GoModularAuth with MultiSession plugin
	app, err := auth.New(auth.Config{
		Adapter: adaptermem.New(),
		Cache: memcache.New(),
		Plugins: []auth.PluginModule{
			multisession.New(
				multisession.WithMaxConcurrentSessions(5, multisession.OverflowRevokeOldest),
			),
		},
	})
	if err != nil {
		log.Fatalf("failed to initialize auth: %v", err)
	}

	// 2. Retrieve the typed MultiSession capability
	sessionMgr, err := auth.Get[plugins.MultiSession](app)
	if err != nil {
		log.Fatalf("failed to resolve capability: %v", err)
	}

	// 3. User signs in, producing sessions
	up, err := app.SignUp(ctx, auth.SignUpInput{
		Email:    "alice@example.com",
		Password: "SuperSecurePassword123!",
		Session: auth.SessionOptions{
			IPAddress: "192.168.1.100",
			UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0",
		},
	})
	if err != nil {
		log.Fatalf("signup failed: %v", err)
	}

	// 4. List user's active sessions with rich device metadata
	sessions, err := sessionMgr.ListDetailedSessions(ctx, up.User.ID, up.Session.ID)
	if err != nil {
		log.Fatalf("list sessions failed: %v", err)
	}

	for _, s := range sessions {
		fmt.Printf("Session ID: %s | Device: %s (%s) | Current: %t\n",
			s.Session.ID, s.Metadata.Device.Name, s.Metadata.Device.OS, s.IsCurrent)
	}

	// 5. Revoke other sessions (e.g. "Log out of all other devices")
	if err := sessionMgr.RevokeOtherSessions(ctx, up.User.ID, up.Session.ID); err != nil {
		log.Fatalf("failed to revoke other sessions: %v", err)
	}
}
```

---

## Configuration

Configure the plugin using functional options in `multisession.New(...)`:

```go
mod := multisession.New(
    // Limit to 3 concurrent active sessions.
    // When exceeded, automatically evict the oldest session (FIFO).
    multisession.WithMaxConcurrentSessions(3, multisession.OverflowRevokeOldest),

    // Or reject new session creation when limit is reached:
    // multisession.WithMaxConcurrentSessions(3, multisession.OverflowReject),

    // Custom metadata persistence store (defaults to thread-safe in-memory store)
    multisession.WithMetadataStore(customStore),

    // Metadata cache TTL (default: 10 minutes)
    multisession.WithMetadataCacheTTL(15 * time.Minute),
)
```

---

## Public API

### Capability Interface

Applications access the capability via `auth.Get[plugins.MultiSession](app)` or `auth.Get[multisession.MultiSession](app)`:

```go
type MultiSession interface {
    // ListSessions returns all active, valid sessions for a user from Core SessionStore.
    ListSessions(ctx context.Context, userID string) ([]*session.Session, error)

    // ListDetailedSessions returns all active sessions for a user, enriched with device
    // and custom metadata, and flags the current session if currentSessionID matches.
    ListDetailedSessions(ctx context.Context, userID string, currentSessionID string) ([]*SessionDetail, error)

    // GetSession returns an active session by its ID. Returns ErrSessionNotFound if not found or expired.
    GetSession(ctx context.Context, sessionID string) (*session.Session, error)

    // GetDetailedSession returns an active session enriched with its metadata.
    GetDetailedSession(ctx context.Context, sessionID string) (*SessionDetail, error)

    // RevokeSession revokes a specific session by ID, updating the Store first,
    // invalidating relevant Cache entries, and publishing revocation events.
    RevokeSession(ctx context.Context, sessionID string) error

    // RevokeOtherSessions revokes all active sessions for userID except currentSessionID.
    RevokeOtherSessions(ctx context.Context, userID, currentSessionID string) error

    // RevokeAllSessions revokes every active session for userID.
    RevokeAllSessions(ctx context.Context, userID string) error

    // SetMetadata persists or updates device and custom metadata for a session.
    SetMetadata(ctx context.Context, sessionID string, meta MetadataInput) error

    // GetMetadata retrieves metadata associated with a session.
    GetMetadata(ctx context.Context, sessionID string) (*Metadata, error)
}
```

### Domain Errors

Sentinel errors allow explicit error handling:

- `multisession.ErrSessionNotFound`: Session does not exist or has expired.
- `multisession.ErrSessionAlreadyRevoked`: Session is already revoked.
- `multisession.ErrInvalidInput`: Required parameter (e.g. `userID`, `sessionID`) is empty.
- `multisession.ErrUnauthorized`: Target session does not belong to the user.
- `multisession.ErrMaxConcurrentSessionsReached`: Session limit reached under `OverflowReject` policy.
- `multisession.ErrMetadataNotFound`: No metadata recorded for session.

---

## Device & Session Metadata

When sessions are created, User-Agent strings and client IP addresses are automatically parsed into typed `DeviceMetadata`:

```go
type DeviceMetadata struct {
    Name      string `json:"name,omitempty"`      // e.g. "Chrome on macOS"
    Type      string `json:"type,omitempty"`      // e.g. "desktop", "mobile", "tablet", "bot"
    OS        string `json:"os,omitempty"`        // e.g. "macOS", "iOS", "Windows", "Linux", "Android"
    Browser   string `json:"browser,omitempty"`   // e.g. "Chrome", "Safari", "Firefox", "Edge"
    IPAddress string `json:"ip_address,omitempty"`
}
```

Applications can also associate custom key-values (e.g. 2FA verification status, office location) via `SetMetadata`:

```go
err := sessionMgr.SetMetadata(ctx, sessionID, multisession.MetadataInput{
    Device: multisession.DeviceMetadata{
        Name: "HQ Office Desktop",
    },
    Custom: map[string]string{
        "trusted_device": "true",
        "office":         "Zurich",
    },
})
```

---

## Persistence & SQL Migrations

Session records reside in the Core `sessions` table. Optional metadata records are stored in `session_metadata`:

```sql
CREATE TABLE IF NOT EXISTS session_metadata (
    session_id      VARCHAR(64) PRIMARY KEY,
    user_id         VARCHAR(64) NOT NULL,
    device_name     VARCHAR(255),
    device_type     VARCHAR(64),
    device_os       VARCHAR(64),
    device_browser  VARCHAR(64),
    device_ip       VARCHAR(64),
    custom_metadata TEXT,
    created_at      TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at      TIMESTAMP WITH TIME ZONE NOT NULL,
    CONSTRAINT fk_session_metadata_session
        FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_session_metadata_user_id ON session_metadata(user_id);
```

An in-memory metadata store (`store/memory`) is enabled by default.

---

## Cache Invalidation Strategy

The plugin maintains strict cache-aside semantics:

1. **Store is Source of Truth**: All operations commit to the database before modifying cache.
2. **Immediate Invalidation**:
   - `RevokeSession`: Stores revocation, then deletes `gomodularauth:session:<tokenHash>` and `gomodularauth:multisession:meta:<sessionID>`.
   - `RevokeOtherSessions` / `RevokeAllSessions`: Atomically revokes sessions inside Store transaction, then invalidates all corresponding cache entries post-commit.
3. **Resilience**: Cache misses degrade gracefully to the persistent Store.

---

## Observational Events

The plugin publishes non-sensitive events to the GoModularAuth event dispatcher:

- `multisession.session_revoked`: A single session was revoked.
- `multisession.sessions_revoked`: Bulk sessions were revoked (e.g. revoke others or revoke all).
- `multisession.session_evicted`: A session was evicted due to concurrent session limits.
- `multisession.metadata_updated`: Metadata was saved or updated.

Payloads never include secrets or token hashes.

---

## Security Model

- **Authorization & Ownership Checks**: `RevokeOtherSessions` verifies that the `currentSessionID` belongs to the requesting `userID` before revoking other sessions, preventing cross-tenant privilege escalation.
- **No Secret Exposure**: Plaintext tokens are never stored, logged, or exposed. Tokens hashes are never included in event payloads.
- **Concurrent Revocation Safety**: Calling `RevokeSession` concurrently on the same session executes idempotently without race conditions.
- **Atomic Concurrency Limiting**: `BeforeSessionCreate` hook executes inside the Core Store transaction, ensuring session counts cannot be exceeded through parallel sign-ins.

---

## Testing

Run tests across the entire module:

```bash
go test -v ./...
go vet ./...
```

---

## License

MIT License. See [LICENSE](LICENSE) for details.
