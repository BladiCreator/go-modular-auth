# GoModularAuth MultiSession Plugin

`gomodularauth-multi-session` provides advanced management of multiple concurrent Core Sessions for GoModularAuth users while strictly preserving Core session semantics.

## Installation

```bash
go get github.com/BladiCreator/go-modular-auth/plugins/multisession
```

## Quick Start

```go
package main

import (
	"context"
	"fmt"
	"log"

	auth "github.com/BladiCreator/go-modular-auth"
	adaptermem "github.com/BladiCreator/go-modular-auth/adapters/memory"
	multisession "github.com/BladiCreator/go-modular-auth/plugins/multisession"
	"github.com/BladiCreator/go-modular-auth/plugins/multisession/plugins"
)

func main() {
	ctx := context.Background()

	// 1. Initialize GoModularAuth with MultiSession plugin
	app, err := auth.New(auth.Config{
		Adapter: adaptermem.NewAdapter(),
		Cache:   adaptermem.NewCache(),
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

Detailed guide: [**`doc/plugins/multisession.md`**](../../doc/plugins/multisession.md).
