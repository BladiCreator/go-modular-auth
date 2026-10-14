# Last Login Tracking Plugin

The **LastLogin Plugin** (`plugins/lastlogin`) tracks and records user authentication activity, timestamps, authentication methods (password, OAuth, passkeys), and originating IP/User-Agent metadata.

---

## 1. Problem Solved

Security-conscious applications and enterprise compliance frameworks require tracking authentication metadata:
- **Suspicious Activity & Anomaly Detection**: Identifying logins from unexpected IP ranges or geographic locations.
- **Account Stale Detection**: Identifying inactive user accounts eligible for de-provisioning.
- **User Transparency**: Showing users their "Last seen from IP: X at Time: Y" on security profile pages.

---

## 2. Installation & Registration

```bash
go get github.com/BladiCreator/go-modular-auth/plugins/lastlogin
```

Register the plugin in the GoModularAuth configuration:

```go
package main

import (
    auth "github.com/BladiCreator/go-modular-auth"
    "github.com/BladiCreator/go-modular-auth/plugins/lastlogin"
)

func main() {
    lastLoginMod := lastlogin.New()

    engine, err := auth.New(auth.Config{
        Store:   store,
        Plugins: []auth.PluginModule{lastLoginMod},
    })
    if err != nil {
        panic(err)
    }

    // Resolve capability
    tracker := auth.MustGet[lastlogin.LastLogin](engine)
    _ = tracker
}
```

---

## 3. Capability Interface: `lastlogin.LastLogin`

```go
type LastLogin interface {
    Record(ctx context.Context, rec *Record) error
    Get(ctx context.Context, userID string) (*Record, error)
}
```

### Domain Entity: `Record`
```go
type Record struct {
    UserID     string    `json:"user_id"`
    AccountID  string    `json:"account_id,omitempty"`
    Method     string    `json:"method"`     // "password", "oauth_google", "passkey"
    IP         string    `json:"ip,omitempty"`
    UserAgent  string    `json:"user_agent,omitempty"`
    LoggedInAt time.Time `json:"logged_in_at"`
}
```

---

## 4. Usage

### Recording Authentication Events
```go
err := tracker.Record(ctx, &lastlogin.Record{
    UserID:    user.ID,
    Method:    "passkey",
    IP:        "203.0.113.195",
    UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)...",
})
```

### Querying Last Login Activity
```go
activity, err := tracker.Get(ctx, user.ID)
if err != nil {
    if errors.Is(err, lastlogin.ErrNotFound) {
        fmt.Println("User has never logged in yet")
        return
    }
    return err
}

fmt.Printf("Last login: %s via %s from IP %s\n",
    activity.LoggedInAt.Format(time.RFC3339),
    activity.Method,
    activity.IP,
)
```
