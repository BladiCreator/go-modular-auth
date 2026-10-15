# One-Time Token (OTT) Plugin

The **One-Time Token Plugin** (`plugins/one-time-token`) provides a general-purpose primitive for generating, validating, and atomically consuming cryptographically secure, single-use verification tokens.

---

## 1. Problem Solved

Custom application workflows frequently require ephemeral, single-use proofs of intent:
- Step-up authentication challenges (confirming a wire transfer or sensitive setting modification).
- Account email change confirmations.
- Expiring secure file download links.
- Temporary invitation or delegation tickets.

The `one-time-token` plugin leverages the hardened GoModularAuth token subsystem (`verification.Token`), ensuring:
- **Zero Plaintext Persistence**: Plaintext tokens are returned exactly once upon creation; only SHA-256 hashes are stored.
- **Atomic Single-Use Guarantee**: Atomic compare-and-swap marking prevents concurrent double-consumption and replay attacks.
- **Automatic Expiration**: Enforced TTL boundaries.

---

## 2. Installation & Registration

```bash
go get github.com/BladiCreator/go-modular-auth/plugins/one-time-token
```

Register the plugin:

```go
package main

import (
    auth "github.com/BladiCreator/go-modular-auth"
    "github.com/BladiCreator/go-modular-auth/plugins/one-time-token"
)

func main() {
    ottMod := ott.New(
        ott.WithDefaultTTL(10 * time.Minute),
        ott.WithDefaultPurpose("general_verification"),
    )

    engine, err := auth.New(auth.Config{
        Adapter: adaptermem.New(),
        Plugins: []auth.PluginModule{ottMod},
    })
    if err != nil {
        panic(err)
    }

    // Resolve capability
    ottSvc := auth.MustGet[ott.OneTimeToken](engine)
    _ = ottSvc
}
```

---

## 3. Capability Interface: `ott.OneTimeToken`

```go
type OneTimeToken interface {
    // Generate creates a secure, single-use token bound to subject.
    Generate(ctx context.Context, subject string, opts ...GenerateOption) (string, error)

    // Consume atomically consumes the token and returns the verification token.
    Consume(ctx context.Context, token string, opts ...GenerateOption) (*verification.Token, error)

    // Revoke invalidates all active tokens for the given subject and purpose.
    Revoke(ctx context.Context, subject string, opts ...GenerateOption) error
}
```

---

## 4. Usage

### 4.1 Issuing a Token
```go
// Issue a token for a sensitive financial transfer
tokenString, err := ottSvc.Generate(ctx, currentUserID,
    ott.WithCustomPurpose("wire_transfer_confirmation"),
    ott.WithCustomTTL(5 * time.Minute),
)
```

### 4.2 Atomically Consuming a Token
```go
// When user provides the token string:
tok, err := ottSvc.Consume(ctx, tokenString,
    ott.WithCustomPurpose("wire_transfer_confirmation"),
)
if err != nil {
    // ErrInvalidToken (covers expired, consumed, or invalid tokens identically)
    return err
}

// Proceed with sensitive operation
```

### 4.3 Revoking Pending Tokens
```go
// Revoke all pending tokens for a user
err := ottSvc.Revoke(ctx, currentUserID,
    ott.WithCustomPurpose("wire_transfer_confirmation"),
)
```
