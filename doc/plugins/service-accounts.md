# Service Accounts Plugin

The **Service Accounts Plugin** (`plugins/service-accounts`) manages machine-to-machine (M2M) non-human identities, scoped API credentials, and secret rotation for internal microservices, daemon jobs, and third-party automated integrations.

---

## 1. Problem Solved

Automated jobs and external systems should not authenticate using human user accounts:
- **No Password Lifecycles**: Machine accounts must not be subject to human password expiration or interactive MFA challenges.
- **Granular Scopes**: Machine access must be restricted to explicit scopes (`invoices:write`, `metrics:read`).
- **Secret Rotation**: Need atomic credential rotation (`RotateSecret`) without downtime.
- **Revocation & Auditing**: Instant suspension of compromised machine accounts without affecting human accounts.

---

## 2. Installation & Registration

```bash
go get github.com/BladiCreator/go-modular-auth/plugins/service-accounts
```

Register the plugin:

```go
package main

import (
    auth "github.com/BladiCreator/go-modular-auth"
    "github.com/BladiCreator/go-modular-auth/plugins/service-accounts"
)

func main() {
    saMod := serviceaccounts.New()

    engine, err := auth.New(auth.Config{
        Store:   store,
        Plugins: []auth.PluginModule{saMod},
    })
    if err != nil {
        panic(err)
    }

    // Resolve capability
    saManager := auth.MustGet[serviceaccounts.ServiceAccountManager](engine)
    _ = saManager
}
```

---

## 3. Capability Interface: `serviceaccounts.ServiceAccountManager`

```go
type ServiceAccountManager interface {
    Create(ctx context.Context, in CreateInput) (*ServiceAccount, string, error)
    Authenticate(ctx context.Context, id, secret string) (*ServiceAccount, error)
    RotateSecret(ctx context.Context, id string) (string, error)
    Get(ctx context.Context, id string) (*ServiceAccount, error)
    List(ctx context.Context, ownerID string) ([]*ServiceAccount, error)
    Revoke(ctx context.Context, id string) error
}
```

---

## 4. Usage

### 4.1 Creating a Service Account
```go
sa, plaintextSecret, err := saManager.Create(ctx, serviceaccounts.CreateInput{
    Name:        "stripe-webhook-worker",
    Description: "Worker verifying and handling incoming payment webhooks",
    OwnerID:     organizationID,
    Scopes:      []string{"payments:read", "payments:write"},
})
// Store or hand plaintextSecret to daemon once; only SHA-256 hash is persisted
```

### 4.2 Authenticating Incoming Machine Calls
```go
saAccount, err := saManager.Authenticate(ctx, saID, providedSecret)
if err != nil {
    // ErrInvalidSecret or ErrInactive
    return err
}

fmt.Printf("Authenticated M2M Service Account: %s (Scopes: %v)\n", saAccount.Name, saAccount.Scopes)
```

### 4.3 Rotating Secrets
```go
// Atomically generate new secret and invalidate previous secret
newSecret, err := saManager.RotateSecret(ctx, saAccount.ID)
```

### 4.4 Revoking Service Accounts
```go
// Immediately deactivate service account
err := saManager.Revoke(ctx, saAccount.ID)
```
