# GoModularAuth Password Policy Plugin (`gomodularauth-password-policy`)

[![Go Reference](https://pkg.go.dev/badge/github.com/BladiCreator/go-modular-auth/plugins/password-policy.svg)](https://pkg.go.dev/github.com/BladiCreator/go-modular-auth/plugins/password-policy)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

`gomodularauth-password-policy` provides configurable password-strength, complexity, reuse prevention, and compromised-password detection through Core authentication hooks in [GoModularAuth](https://github.com/BladiCreator/go-modular-auth).

---

## Table of Contents

- [1. Problem Solved](#1-problem-solved)
- [2. Features](#2-features)
- [3. Installation](#3-installation)
- [4. Configuration & Registration](#4-configuration--registration)
- [5. Primary API](#5-primary-api)
- [6. Usage Examples](#6-usage-examples)
- [7. Persistence & Schema](#7-persistence--schema)
- [8. Audit Events](#8-audit-events)
- [9. Security Model](#9-security-model)

---

## 1. Problem Solved

Default authentication configurations often enforce only basic length boundaries. Enterprise environments require compliance with security frameworks (NIST SP 800-63B, PCI-DSS, ISO 27001) that mandate:
- Minimum and maximum length guarantees.
- Complexity constraints (uppercase, lowercase, numbers, symbols).
- Password history tracking to prevent immediate reuse of recent passwords.
- Compromised or breached password dictionary blocks.
- Non-invasive hook-based workflow interception during `SignUp`, `ChangePassword`, and `ResetPassword`.

`gomodularauth-password-policy` enforces these policies without implementing custom password hashing, strictly reusing GoModularAuth Core's `PasswordHasher`.

---

## 2. Features

- **Configurable Length Constraints**: Enforces minimum and maximum password lengths.
- **Character Complexity Enforcement**: Optional requirements for uppercase, lowercase, digits, and special symbols.
- **Password History & Reuse Prevention**: Records historical password hashes and verifies candidate passwords against the last N passwords using Core's `PasswordHasher.Verify()`.
- **Compromised & Common Passwords Detection**: Built-in blocklist of widely breached/common passwords with extensible custom checking functions.
- **Hook-Based Interception**: Seamlessly hooks into `BeforeSignUp` to abort invalid registrations before database writes, and `AfterSignUp` to record initial history.
- **Change & Reset Password Integration**: Exposes unified operations that validate policies before updating credentials in Core.
- **Structured Audit Events**: Publishes `password_policy.validated`, `password_policy.violation`, and `password_policy.history_recorded` events.
- **Capability Access**: Exposes the typed `PasswordPolicy` capability via `auth.Get[plugins.PasswordPolicy]()`.

---

## 3. Installation

```bash
go get github.com/BladiCreator/go-modular-auth/plugins/password-policy
```

---

## 4. Configuration & Registration

Register `passwordpolicy.New()` as a plugin in GoModularAuth:

```go
package main

import (
    "log"

    auth "github.com/BladiCreator/go-modular-auth"
    passwordpolicy "github.com/BladiCreator/go-modular-auth/plugins/password-policy"
    "github.com/BladiCreator/go-modular-auth/plugins/password-policy/plugins"
)

func main() {

    engine, err := auth.New(auth.Config{
        Plugins: []auth.PluginModule{
            passwordpolicy.New(
                passwordpolicy.WithMinLength(10),
                passwordpolicy.WithComplexity(true, true, true, true), // upper, lower, digit, symbol
                passwordpolicy.WithHistoryCount(5),                    // prevent reuse of last 5 passwords
                passwordpolicy.WithRejectCompromised(true),
            ),
        },
    })
    if err != nil {
        log.Fatalf("failed to initialize auth: %v", err)
    }

    // Resolve typed capability
    policyPlugin, err := auth.Get[plugins.PasswordPolicy](engine)
    if err != nil {
        log.Fatalf("failed to resolve PasswordPolicy capability: %v", err)
    }
}
```

---

## 5. Primary API

The capability is exposed via the typed `PasswordPolicy` interface:

```go
type PasswordPolicy interface {
    // ValidatePassword evaluates a candidate password against the policy (and history if userID is provided).
    ValidatePassword(ctx context.Context, password string, userID string) error

    // ValidatePasswordDetailed returns structured validation status and specific violation codes.
    ValidatePasswordDetailed(ctx context.Context, password string, userID string) (*ValidationResult, error)

    // ChangePassword enforces policy, changes password via Core, and records password history.
    ChangePassword(ctx context.Context, in ChangePasswordInput) error

    // ResetPassword enforces policy, resets password via Core, and records history.
    ResetPassword(ctx context.Context, in ResetPasswordInput) error

    // RecordHistory stores a password hash in the user's password history and prunes old records.
    RecordHistory(ctx context.Context, userID, hash string) error

    // GetHistory retrieves historical password records for a user up to limit.
    GetHistory(ctx context.Context, userID string, limit int) ([]*PasswordHistory, error)

    // ClearHistory removes all historical password records for a user.
    ClearHistory(ctx context.Context, userID string) error

    // GetPolicy returns the currently active policy configuration.
    GetPolicy() Policy
}
```

---

## 6. Usage Examples

### Validating Candidate Passwords

```go
// Validate password during registration or form entry
err := policyPlugin.ValidatePassword(ctx, "P@ssword123!", "")
if err != nil {
    // ErrPasswordTooShort, ErrPasswordRequiresUppercase, ErrPasswordCompromised, etc.
    log.Printf("Password rejected: %v", err)
}
```

### Changing Password with Reuse Prevention

```go
err := policyPlugin.ChangePassword(ctx, passwordpolicy.ChangePasswordInput{
    UserID:          "user_123",
    CurrentPassword: "OldPassword1!",
    NewPassword:     "NewSecurePassword2@",
})
if errors.Is(err, passwordpolicy.ErrPasswordInHistory) {
    log.Println("You cannot reuse a recent password.")
}
```

---

## 7. Persistence & Schema

Password history records are persisted via GoModularAuth's unified schema engine (`schema.RegisterSchema`) using the global database adapter:

- Table: `password_histories` (accessed via `sdk.Model[PasswordHistory]`).
- Indexes: `user_id` and `created_at` for rapid retrieval and pruning of previous password hashes.
- Migrations: Located in `migrations/001_create_password_policy_tables.sql`.

---

## 8. Audit Events

| Event Name | Description |
|---|---|
| `password_policy.validated` | Password candidate met all policy requirements |
| `password_policy.violation` | Password failed one or more requirements |
| `password_policy.history_recorded` | A password hash was preserved in user history |

---

## 9. Security Model

1. **No Password Hashing Reimplementation**: The plugin relies on Core's `PasswordHasher` (Argon2id), avoiding fragile custom crypto implementations.
2. **Never Weakens Core Security**: Minimum length configuration cannot circumvent Core's baseline security limits.
3. **No Plaintext Passwords Stored**: History tables store ONLY salted and hashed passwords (`PasswordHash`).
4. **Hook Interception**: Invalid passwords in `SignUp` are rejected before any Core user rows or credentials are created in the database.
