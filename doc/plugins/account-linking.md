# GoModularAuth Account Linking Plugin (`gomodularauth-account-linking`)

[![Go Reference](https://pkg.go.dev/badge/github.com/BladiCreator/go-modular-auth/plugins/account-linking.svg)](https://pkg.go.dev/github.com/BladiCreator/go-modular-auth/plugins/account-linking)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

`gomodularauth-account-linking` provides secure linking and unlinking of authentication accounts while preserving a single canonical Core User identity in [GoModularAuth](https://github.com/BladiCreator/go-modular-auth).

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

Modern enterprise applications require users to authenticate via multiple identity providers (Google, GitHub, Okta, SAML, WebAuthn Passkeys, username/password). Without strict account linking controls, systems suffer from:
- **Account Takeover via Unsafe Automatic Linking**: An attacker registering an account on a low-assurance provider with an existing victim's email could hijack the victim's profile.
- **Silent Merging**: Merging two separate user profiles without explicit intent can violate data privacy, confuse access controls, and break compliance.
- **User Lockout / Orphaning**: Allowing a user to unlink their only authentication method leaves them permanently unable to sign in.
- **Race Conditions**: Concurrent linking attempts can corrupt identities or double-bind provider IDs across users.

`gomodularauth-account-linking` solves all of these problems through transactional identity changes, strict conflict detection, ownership enforcement, lockout prevention, and ticket-based linking ceremonies.

---

## 2. Features

- **Multi-Mechanism Support**: Links and unlinks OAuth, SAML, Passkeys, Username, Email/Password, and any GoModularAuth authentication plugin.
- **Strict Collision Detection**: Never silently merges two `User` entities. Detects if an external account belongs to another user and rejects with `ErrAccountConflict`.
- **Lockout Prevention**: Prevents unlinking the user's sole remaining authentication method (`ErrCannotUnlinkFinalAuthMethod`) unless explicitly overridden (`AllowOrphan: true`).
- **Ticket-Based Linking Ceremonies**: Generates single-use, cryptographically secure linking tickets (`LinkingTicket`) with TTL for safe browser-redirect authentication flows (OAuth, WebAuthn).
- **Atomic Transactions**: All identity changes execute inside `coreStore.Transaction()` to ensure zero partial state.
- **Role & Ownership Authorization**: Validates caller `Principal` to ensure non-administrative users can only manipulate their own identity.
- **Concurrent Safety**: Safe against simultaneous account claims and race conditions.
- **Structured Audit Logging**: Emits `account.linked`, `account.unlinked`, `account.link.failed`, and `account.unlink.failed` audit events.

---

## 3. Installation

```bash
go get github.com/BladiCreator/go-modular-auth/plugins/account-linking
```

---

## 4. Configuration & Registration

Register `accountlinking.New()` in GoModularAuth:

```go
package main

import (
    "log"

    auth "github.com/BladiCreator/go-modular-auth"
    "github.com/BladiCreator/go-modular-auth/adapters/memory"
    accountlinking "github.com/BladiCreator/go-modular-auth/plugins/account-linking"
    "github.com/BladiCreator/go-modular-auth/plugins/account-linking/plugins"
)

func main() {
    ad := memory.NewAdapter()

    engine, err := auth.New(auth.Config{
        Adapter: ad,
        Plugins: []auth.PluginModule{
            accountlinking.New(
                accountlinking.WithAllowOrphanByDefault(false),
            ),
        },
    })
    if err != nil {
        log.Fatalf("failed to initialize auth: %v", err)
    }

    // Resolve typed capability
    linking, err := auth.Get[plugins.AccountLinking](engine)
    if err != nil {
        log.Fatalf("failed to resolve AccountLinking capability: %v", err)
    }

    _ = linking
}
```

---

## 5. Primary API

The capability is exposed via the typed `AccountLinking` interface:

```go
type AccountLinking interface {
    // Direct linking
    LinkAccount(ctx context.Context, in LinkAccountInput) (*account.Account, error)
    UnlinkAccount(ctx context.Context, in UnlinkAccountInput) error
    UnlinkAccountByID(ctx context.Context, in UnlinkAccountByIDInput) error

    // Ticket-based linking ceremonies
    CreateLinkingTicket(ctx context.Context, in CreateTicketInput) (*LinkingTicketResult, error)
    CompleteLinkingTicket(ctx context.Context, in CompleteTicketInput) (*account.Account, error)
    GetLinkingTicket(ctx context.Context, ticketToken string) (*LinkingTicket, error)
    RevokeLinkingTicket(ctx context.Context, ticketToken string) error

    // Queries & Safety checks
    ListLinkedAccounts(ctx context.Context, userID string) ([]*account.Account, error)
    GetAccount(ctx context.Context, provider, providerID string) (*account.Account, error)
    CanUnlinkAccount(ctx context.Context, userID, accountID string) (bool, error)
}
```

---

## 6. Usage Examples

### Direct Account Linking

```go
// User links their verified Google account
account, err := linking.LinkAccount(ctx, accountlinking.LinkAccountInput{
    UserID:     "user_123",
    Provider:   "google",
    ProviderID: "google_sub_987654",
})
if err != nil {
    // ErrAccountConflict: account belongs to another user
    // ErrAccountAlreadyLinked: account already linked to this user
    log.Fatal(err)
}
```

### Two-Step Ticket-Based Ceremony (e.g. Linking in OAuth Flow)

```go
// 1. Authenticated user initiates linking in frontend
ticketRes, err := linking.CreateLinkingTicket(ctx, accountlinking.CreateTicketInput{
    UserID:         "user_123",
    TargetProvider: "github",
    TTL:            10 * time.Minute,
})

// Store ticketRes.TicketToken in secure session or redirect state parameter...

// 2. Upon callback from GitHub OAuth with verified subject
linkedAccount, err := linking.CompleteLinkingTicket(ctx, accountlinking.CompleteTicketInput{
    TicketToken: ticketRes.TicketToken,
    Provider:    "github",
    ProviderID:  "gh_user_443322",
})
if err != nil {
    // ErrTicketExpired, ErrTicketAlreadyUsed, ErrProviderMismatch, ErrAccountConflict
    log.Fatal(err)
}
```

### Unlinking an Account with Lockout Prevention

```go
// Attempting to remove an account
err := linking.UnlinkAccount(ctx, accountlinking.UnlinkAccountInput{
    UserID:     "user_123",
    Provider:   "google",
    ProviderID: "google_sub_987654",
})
if errors.Is(err, accountlinking.ErrCannotUnlinkFinalAuthMethod) {
    fmt.Println("Cannot unlink: user must retain at least one login method.")
}
```

---

## 7. Persistence & Schema

Linking tickets are persisted via GoModularAuth's unified schema engine (`schema.RegisterSchema`) using the global database adapter:

- Table: `linking_tickets` (accessed via `sdk.Model[LinkingTicket]`).
- Indexes: `token_hash` (unique SHA-256 hash lookup) and `expires_at` (expiration indexing).
- Migrations: Located in `migrations/001_create_account_linking_tables.sql`.

---

## 8. Audit Events

| Event Name | Description |
|---|---|
| `account.linked` | An account was successfully linked to a user |
| `account.unlinked` | An account was unlinked from a user |
| `account.link.failed` | Account linking failed due to conflict or authorization |
| `account.unlink.failed` | Account unlinking was rejected (e.g. final auth method) |
| `account.ticket.created` | A linking ticket was issued |

---

## 9. Security Model

1. **No Silent Merging**: Strict conflict check prevents account takeover attacks.
2. **Lockout Protection**: Prevents account orphaning by validating remaining auth methods.
3. **Single-Use Tokens**: Linking tickets are cryptographically hashed and consumed atomically.
4. **Ownership Verification**: Enforces authorization via Core `Principal`.
5. **Transactional Integrity**: All core account operations run inside database transactions.
