# GoModularAuth SSO Plugin (`gomodularauth-sso`)

[![Go Reference](https://pkg.go.dev/badge/github.com/BladiCreator/go-modular-auth/plugins/sso.svg)](https://pkg.go.dev/github.com/BladiCreator/go-modular-auth/plugins/sso)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

`gomodularauth-sso` provides enterprise Single Sign-On (SSO) configuration, domain discovery, and multi-tenant identity federation across OpenID Connect (OIDC) and SAML 2.0 protocols for [GoModularAuth](https://github.com/BladiCreator/go-modular-auth).

---

## Table of Contents

- [1. Problem Solved](#1-problem-solved)
- [2. Installation](#2-installation)
- [3. Configuration](#3-configuration)
- [4. Registration in GoModularAuth](#4-registration-in-gomodularauth)
- [5. Public API](#5-public-api)
- [6. Dependencies](#6-dependencies)
- [7. Persistence](#7-persistence)
- [8. Cache](#8-cache)
- [9. Events](#9-events)
- [10. Security Invariants](#10-security-invariants)
- [11. Testing](#11-testing)

---

## 1. Problem Solved

Enterprise SaaS applications require multi-tenant identity federation:
- Each enterprise organization (customer) configures their own Identity Provider (IdP) such as Okta, Azure AD / Microsoft Entra, Google Workspace, PingFederate, or OneLogin.
- Users authenticate via corporate email domain discovery (e.g. entering `@acme.com` directs the user to Acme's IdP).
- Organizations require automated user provisioning via Just-In-Time (JIT) provisioning.
- In multi-tenant environments, cross-tenant identity confusion or cross-organization account takeover represents a catastrophic security vulnerability: an IdP assertion from Tenant A claiming an email for Tenant B must never grant access or link to Tenant B.

`gomodularauth-sso` solves these problems by providing:
1. **Organization-Scoped Configuration**: Every IdP configuration belongs strictly to an Organization, with domain registration and conflict detection.
2. **Cross-Tenant Isolation**: Assertions are strictly validated against the organization's allowed domains; cross-tenant domain mismatches trigger immediate rejection.
3. **Dual Protocol Support**: Native, pure Go implementations of OIDC Relying Party (Discovery, PKCE S256, Nonce, JWKS signature verification) and SAML 2.0 Service Provider (AuthnRequest, Deflate/Base64, XML assertion verification, Audience restrictions).
4. **Domain Discovery**: Automated routing from user email or corporate domain to the active organization IdP.
5. **JIT Provisioning & Account Linking**: Automatically provisions Core Users and Accounts with configurable default roles in `gomodularauth-organizations`.
6. **Audited Changes**: Structured audit events for every configuration modification and login outcome.

---

## 2. Installation

```bash
go get github.com/BladiCreator/go-modular-auth/plugins/sso
```

---

## 3. Configuration

```go
import (
    "time"
    auth "github.com/BladiCreator/go-modular-auth"
    sso "github.com/BladiCreator/go-modular-auth/plugins/sso"
)

ssoModule := sso.New(
    sso.WithStateTTL(10 * time.Minute),
    sso.WithSPEntityID("urn:myapp:sp"),
    sso.WithSPACSURL("https://myapp.com/sso/saml/acs"),
)
```

---

## 4. Registration in GoModularAuth

```go
engine, err := auth.New(auth.Config{
    Adapter: adaptermem.New(),
    Cache: coreCache,
    Plugins: []auth.PluginModule{
        organizationsModule, // Optional: for JIT membership assignment
        ssoModule,
    },
})
if err != nil {
    log.Fatalf("failed to initialize auth: %v", err)
}

// Access typed capability
ssoCap, err := auth.Get[plugins.SSO](engine)
if err != nil {
    log.Fatalf("failed to resolve SSO capability: %v", err)
}
```

---

## 5. Public API

```go
type SSO interface {
    // Configuration Management (Organization-scoped)
    CreateConfig(ctx context.Context, in CreateConfigInput) (*SSOConfig, error)
    GetConfig(ctx context.Context, orgID, configID string) (*SSOConfig, error)
    ListConfigsByOrganization(ctx context.Context, orgID string) ([]*SSOConfig, error)
    UpdateConfig(ctx context.Context, in UpdateConfigInput) (*SSOConfig, error)
    DeleteConfig(ctx context.Context, orgID, configID string) error

    // Domain Discovery
    DiscoverByEmail(ctx context.Context, email string) (*DomainDiscoveryResult, error)
    DiscoverByDomain(ctx context.Context, domain string) (*DomainDiscoveryResult, error)

    // SSO Protocol Operations
    InitiateSSO(ctx context.Context, in InitiateSSOInput) (*InitiateSSOResult, error)
    ProcessSSOCallback(ctx context.Context, in ProcessSSOCallbackInput) (*SSOAuthResult, error)

    // Account Linking & Identity Federation Management
    LinkAccount(ctx context.Context, in LinkAccountInput) (*account.Account, error)
    UnlinkAccount(ctx context.Context, orgID, userID, providerID string) error
    ListLinkedAccounts(ctx context.Context, orgID, userID string) ([]*account.Account, error)
}
```

---

## 6. Dependencies

| Dependency | Purpose | Rationale |
| :--- | :--- | :--- |
| `github.com/BladiCreator/go-modular-auth` | Core GoModularAuth engine | Core User, Account, Session, and Store |
| `github.com/BladiCreator/go-modular-auth/plugin-sdk` | Plugin runtime SDK | Dependency injection and capability registration |
| `github.com/BladiCreator/go-modular-auth/plugins/organizations` | Multi-tenant organization support | Optional JIT organization membership assignment |
| Go Standard Library (`crypto/*`, `net/http`, `encoding/xml`) | Pure Go Cryptography & Networking | No external third-party SAML/JWT dependencies |

---

## 7. Persistence

The plugin defines an explicit persistence contract in `store.Store`:
- `SaveConfig`, `GetConfig`, `ListConfigsByOrganization`, `UpdateConfig`, `DeleteConfig`
- `GetConfigByDomain`
- `SaveState`, `GetState`, `ConsumeState`, `DeleteState`, `PurgeExpiredStates`

PostgreSQL migration schemas are available in `migrations/001_create_sso_tables.sql`.

---

## 8. Cache

- **JWKS Cache**: Cryptographic keys retrieved from OIDC discovery JWKS endpoints are cached in-memory with automatic TTL expiration.
- **State Store**: In-flight state sessions are persisted authoritatively in the Store to prevent state loss across server restarts.

---

## 9. Events

The plugin emits structured security audit events:
- `sso.config.created`
- `sso.config.updated`
- `sso.config.deleted`
- `sso.login.success`
- `sso.login.failed`
- `sso.jit.provisioned`
- `sso.account.linked`

---

## 10. Security Invariants

1. **Cross-Tenant Identity Confusion**: Callback assertions are validated against the organization's allowed domains (`cfg.Domains`). Cross-tenant mismatches are strictly rejected with `ErrCrossTenantViolation`.
2. **Domain Collision Protection**: No two organizations can register the same domain (`ErrDomainConflict`).
3. **Single-Use State Sessions**: `ConsumeState` atomically marks `consumed_at`. Replay attacks are rejected with `ErrStateConsumed`.
4. **Mandatory PKCE & Nonce**: OIDC flows mandate S256 PKCE and random nonces to protect against authorization code interception.
5. **Audience & Expiration Validation**: SAML assertions validate `AudienceRestriction` and `NotBefore`/`NotOnOrAfter` validity windows.

---

## 11. Testing

```bash
go test -v -race ./...
```
