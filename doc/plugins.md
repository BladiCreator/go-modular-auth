# Plugin System & Official Plugins Catalog

## 1. Principles of the Plugin System

GoModularAuth uses plugins to deliver capabilities beyond the minimal core model (`User + Account + Credential + Session`).

> **Rule of Inclusion**:
> If a capability can be excluded from an installation without breaking basic authentication, it belongs in a **Plugin**, not in the Core.

---

## 2. Plugin Architecture & Plugin SDK

To maintain absolute decoupling, GoModularAuth separates the **installable module** from the **consumed capability**:

```text
organizations.New(opts...)
        │
        ▼
   PluginModule (installed into Auth config)
        │
        ▼
   Plugin Context (plugin-sdk boundary)
        │
        ▼
   auth.Provide[T](host, service)
        │
        ▼
   auth.Get[T](engine) (consumed by application code)
```

### 2.1 The Plugin SDK (`plugin-sdk`)
Plugins use the `github.com/BladiCreator/go-modular-auth/plugin-sdk` package to interact safely with core infrastructure:

```go
package myplugin

import (
    auth "github.com/BladiCreator/go-modular-auth"
    sdk "github.com/BladiCreator/go-modular-auth/plugin-sdk"
)

type Module struct{}

func (m *Module) ID() string { return "my_plugin" }

func (m *Module) Init(h *auth.Host) error {
    ctx := sdk.NewContext(h)
    service := newService(ctx)
    return sdk.Provide[MyCapability](ctx, service)
}
```

The `*sdk.Context` exposes:
- `ctx.Core()`: Core authentication engine instance.
- `ctx.Adapter()`: Primary generic schema-driven database adapter.
- `ctx.DB()`: Typed database facade wrapping the adapter.
- `ctx.Schema()`: Compiled global schema across Core and all plugins.
- `ctx.Store()`: Core repository bridge.
- `ctx.Cache()`: Shared cache adapter with namespacing helpers.
- `ctx.Email()`: Transactional email sender.
- `ctx.Hooks()`: Registration for synchronous lifecycle hooks.
- `ctx.Events()`: In-process event dispatcher.
- `ctx.Logger()`: Logger tagged with the module ID.

### 2.2 Strongly Typed Consumption (`auth.Get[T]`)
Applications consume registered capabilities using Go generics without type assertions:

```go
// Returns (T, error)
orgs, err := auth.Get[organizations.Organization](engine)

// Panics if missing (recommended for application startup wiring)
orgs := auth.MustGet[organizations.Organization](engine)
```

---

## 3. Catalog of Official Plugins (35 Plugins)

The repository provides **35 production-ready plugins** structured into 8 distinct categories:

### 3.1 Authentication Factors & Passwordless (8 Plugins)

| Plugin | Import Path | Capability Interface | Description |
| :--- | :--- | :--- | :--- |
| **`account-linking`** | `.../plugins/account-linking` | `accountlinking.AccountLinking` | Links multiple auth accounts (OAuth, passkeys) to a single user identity. |
| **`anonymous`** | `.../plugins/anonymous` | `anonymous.Anonymous` | Issues guest/anonymous sessions and enables conversion to permanent accounts. |
| **`email-otp`** | `.../plugins/email-otp` | `emailotp.EmailOTP` | Passwordless verification via short-lived numeric email codes. |
| **`magic-link`** | `.../plugins/magic-link` | `magiclink.MagicLink` | Secure passwordless login via single-use email links. |
| **`passkeys`** | `.../plugins/passkeys` | `passkey.Passkey` | FIDO2 / WebAuthn discoverable credentials and biometric authentication. |
| **`phone`** | `.../plugins/phone` | `phone.Phone` | Phone authentication and SMS OTP verification with E.164 normalization. |
| **`twofactor`** | `.../plugins/twofactor` | `twofactor.TwoFactor` | TOTP (RFC 6238), backup recovery codes, and NIST SP 800-63B AAL1/AAL2 assurance levels. |
| **`username`** | `.../plugins/username` | `username.Username` | Enables username-based registration and authentication. |

### 3.2 Token Protocols & Sessions (4 Plugins)

| Plugin | Import Path | Capability Interface | Description |
| :--- | :--- | :--- | :--- |
| **`bearer`** | `.../plugins/bearer` | `bearer.Bearer` | Standard Bearer token authentication and validation. |
| **`jwt`** | `.../plugins/jwt` | `jwt.JWT` | Cryptographically signed and encrypted JSON Web Tokens with JWA and revocation checks. |
| **`multisession`** | `.../plugins/multisession` | `multisession.MultiSession` | Inspect active user sessions, remote sign-out, and concurrent session revocation. |
| **`one-time-token`** | `.../plugins/one-time-token` | `ott.OneTimeToken` | General-purpose secure single-use token issuance and validation. |

### 3.3 Single Sign-On (SSO) & Client Protocols (4 Plugins)

| Plugin | Import Path | Capability Interface | Description |
| :--- | :--- | :--- | :--- |
| **`oauth`** | `.../plugins/oauth` | `oauth.OAuth` | OAuth 2.0 social login client (Google, GitHub, Discord, Apple, GitLab, etc.). |
| **`oidc`** | `.../plugins/oidc` | `oidc.OIDC` | OpenID Connect 1.0 client integration with discovery and ID token validation. |
| **`saml`** | `.../plugins/saml` | `saml.SAML` | SAML 2.0 Service Provider (SP) integration for enterprise identity providers. |
| **`sso`** | `.../plugins/sso` | `sso.SSO` | Unified SSO orchestrator dynamically routing between SAML and OIDC. |

### 3.4 Identity Provider (IdP) Servers (4 Plugins)

| Plugin | Import Path | Capability Interface | Description |
| :--- | :--- | :--- | :--- |
| **`oauth-provider`** | `.../plugins/oauth-provider` | `oauthprovider.OAuthProvider` | Complete OAuth 2.1 Authorization Server: PKCE S256, Client Credentials, Refresh Token Rotation, Introspection (RFC 7662), Revocation (RFC 7009). |
| **`oidc-provider`** | `.../plugins/oidc-provider` | `oidcprovider.OIDCProvider` | OpenID Connect 1.0 Identity Provider (IdP) issuing ID tokens and user info endpoints. |
| **`saml-provider`** | `.../plugins/saml-provider` | `samlprovider.SAMLProvider` | SAML 2.0 Identity Provider (IdP) generating signed assertions. |
| **`scim`** | `.../plugins/scim` | `scim.SCIMProvider` | SCIM 2.0 (RFC 7643 / RFC 7644) server for automated user and group provisioning from Okta, Azure AD, etc. |

### 3.5 Multi-Tenancy & Authorization (5 Plugins)

| Plugin | Import Path | Capability Interface | Description |
| :--- | :--- | :--- | :--- |
| **`organizations`** | `.../plugins/organizations` | `organizations.Organization` | Multi-tenant organizations, teams, membership, and invitation lifecycles. |
| **`rbac`** | `.../plugins/rbac` | `rbac.RBAC` | Role-Based Access Control, role hierarchies, assignments, and cached evaluations. |
| **`policy`** | `.../plugins/policy` | `policy.Policy` | Attribute-Based Access Control (ABAC) and composable policy evaluation engine. |
| **`admin`** | `.../plugins/admin` | `admin.Admin` | Privileged operations: user bans, session revocation, and organization-scoped admin (`ForOrg`). |
| **`api-keys`** | `.../plugins/api-keys` | `apikeys.APIKeys` | API key lifecycle with SHA-256 hashing, scoped permissions, and rotation. |

### 3.6 Autonomous & Modern Identities (3 Plugins)

| Plugin | Import Path | Capability Interface | Description |
| :--- | :--- | :--- | :--- |
| **`agent`** | `.../plugins/agent` | `agent.AgentManager` | First-class identity, short-lived credentials, and scopes for autonomous AI agents and Model Context Protocol (MCP) clients. |
| **`device-authorization`** | `.../plugins/device-authorization` | `deviceauth.DeviceAuthorization` | OAuth 2.0 Device Authorization Grant (RFC 8628) for CLIs, smart TVs, and headless devices. |
| **`service-accounts`** | `.../plugins/service-accounts` | `serviceaccounts.ServiceAccounts` | Machine-to-machine (M2M) identity management with API keys and custom metadata. |

### 3.7 Monetization & Subscriptions (2 Plugins)

| Plugin | Import Path | Capability Interface | Description |
| :--- | :--- | :--- | :--- |
| **`stripe`** | `.../plugins/stripe` | `stripe.Stripe` | Stripe Checkout sessions, customer billing portal, subscription checks, and webhooks. |
| **`polar`** | `.../plugins/polar` | `polar.Polar` | Polar SaaS subscriptions, checkout, benefit and license key grants, and webhooks. |

### 3.8 Governance, Security & Observability (5 Plugins)

| Plugin | Import Path | Capability Interface | Description |
| :--- | :--- | :--- | :--- |
| **`audit`** | `.../plugins/audit` | `audit.Auditor` | Structured security audit trail subscribing to all authentication and session events. |
| **`rate-limit`** | `.../plugins/rate-limit` | `ratelimit.RateLimit` | Token bucket and sliding window rate limiting with distributed cache counters. |
| **`password-policy`** | `.../plugins/password-policy` | `passwordpolicy.Policy` | Advanced password complexity verification (character classes, breach checks). |
| **`lastlogin`** | `.../plugins/lastlogin` | `lastlogin.Tracker` | Automatic tracking of user sign-in activity and last known IP addresses. |
| **`openapi`** | `.../plugins/openapi` | `openapi.OpenAPIGenerator` | Dynamically generates OpenAPI 3.0 JSON specifications based on installed plugins. |

---

## 4. Registering and Composing Plugins

```go
package main

import (
    "database/sql"
    "log"

    _ "github.com/jackc/pgx/v5/stdlib"
    auth "github.com/BladiCreator/go-modular-auth"
    "github.com/BladiCreator/go-modular-auth/adapters/postgres"
    "github.com/BladiCreator/go-modular-auth/plugins/admin"
    "github.com/BladiCreator/go-modular-auth/plugins/organizations"
    "github.com/BladiCreator/go-modular-auth/plugins/twofactor"
)

func main() {
    db, err := sql.Open("pgx", "postgres://user:pass@localhost:5432/authdb?sslmode=disable")
    if err != nil {
        log.Fatalf("failed to connect to db: %v", err)
    }
    ad := postgres.New(db)

    // 1. Initialize plugin modules
    orgModule := organizations.New()
    twoFactorModule := twofactor.New()
    adminModule := admin.New()

    // 2. Initialize engine with topological resolution and schema-driven adapter
    engine, err := auth.New(auth.Config{
        Adapter: ad,
        Plugins: []auth.PluginModule{orgModule, twoFactorModule, adminModule},
    })
    if err != nil {
        log.Fatalf("failed to initialize auth engine: %v", err)
    }

    // 3. Resolve typed capabilities
    orgService := auth.MustGet[organizations.Organization](engine)
    adminService := auth.MustGet[admin.Admin](engine)

    _ = orgService
    _ = adminService
}
```
