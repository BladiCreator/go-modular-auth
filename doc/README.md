# GoModularAuth Documentation

Welcome to the comprehensive documentation for **GoModularAuth**, a server-only, transport-agnostic, modular authentication engine for Go.

---

## Architecture Overview

GoModularAuth separates identity verification and authentication workflows from infrastructure, web transport, and business authorization logic.

```text
                               GoModularAuth Engine
                                        │
             ┌──────────────────────────┼──────────────────────────┐
             │                          │                          │
     Transport Adapters               Core                   Plugin System
             │                          │                     (33 Plugins)
      ┌──────┴──────┐            ┌──────┴──────┐                   │
      │             │            │             │            ┌──────┴──────┐
     HTTP          gRPC        Store         Cache         OAuth         2FA
 (Middleware,  (Interceptors,  (Truth)     (Ephemeral)    Passkeys       SCIM
  Extractors)   Metadata)        │             │         Organizations  Admin
                                 │             │          SAML / OIDC   Agents
                                 ▼             ▼             ...         ...
                           SQLite/Postgres/  Redis/
                            MySQL/Memory     Valkey/
                                             Memory
```

---

## Documentation Index

1. [**Architecture & Principles**](architecture.md)
   - Core philosophy: server-only, transport-agnostic, function-first.
   - Authentication (who) vs Authorization (what) separation.
   - Component taxonomy: Core vs Adapters vs Plugin SDK vs Plugins.
   - Authoritative Store vs Ephemeral Cache invariants.
   - Cross-module transaction propagation via `sqltx`.

2. [**Core Engine & Domain Operations**](core.md)
   - Core domain entities: `User`, `Account`, `Credential`, `Session`, `VerificationToken`, `Principal`.
   - Engine operations: `SignUp`, `SignIn`, `SignOut`, `GetSession`, `RequireSession`, `CreateSession`.
   - Credential management & verification: `ChangePassword`, `RequestPasswordReset`, `ResetPassword`, `VerifyEmail`.
   - Single-use token engine: `IssueToken`, `ConsumeToken`, `PurgeExpired`.
   - Password hashing with Argon2id (OWASP recommended parameters).
   - Zero-allocation semantic caching and configuration defaults.

3. [**Store Adapters (Persistence)**](store-adapter.md)
   - The Store as the authoritative source of truth.
   - Sub-store contracts: `UserStore`, `AccountStore`, `CredentialStore`, `SessionStore`, `TokenStore`.
   - Atomic database transactions and error normalization (`store.ErrNotFound`, `store.ErrConflict`).
   - Production SQL adapters:
     - **PostgreSQL Adapter** (`adapters/postgres`)
     - **SQLite Adapter** (`adapters/sqlite`)
     - **MySQL Adapter** (`adapters/mysql`)
     - **In-Memory Store** (`adapters/memory`)
   - Cross-plugin transaction sharing via `sqltx.Executor`.

4. [**Cache Adapters (Performance & Ephemeral State)**](cache-adapter.md)
   - Ephemeral Cache vs Authoritative Persistence.
   - Cache-Aside and Read-Through patterns with post-commit invalidation.
   - Semantic caches: `SessionCache` and `UserCache`.
   - Distributed atomic counters (`cache.Counter`) for rate limiting.
   - Production cache adapters:
     - **Redis Adapter** (`adapters/redis`)
     - **Valkey Adapter** (`adapters/valkey`)
     - **In-Memory Cache** (`adapters/memory`)
   - Fault tolerance and graceful degradation on cache downtime.

5. [**Email Adapters (Transactional Delivery)**](email-adapter.md)
   - Decoupling notification generation from physical message delivery.
   - `email.Sender` and `email.SenderFunc` interfaces.
   - Production **SMTP Adapter** (`adapters/smtp`): TLS, STARTTLS, authentication, and multipart MIME.
   - In-memory mock sender for unit and integration testing.

8. [**Official Adapters Directory**](adapters/README.md)
   - Detailed usage guides for all 9 adapters:
     - Transport: [HTTP](adapters/http.md), [gRPC](adapters/grpc.md)
     - Persistence: [PostgreSQL](adapters/postgres.md), [SQLite](adapters/sqlite.md), [MySQL](adapters/mysql.md), [In-Memory Store](adapters/memory.md)
     - Caching: [Redis](adapters/redis.md), [Valkey](adapters/valkey.md), [In-Memory Cache](adapters/memory.md)
     - Messaging: [SMTP](adapters/smtp.md), [In-Memory Mock](adapters/memory.md)

9. [**Official Plugins Directory**](plugins/README.md)
   - Comprehensive implementation and usage guides for all 33 plugins:
     - [Authentication Factors & Passwordless](plugins/auth-factors.md) (Passkeys, 2FA, Magic Link, Email OTP, Phone, etc.)
     - [Token Protocols & Sessions](plugins/tokens-sessions.md) (JWT, Bearer, Multi-session, One-Time Token)
     - [SSO & Client Protocols](plugins/sso.md) (OAuth, OIDC, SAML, Unified SSO)
     - [Identity Provider Servers](plugins/identity-providers.md) (OAuth 2.1 Provider, OIDC IdP, SAML IdP, SCIM 2.0)
     - [Multi-Tenancy & Organizations](plugins/organizations.md) (Organizations, Teams, Invitations)
     - [Authorization & Access Control](plugins/authorization.md) (RBAC, Policy/ABAC, API Keys, Admin)
     - [Autonomous Identities & Agents](plugins/agents.md) (AI Agents / MCP, Device Flow RFC 8628, Service Accounts)
     - [Governance & Security](plugins/governance.md) (Audit Logging, Rate Limiting, Password Policy, OpenAPI, Last Login)

