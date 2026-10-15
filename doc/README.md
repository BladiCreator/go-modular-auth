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
             │                          │                     (35 Plugins)
      ┌──────┴──────┐            ┌──────┴──────┐                   │
      │             │            │             │            ┌──────┴──────┐
     HTTP          gRPC       Adapter        Cache         OAuth         2FA
 (Middleware,  (Interceptors,  (Truth)     (Ephemeral)    Passkeys       SCIM
  Extractors)   Metadata)        │             │         Organizations  Admin
                                 │             │          SAML / OIDC   Agents
                                 ▼             ▼             Billing     ...
                           SQLite/Postgres/  Redis/
                            MySQL/SurrealDB/ Valkey/
                                Memory       Memory
```

---

## Documentation Index

1. [**Architecture & Principles**](architecture.md)
   - Core philosophy: server-only, transport-agnostic, function-first.
   - Authentication (who) vs Authorization (what) separation.
   - Component taxonomy: Core vs Adapters vs Plugin SDK vs Plugins.
   - Authoritative Database Adapter vs Ephemeral Cache invariants.
   - Cross-module transaction propagation via `sqltx`.

2. [**Core Engine & Domain Operations**](core.md)
   - Core domain entities: `User`, `Account`, `Credential`, `Session`, `VerificationToken`, `Principal`.
   - Engine operations: `SignUp`, `SignIn`, `SignOut`, `GetSession`, `RequireSession`, `CreateSession`.
   - Credential management & verification: `ChangePassword`, `RequestPasswordReset`, `ResetPassword`, `VerifyEmail`.
   - Single-use token engine: `IssueToken`, `ConsumeToken`, `PurgeExpired`.
   - Password hashing with Argon2id (OWASP recommended parameters).
   - Zero-allocation semantic caching and configuration defaults.

3. [**Database Adapters (Persistence & Schema)**](store-adapter.md)
   - The Database Adapter (`adapter.Adapter`) as the authoritative source of truth.
   - Schema-driven DDL and dynamic compilation via `schema.Schema`.
   - Model repositories via `sdk.Model[T]`.
   - Atomic database transactions and error normalization (`adapter.ErrNotFound`, `adapter.ErrConflict`).
   - Production database adapters:
     - **PostgreSQL Adapter** (`adapters/postgres`)
     - **SQLite Adapter** (`adapters/sqlite`)
     - **MySQL Adapter** (`adapters/mysql`)
     - **SurrealDB Adapter** (`adapters/surrealdb`)
     - **In-Memory Adapter** (`adapters/memory`)
   - Internal core bridging via `core/adapter/bridge` to `store.Store`.

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

6. [**Official Adapters Directory**](adapters/README.md)
   - Detailed usage guides for all 10 adapters:
     - Transport: [HTTP](adapters/http.md), [gRPC](adapters/grpc.md)
     - Persistence: [PostgreSQL](adapters/postgres.md), [SQLite](adapters/sqlite.md), [MySQL](adapters/mysql.md), [SurrealDB](adapters/surrealdb.md), [In-Memory](adapters/memory.md)
     - Caching: [Redis](adapters/redis.md), [Valkey](adapters/valkey.md), [In-Memory Cache](adapters/memory.md)
     - Messaging: [SMTP](adapters/smtp.md), [In-Memory Mock](adapters/memory.md)

7. [**Official Plugins Directory**](plugins/README.md)
   - Comprehensive implementation and usage guides for all 35 plugins:
     - [Authentication Factors & Passwordless](plugins/README.md#1-authentication-factors--passwordless) (Passkeys, 2FA, Magic Link, Email OTP, Phone, etc.)
     - [Token Protocols & Sessions](plugins/README.md#2-tokens--session-management) (JWT, Bearer, Multi-session, One-Time Token)
     - [SSO & Client Protocols](plugins/README.md#3-single-sign-on-sso--client-protocols) (OAuth, OIDC, SAML, Unified SSO)
     - [Identity Provider Servers](plugins/README.md#4-identity-provider-idp-servers) (OAuth 2.1 Provider, OIDC IdP, SAML IdP, SCIM 2.0)
     - [Multi-Tenancy & Organizations](plugins/README.md#5-multi-tenancy--organizations) (Organizations)
     - [Authorization & Access Control](plugins/README.md#6-authorization--access-control) (RBAC, Policy/ABAC, API Keys, Admin)
     - [Autonomous Identities & Agents](plugins/README.md#7-autonomous-identities--modern-clients) (AI Agents / MCP, Device Flow RFC 8628, Service Accounts)
     - [Monetization & Subscriptions](plugins/README.md#9-monetization--subscriptions) (Stripe, Polar)
     - [Governance & Security](plugins/README.md#8-governance-security--observability) (Audit Logging, Rate Limiting, Password Policy, OpenAPI, Last Login)- [Autonomous Identities & Agents](plugins/agents.md) (AI Agents / MCP, Device Flow RFC 8628, Service Accounts)
     - [Governance & Security](plugins/governance.md) (Audit Logging, Rate Limiting, Password Policy, OpenAPI, Last Login)

