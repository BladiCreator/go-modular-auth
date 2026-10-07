# GoModularAuth Documentation

Welcome to the comprehensive documentation for **GoModularAuth**, a server-only, transport-agnostic, modular authentication engine for Go.

---

## Documentation Index

1. [**Architecture & Principles**](architecture.md)
   - Core philosophy: transport-agnostic, server-only, function-first.
   - Authentication vs Authorization separation.
   - Component taxonomy: Core vs Adapters vs Plugins.
   - Authoritative Store vs Ephemeral Cache.

2. [**Core Engine & Operations**](core.md)
   - Core entities: `User`, `Account`, `Credential`, `Session`, `VerificationToken`, `Principal`.
   - Operations: `SignUp`, `SignIn`, `SignOut`, `GetSession`, `RequireSession`, `GetUser`, `RequireUser`.
   - Account recovery & verification: `VerifyEmail`, `ChangePassword`, `ResetPassword`.
   - Password hashing with Argon2id (OWASP defaults).
   - Configuration & secure zero-value defaults.

3. [**Store Adapter (Persistence)**](store-adapter.md)
   - Store as the authoritative source of truth.
   - Sub-store contracts: `UserStore`, `AccountStore`, `CredentialStore`, `SessionStore`, `TokenStore`.
   - Transaction semantics & atomic multi-entity mutations.
   - In-memory reference implementation (`store/memory`).
   - Guide: How to implement a database adapter (PostgreSQL, SQLite, MySQL).

4. [**Cache Adapter (Performance & Ephemeral State)**](cache-adapter.md)
   - Ephemeral cache vs Authoritative persistence.
   - Cache-Aside / Read-Through patterns.
   - Semantic caches: `SessionCache` and `UserCache`.
   - Key namespacing and secret hashing.
   - TTL boundaries (bounding cache TTL to entity expiry).
   - Atomic counters (`cache.Counter`) for distributed rate limiting.
   - Fault tolerance: graceful degradation to Store on cache outage.

5. [**Email Adapter (Transactional Messaging)**](email-adapter.md)
   - Decoupling message generation from physical delivery.
   - `email.Sender` contract and transactional email templates.
   - In-memory mock sender for unit and integration testing.

6. [**Plugin System**](plugins.md)
   - Distinction between `PluginModule` (installer) and `PluginCapability` (interface).
   - Strongly typed capability resolution via `auth.Get[T]()`.
   - Dependency validation and topological initialization order.
   - Synchronous transactional `Hooks` vs Post-commit `Events`.

7. [**Transport Adapters (HTTP, gRPC, CLI)**](transport.md)
   - Why GoModularAuth never imports `net/http` or web frameworks directly.
   - Bridging incoming HTTP requests (cookies, headers, Bearer tokens).
   - Injecting and consuming `Principal` from `context.Context`.
   - Examples for standard `net/http`, Gin, and Fiber.
