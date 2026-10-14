# Architecture & Design Principles

## 1. Overview

**GoModularAuth** is a modular authentication engine for Go, strictly focused on server-side identity verification. Its primary design goal is to provide a small, stable, and hardened core that can be extended via plugins and adapters without devolving into a monolithic web framework.

```text
                                GoModularAuth Engine
                                         │
             ┌───────────────────────────┼───────────────────────────┐
             │                           │                           │
     Transport Adapters             Core Engine                 Plugin SDK &
             │                           │                       33 Plugins
      ┌──────┴──────┐             ┌──────┴──────┐                    │
      │             │             │             │             ┌──────┴──────┐
     HTTP          gRPC         Store         Cache          OAuth         2FA
 (Middleware,  (Interceptors,  (Truth)     (Ephemeral)     Passkeys       SCIM
  Extractors)   Metadata)         │             │          Organizations  Admin
                                  │             │           SAML / OIDC   Agents
                                  ▼             ▼              ...         ...
                           ┌──────────────┐ ┌──────────────┐
                           │ SQLite       │ │ Redis        │
                           │ PostgreSQL   │ │ Valkey       │
                           │ MySQL        │ │ Memory       │
                           │ Memory       │ └──────────────┘
                           └──────────────┘
```

---

## 2. Core Architectural Pillars

### 2.1 Server-Only & Transport-Agnostic
The core engine has **zero dependencies on transport layers** (`net/http`, `google.golang.org/grpc`, `gin`, `fiber`, `echo`).
It accepts standard domain inputs and returns domain outputs:

```go
auth.SignUp(ctx, input)
auth.SignIn(ctx, input)
auth.SignOut(ctx, input)
auth.GetSession(ctx, token)
auth.RequireSession(ctx, token)
```

Transport adapters handle translating transport-specific concerns (cookies, HTTP headers, query parameters, status codes, gRPC metadata) to and from the GoModularAuth core.

### 2.2 Function-First & Composition Over Magic
- Explicit interfaces with minimal method counts.
- Operations take `context.Context` as their first parameter for cancellation, deadlines, and tracing.
- Structured, typed sentinel errors (`errors.Is`) rather than string-matching errors.
- **No global state**: Instances of `*auth.Auth` are fully self-contained. Applications can instantiate multiple auth engines side-by-side (e.g., admin realm vs customer realm).

### 2.3 Authentication vs Authorization Separation
GoModularAuth strictly separates identity verification from permission management:

- **Authentication (*Who is this identity?*)**:
  Handled by the Core and Authentication Plugins: Sign Up, Sign In, Sign Out, Passwords, Accounts, Credentials, Sessions, Email Verification, Password Reset, Passkeys, OAuth, Magic Links.
- **Authorization (*What can this identity do?*)**:
  Separated via the `auth.Principal` boundary. Authorization domains (Roles, Permissions, Multi-Tenancy, Organizations, Teams, Resource Access) are handled by downstream plugins or host applications that consume the authenticated `Principal`.

```go
type Principal struct {
    Subject string
    Type    PrincipalType // "user", "service_account", "api_key", ...
}
```

---

## 3. Component Taxonomy: Adapters vs Plugins

The architecture maintains an unambiguous line between **Adapters** and **Plugins**:

| Concept | Role | Package Location | Built-in Implementations |
| :--- | :--- | :--- | :--- |
| **Store Adapter** | Authoritative source of truth for persistent state. | `adapters/` or custom | PostgreSQL, SQLite, MySQL, In-Memory |
| **Cache Adapter** | Ephemeral, non-authoritative acceleration layer. | `adapters/` or custom | Redis, Valkey, In-Memory |
| **Email Adapter** | Physical transmission of transactional notifications. | `adapters/` or custom | SMTP (TLS/STARTTLS/MIME), In-Memory Mock |
| **Transport Adapter** | Protocol boundary translating wire protocols into domain calls. | `adapters/` or custom | HTTP Middleware & Extractors, gRPC Interceptors |
| **Plugin Module** | Functional capabilities extending authentication or authorization. | `plugins/` | 33 plugins (OAuth, Passkeys, TOTP, Orgs, SCIM, Agents, etc.) |

> **Architectural Rule:**
> An **Adapter** provides an infrastructure implementation fulfilling a core interface contract (`store.Store`, `cache.Cache`, `email.Sender`).
> A **Plugin** contributes functional, domain-level capabilities to the system via the `plugin-sdk` and `auth.PluginModule`.

---

## 4. The Source of Truth: Store vs Cache

GoModularAuth enforces strict invariants regarding data persistence:

```text
                 ┌───────────────┐
                 │     Store     │
                 │ Source Truth  │
                 └───────┬───────┘
                         │
                    authoritative
                         │
                         ▼
                 ┌───────────────┐
                 │     Cache     │
                 │ derived/temp  │
                 └───────────────┘
```

1. **Store = Authoritative Source of Truth**:
   The store holds permanent, consistent records for users, accounts, credentials, sessions, and verification tokens. If a record is not in the store (or has been marked revoked in the store), it does not exist.
2. **Cache = Ephemeral Acceleration**:
   The cache reduces query latency and database load. A cache is **never** required for the system to operate. If the cache crashes or network connectivity is severed, GoModularAuth degrades automatically to querying the Store.
3. **Transactions belong exclusively to the Store**:
   Atomic business transactions are executed on the Store adapter. Cache updates or invalidations take place **after** the store transaction has successfully committed.

---

## 5. Cross-Module Transaction Propagation (`sqltx`)

When a core workflow (such as `SignUp` or `CreateSession`) executes, plugins may need to participate in the exact same database transaction:

- The store adapter implements `sqltx.Executor(ctx, db)` to attach active database transactions (`*sql.Tx`) to the `context.Context`.
- Both core sub-stores and SQL plugin stores call `sqltx.Executor(ctx, db)` to automatically join any outer transaction if present.
- If an operation fails inside a hook or sub-store, the entire transaction rolls back atomically across all participating tables.

---

## 6. Dependency Graph & Topological Initialization

Plugins can declare dependencies on other plugins by implementing `auth.Dependent`:

```go
type Dependent interface {
    Dependencies() []string
}
```

During engine creation (`auth.New(cfg)`):
1. The engine checks for duplicate module IDs.
2. It detects missing dependencies and returns `ErrPluginDependency`.
3. It performs cycle detection on the dependency graph.
4. It topologically sorts the plugins, guaranteeing that dependencies are initialized **before** the plugins that depend on them.
