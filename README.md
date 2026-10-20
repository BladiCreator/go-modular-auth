<p align="center">
  <img src="assets/logo.png" alt="Go Modular Auth Logo" width="200" />
</p>

<h1 align="center">Go Modular Auth</h1>

<p align="center">
  <strong>Server-only, transport-agnostic, modular authentication engine for Go.</strong>
</p>

<p align="center">
  <a href="https://pkg.go.dev/github.com/BladiCreator/go-modular-auth"><img src="https://pkg.go.dev/badge/github.com/BladiCreator/go-modular-auth.svg" alt="Go Reference"></a>
  <a href="https://github.com/BladiCreator/go-modular-auth/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>
  <a href="https://golang.org/"><img src="https://img.shields.io/badge/Go-1.27+-00ADD8?logo=go" alt="Go Version"></a>
</p>

---

## 1. Objective & Principles

**GoModularAuth** is a modular, server-only authentication engine for Go. It is built from the ground up on Clean & Hexagonal Architecture to separate domain authentication workflows from infrastructure and web frameworks.

- **Server-Only & Domain-First**: Pure domain operations. Zero global state.
- **Transport-Agnostic**: The core engine **never** imports `net/http`, `grpc`, `fiber`, or `gin`. Transport adapters bridge HTTP requests or gRPC RPCs to core operations.
- **Adapter = Source of Truth**: All identities, credentials, accounts, and sessions live in the authoritative schema-driven Database Adapter.
- **Cache = Ephemeral Acceleration**: Optional Cache-Aside acceleration with bounded TTLs, post-commit invalidation, and graceful degradation to the Store on cache outage.
- **ACID Cross-Module Transactions**: Transactions propagate seamlessly between Core and Plugins via package `sqltx`.
- **Topological Plugin Graph**: Plugins declare dependencies; the engine sorts them topologically and prevents dependency cycles.
- **Enterprise & Modern Auth Ready**: 35 official plugins covering WebAuthn Passkeys, TOTP (AAL1/AAL2), OAuth 2.1 Provider, SCIM 2.0, SAML/OIDC SSO, Multi-Tenancy Organizations, Monetization (Stripe/Polar), and AI Agent identities.

> 📚 **Comprehensive Documentation**: Complete in-depth guides and API references are available in the [**`doc/`**](doc/README.md) directory.

---

## 2. Architecture

```text
                                GoModularAuth Engine
                                         │
             ┌───────────────────────────┼───────────────────────────┐
             │                           │                           │
      Transport Adapters             Core Engine                 Plugin SDK &
             │                           │                       35 Plugins
      ┌──────┴──────┐             ┌──────┴──────┐                    │
      │             │             │             │             ┌──────┴──────┐
     HTTP          gRPC        Adapter        Cache          OAuth         2FA
 (Middleware,  (Interceptors,  (Truth)     (Ephemeral)     Passkeys       SCIM
  Extractors)   Metadata)         │             │          Organizations  Admin
                                  │             │           SAML / OIDC   Agents
                                  ▼             ▼             Billing      ...
                           ┌──────────────┐ ┌──────────────┐
                           │ SQLite       │ │ Redis        │
                           │ PostgreSQL   │ │ Valkey       │
                           │ MySQL        │ │ Memory       │
                           │ SurrealDB    │ └──────────────┘
                           │ Memory       │
                           └──────────────┘
```

---

## 3. Adapters & Plugins Ecosystem

### Production Adapters (`adapters/`)
- **Persistence Stores**:
  - `adapters/postgres`: Production PostgreSQL store with automatic migrations and connection pooling.
  - `adapters/sqlite`: Production SQLite store (WAL mode, busy timeout support).
  - `adapters/mysql`: Production MySQL store.
  - `adapters/surrealdb`: Production SurrealDB multi-model database adapter with dynamic schema generation.
  - `adapters/memory`: In-memory thread-safe store for unit and integration testing.
- **Caching & Ephemeral State**:
  - `adapters/redis`: Distributed cache and atomic counter for rate limiting.
  - `adapters/valkey`: High-performance Valkey cache adapter.
  - `adapters/memory`: In-memory cache with TTL eviction.
- **Transactional Delivery**:
  - `adapters/smtp`: Production SMTP sender supporting TLS, STARTTLS, and multipart/alternative MIME.
  - `adapters/memory`: In-memory mock sender for testing.
- **Transports**:
  - `adapters/http`: HTTP middleware (`Authenticate`, `RequireSession`) and extractors (`BearerExtractor`, `CookieExtractor`).
  - `adapters/grpc`: Unary and streaming gRPC server interceptors with metadata token extractors.

### 35 Official Plugins (`plugins/`)
- **Authentication**: `passkeys` (WebAuthn/FIDO2), `twofactor` (TOTP RFC 6238 + AAL1/AAL2), `magic-link`, `email-otp`, `phone` (SMS OTP), `account-linking`, `username`, `anonymous`.
- **Tokens & Sessions**: `jwt`, `bearer`, `multisession`, `one-time-token`.
- **SSO & Client Protocols**: `oauth` (Google, GitHub, etc.), `oidc`, `saml`, `sso`.
- **Identity Provider (IdP) Servers**: `oauth-provider` (OAuth 2.1 Server with PKCE S256), `oidc-provider`, `saml-provider`, `scim` (SCIM 2.0 Provisioning).
- **Multi-Tenancy & Authorization**: `organizations`, `rbac`, `policy` (ABAC engine), `admin`, `api-keys`.
- **Autonomous Identities**: `agent` (Autonomous AI agents & MCP client credentials), `device-authorization` (RFC 8628), `service-accounts`.
- **Monetization & Subscriptions**: `stripe` (Stripe billing & customer portal), `polar` (Polar SaaS & benefit licensing).
- **Security & Governance**: `audit`, `rate-limit`, `password-policy`, `lastlogin`, `openapi` (Spec generator).

---

## 4. Installation

```bash
go get github.com/BladiCreator/go-modular-auth
```

Requires **Go 1.27+**.

---

## 5. Quickstart

### Production Setup with PostgreSQL, HTTP Middleware & Organizations Plugin

```go
package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/http"

	_ "github.com/jackc/pgx/v5/stdlib"

	auth "github.com/BladiCreator/go-modular-auth"
	authhttp "github.com/BladiCreator/go-modular-auth/adapters/http"
	"github.com/BladiCreator/go-modular-auth/adapters/postgres"
	"github.com/BladiCreator/go-modular-auth/plugins/organizations"
)

func main() {
	ctx := context.Background()

	// 1. Initialize PostgreSQL database and storage adapter
	db, err := sql.Open("pgx", "postgres://user:pass@localhost:5432/authdb?sslmode=disable")
	if err != nil {
		log.Fatal(err)
	}
	ad := postgres.New(db)

	// 2. Initialize Organizations plugin
	orgModule := organizations.New()

	// 3. Initialize GoModularAuth Engine with schema-driven adapter
	engine, err := auth.New(auth.Config{
		Adapter: ad,
		Plugins: []auth.PluginModule{orgModule},
	})
	if err != nil {
		log.Fatalf("failed to initialize auth engine: %v", err)
	}

	// 4. Resolve strongly-typed plugin capability
	orgService := auth.MustGet[organizations.Organization](engine)
	_ = orgService

	// 5. Setup HTTP router with authentication middleware
	mux := http.NewServeMux()

	// Public Sign-Up Endpoint
	mux.HandleFunc("POST /api/signup", func(w http.ResponseWriter, r *http.Request) {
		res, err := engine.SignUp(r.Context(), auth.SignUpInput{
			Email:    "alice@example.com",
			Password: "SuperSecretPassword123!",
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		fmt.Fprintf(w, "User created: %s, Session Token: %s\n", res.User.ID, res.Token)
	})

	// Protected Endpoint guarded by RequireSession
	protectedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, _ := authhttp.PrincipalFrom(r.Context())
		fmt.Fprintf(w, "Authenticated Principal: %s\n", principal.Subject)
	})

	mux.Handle("GET /api/me", authhttp.RequireSession(engine,
		authhttp.WithExtractor(authhttp.BearerExtractor),
		authhttp.WithExtractor(authhttp.CookieExtractor("session_token")),
	)(protectedHandler))

	log.Println("Server listening on :8080...")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
```

## 6. Documentation Index

- [Architecture & Design Principles](doc/architecture.md)
- [Core Engine & Domain Operations](doc/core.md)
- [Store Adapters (Persistence)](doc/store-adapter.md)
- [Cache Adapters (Performance & Ephemeral State)](doc/cache-adapter.md)
- [Email Adapters (Transactional Messaging)](doc/email-adapter.md)
- [Transport Adapters (HTTP & gRPC)](doc/transport.md)
- [Official Adapters Directory (10 Adapters)](doc/adapters/README.md)
- [Official Plugins Directory (35 Plugins)](doc/plugins/README.md)

---

## 7. License

MIT License. See [LICENSE](LICENSE) for details.
