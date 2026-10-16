# GoModularAuth OIDC Provider Plugin (`gomodularauth-oidc-provider`)

[![Go Reference](https://pkg.go.dev/badge/github.com/BladiCreator/go-modular-auth/plugins/oidc-provider.svg)](https://pkg.go.dev/github.com/BladiCreator/go-modular-auth/plugins/oidc-provider)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

The **OIDC Provider Plugin** (`gomodularauth-oidc-provider`) turns your [GoModularAuth](https://github.com/BladiCreator/go-modular-auth) application into an OpenID Connect (OIDC) Identity Provider (IdP). It issues cryptographically signed RS256 ID Tokens, serves discovery metadata (`/.well-known/openid-configuration`), publishes JSON Web Key Sets (`JWKS`), and resolves OpenID `UserInfo` endpoints.

---

## Table of Contents

- [Overview & Problem Solved](#overview--problem-solved)
- [Architecture & Design Principles](#architecture--design-principles)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration Options](#configuration-options)
- [Primary Capability API](#primary-capability-api)
- [Persistence & Unified Schema](#persistence--unified-schema)
- [Cache Semantics](#cache-semantics)
- [Observational Events](#observational-events)
- [Security Model & Invariants](#security-model--invariants)
- [Testing & Examples](#testing--examples)
- [License](#license)

---

## Overview & Problem Solved

While the consumer plugin (`gomodularauth-oidc`) allows GoModularAuth to log in users using external IdPs (like Google or Okta), many organizations need their own application to act as the authoritative identity provider:

- **Single Sign-On (SSO) for Internal Ecosystems**: Enable auxiliary apps, portals, microservices, and mobile apps to federate authentication through your primary platform.
- **Standards Compliance**: Complies with the OpenID Connect Core 1.0 specification for discovery, JWKS publication, and JWT ID token issuance.
- **Zero Schema Bloat**: Leverages Core's existing `user.User` store directly to populate standard identity claims (`sub`, `email`, `email_verified`).

---

## Architecture & Design Principles

```text
Client Application (Relying Party)
            │
            ├───────────────► Discovery: /.well-known/openid-configuration
            ├───────────────► Public Keys: /.well-known/jwks.json
            │
            ▼
auth.Get[oidcprovider.OIDCProvider](engine)
            │
            ▼
┌────────────────────────────────────────────────────────┐
│        gomodularauth-oidc-provider (Plugin)            │
│                                                        │
│  - RS256 Token Signing via Private RSA Key             │
│  - JWKS Construction from Public RSA Key               │
│  - Standard OIDC Discovery Document Builder            │
│  - UserInfo Claim Extraction                           │
└──────────────┬──────────────────────────┬──────────────┘
               │                          │
               ▼                          ▼
┌──────────────────────────────┐  ┌──────────────────────┐
│ Core Users Store             │  │ Core auth.Host       │
│ ctx.Store().Users()          │  │  - Context Clock     │
└──────────────────────────────┘  └──────────────────────┘
```

The plugin adheres strictly to GoModularAuth's architectural principles:
- **Core Decoupling**: Utilizes the standard Core user storage contract without requiring plugin-specific database tables.
- **Standard Cryptography**: Uses standard Go `crypto/rsa` and `crypto/sha256` PKCS1v15 signing to ensure broad compatibility with any OIDC client library.
- **Ephemeral Flexibility**: Automatically generates a 2048-bit RSA keypair in development if none is explicitly provided.

---

## Installation

```bash
go get github.com/BladiCreator/go-modular-auth/plugins/oidc-provider
```

---

## Quick Start

```go
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	adaptermem "github.com/BladiCreator/go-modular-auth/adapters/memory"
	oidcprovider "github.com/BladiCreator/go-modular-auth/plugins/oidc-provider"
	"github.com/BladiCreator/go-modular-auth/user"
)

func main() {
	ctx := context.Background()

	// 1. Generate or load RSA private key for token signing
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("failed to generate key: %v", err)
	}

	// 2. Initialize GoModularAuth with OIDC Provider plugin
	engine, err := auth.New(auth.Config{
		Adapter: adaptermem.NewAdapter(),
		Plugins: []auth.PluginModule{
			oidcprovider.New(
				oidcprovider.WithIssuer("https://auth.mycompany.com"),
				oidcprovider.WithPrivateKey(privKey, "key-2026-v1"),
				oidcprovider.WithDefaultTTL(1*time.Hour),
			),
		},
	})
	if err != nil {
		log.Fatalf("failed to initialize auth: %v", err)
	}

	// 3. Resolve OIDCProvider capability
	provider, err := auth.Get[oidcprovider.OIDCProvider](engine)
	if err != nil {
		log.Fatalf("failed to resolve OIDCProvider: %v", err)
	}

	// 4. Inspect Discovery Document & JWKS
	discovery := provider.GetDiscovery()
	fmt.Printf("Issuer: %s, JWKS URI: %s\n", discovery.Issuer, discovery.JWKSURI)

	jwks, err := provider.GetJWKS(ctx)
	if err != nil {
		log.Fatalf("failed to get JWKS: %v", err)
	}
	fmt.Printf("Published %d JWKS key(s)\n", len(jwks.Keys))

	// 5. Issue an RS256 ID Token for an authenticated user
	testUser := &user.User{
		ID:            "usr_alice",
		Email:         "alice@mycompany.com",
		EmailVerified: true,
	}

	idToken, err := provider.IssueIDToken(ctx, testUser, "client_app_123", "random_nonce_abc", 30*time.Minute)
	if err != nil {
		log.Fatalf("failed to issue ID token: %v", err)
	}
	fmt.Printf("Issued OIDC ID Token: %s\n", idToken)
}
```

---

## Configuration Options

Configure the plugin using functional options in `oidcprovider.New(opts ...Option)`:

```go
oidcprovider.New(
    oidcprovider.WithIssuer("https://auth.example.com"),
    oidcprovider.WithPrivateKey(rsaKey, "main-key-id"),
    oidcprovider.WithDefaultTTL(2 * time.Hour),
)
```

| Option | Default | Description |
| :--- | :--- | :--- |
| `WithIssuer(issuer string)` | `"http://localhost:8080"` | Sets the canonical OIDC issuer URL (`iss` claim). |
| `WithPrivateKey(pk *rsa.PrivateKey, kid string)` | Generated 2048-bit RSA key (`"default-key"`) | Configures the RSA private key and key identifier used for RS256 token signing. |
| `WithDefaultTTL(ttl time.Duration)` | `1 * time.Hour` | Sets the default expiration lifetime for issued ID tokens when not overridden per call. |

---

## Primary Capability API

The primary capability is exposed through `oidcprovider.OIDCProvider`, resolved via `auth.Get[oidcprovider.OIDCProvider](engine)`.

### Interface Definition

```go
package oidcprovider

import (
	"context"
	"time"

	"github.com/BladiCreator/go-modular-auth/plugins/oidc-provider/discovery"
	"github.com/BladiCreator/go-modular-auth/plugins/oidc-provider/jwks"
	"github.com/BladiCreator/go-modular-auth/user"
)

type OIDCProvider interface {
	// GetDiscovery returns the OpenID Connect discovery metadata document.
	GetDiscovery() *discovery.Document

	// GetJWKS returns the JSON Web Key Set containing public keys for token verification.
	GetJWKS(ctx context.Context) (*jwks.JWKS, error)

	// IssueIDToken signs and returns an RS256 JWT ID token for the specified user and client.
	IssueIDToken(ctx context.Context, u *user.User, clientID, nonce string, ttl time.Duration) (string, error)

	// GetUserInfo retrieves claims for the OpenID UserInfo endpoint.
	GetUserInfo(ctx context.Context, userID string) (map[string]any, error)
}
```

### Sentinel Errors

| Error | Description |
| :--- | :--- |
| `ErrUserNotFound` | The requested user could not be found in the Core user store. |
| `ErrInvalidUser` | Provided `user.User` reference is nil or has an empty ID. |
| `ErrSigningFailed` | RSA PKCS1v15 signing operation failed. |
| `ErrKeyUnavailable` | Private key is not configured or unavailable. |

---

## Persistence & Unified Schema

- **No Plugin Tables Required**: `gomodularauth-oidc-provider` does not define or require dedicated database tables.
- **Core User Store Integration**: `GetUserInfo` queries the Core user repository directly via `s.ctx.Store().Users().GetByID(ctx, userID)`.

---

## Cache Semantics

- **Discovery Document**: Static in-memory representation constructed during initialization. Can be served with HTTP caching headers (`Cache-Control: public, max-age=86400`).
- **JWKS Endpoint**: Derives directly from the in-memory public key; HTTP responses should be cached aggressively by downstream relying parties.

---

## Observational Events

- Token issuance can be logged through custom audit logging middleware or integrated event listeners.
- Failed signature operations and missing user lookups emit standard Go errors that can be captured by application instrumentation.

---

## Security Model & Invariants

1. **RS256 Digital Signatures**: All ID tokens are signed using RSA PKCS1v15 with SHA-256. Symmetric HMAC keys are disallowed for ID token signing to prevent token forgery by clients.
2. **Claim Standards Compliance**: Every issued ID token contains:
   - `iss`: Configured canonical issuer URL.
   - `sub`: Unique user ID.
   - `aud`: Authorized Client ID (audience).
   - `exp` & `iat`: Expiration and issuance UNIX timestamps.
   - `nonce`: Client-supplied replay-mitigation nonce (when provided).
   - `email` & `email_verified`: User email identity claims.
3. **Private Key Protection**: Private keys are held strictly in memory and are never exposed via public endpoints. Only the corresponding public key is exposed through `GetJWKS`.

---

## Testing & Examples

Unit testing token issuance using ephemeral in-memory keys:

```go
func TestOIDCProviderTokenIssuance(t *testing.T) {
	ctx := context.Background()
	engine, _ := auth.New(auth.Config{
		Adapter: adaptermem.NewAdapter(),
		Plugins: []auth.PluginModule{oidcprovider.New()},
	})

	provider, _ := auth.Get[oidcprovider.OIDCProvider](engine)

	u := &user.User{ID: "usr_test", Email: "test@example.com"}
	token, err := provider.IssueIDToken(ctx, u, "client_test", "nonce_123", time.Hour)
	if err != nil || token == "" {
		t.Fatalf("failed to issue token: %v", err)
	}

	jwksDoc, err := provider.GetJWKS(ctx)
	if err != nil || len(jwksDoc.Keys) == 0 {
		t.Fatalf("failed to retrieve jwks: %v", err)
	}
}
```

---

## License

MIT License. See [LICENSE](file:///media/vladimir/Storage/Projects/Go/go-modular-auth/LICENSE) for details.
