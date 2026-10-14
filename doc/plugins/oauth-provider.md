# gomodularauth-oauth-provider

`gomodularauth-oauth-provider` is a pure Go modular library plugin that implements an **OAuth 2.1 Authorization Server** for [GoModularAuth](https://github.com/BladiCreator/go-modular-auth). It enables GoModularAuth instances to act as Identity Providers (IdP) for first-party single-page apps (SPAs), mobile applications, and third-party API clients.

## Key Features

- **OAuth 2.1 Compliant**:
  - Authorization Code Grant with mandatory **PKCE (RFC 7636)** for public clients (S256 enforcement).
  - Client Credentials Grant for machine-to-machine (M2M) communication.
  - Refresh Token Grant with automatic **Refresh Token Rotation**.
  - Token Revocation per **RFC 7009**.
  - Token Introspection per **RFC 7662**.
- **Transport Independence**: No hardcoded HTTP/gRPC handlers; pure domain operations that plug seamlessly into any web framework (Gin, Echo, Fiber, Chi, Standard Library).
- **Security-First Persistence**:
  - Client secrets stored with salted SHA-256 hashes (`$s256$<salt>$<digest>`). Plaintext secrets are never stored.
  - Tokens and authorization codes stored as SHA-256 hashes.
  - Exact redirect URI matching enforced (no wildcard or path traversal risks).
  - Single-use, atomic authorization code consumption (anti-replay guarantee).
- **Core Integration**: Seamless integration with GoModularAuth Core `User`, `Principal`, events, and typed capability lookup.

---

## Architecture

```text
                  Application HTTP / gRPC Transport
                                  │
                                  ▼
                        GoModularAuth Engine
                                  │
                                  ▼
                    gomodularauth-oauth-provider
                                  │
                 ┌────────────────┴────────────────┐
                 ▼                                 ▼
      oauthprovider.Store                sdk.EventDispatcher
     (Memory / PostgreSQL)             (Core Event Pipeline)
```

---

## Installation

```bash
go get github.com/BladiCreator/go-modular-auth/plugins/oauth-provider
```

---

## Quick Start

### 1. Register the Plugin with GoModularAuth

```go
package main

import (
	"log"

	auth "github.com/BladiCreator/go-modular-auth"
	corestore "github.com/BladiCreator/go-modular-auth/store/memory"
	oauthprovider "github.com/BladiCreator/go-modular-auth/plugins/oauth-provider"
	"github.com/BladiCreator/go-modular-auth/plugins/oauth-provider/plugins"
	oauthmemory "github.com/BladiCreator/go-modular-auth/plugins/oauth-provider/store/memory"
)

func main() {
	// Initialize OAuth Provider plugin module
	oauthMod := oauthprovider.New(
		oauthprovider.WithStore(oauthmemory.New()), // or postgres.New(db)
		oauthprovider.WithIssuer("https://auth.example.com"),
		oauthprovider.WithRequirePKCE(true),
		oauthprovider.WithRotateRefreshTokens(true),
	)

	// Initialize GoModularAuth Engine
	engine, err := auth.New(auth.Config{
		Store:   corestore.New(),
		Plugins: []auth.PluginModule{oauthMod},
	})
	if err != nil {
		log.Fatalf("failed to initialize auth engine: %v", err)
	}

	// Retrieve strongly-typed capability
	provider, err := auth.Get[plugins.OAuthProvider](engine)
	if err != nil {
		log.Fatalf("failed to resolve OAuthProvider capability: %v", err)
	}

	_ = provider
}
```

---

## Core Operations

### 1. Registering a Client

```go
// Register a Public Client (SPA / Mobile)
pubClient, err := provider.RegisterClient(ctx, oauthprovider.RegisterClientInput{
	Name:              "React SPA",
	ClientType:        oauthprovider.ClientTypePublic,
	RedirectURIs:      []string{"https://app.example.com/oauth/callback"},
	AllowedGrantTypes: []string{oauthprovider.GrantTypeAuthorizationCode},
	AllowedScopes:     []string{"openid", "profile", "read:data"},
})

// Register a Confidential Client (Backend / Microservice)
confClient, err := provider.RegisterClient(ctx, oauthprovider.RegisterClientInput{
	Name:              "Billing Microservice",
	ClientType:        oauthprovider.ClientTypeConfidential,
	RedirectURIs:      []string{"https://billing.internal/callback"},
	AllowedGrantTypes: []string{oauthprovider.GrantTypeClientCredentials},
	AllowedScopes:     []string{"invoices:create", "invoices:read"},
})
// confClient.ClientSecret contains the raw secret returned ONLY once upon registration.
```

### 2. Authorization Request (`/authorize`)

```go
authRes, err := provider.Authorize(ctx, oauthprovider.AuthorizeInput{
	ClientID:            pubClient.Client.ID,
	UserID:              "user_uuid_1234",
	RedirectURI:         "https://app.example.com/oauth/callback",
	ResponseType:        "code",
	Scopes:              []string{"openid", "profile"},
	State:               "random_anti_csrf_state",
	CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
	CodeChallengeMethod: "S256",
	UserConsent:         true,
})
if err != nil {
	// Handle errors: ErrPKCERequired, ErrRedirectURIMismatch, ErrConsentRequired, etc.
}

// Redirect user to authRes.RedirectURI with code=authRes.Code & state=authRes.State
```

### 3. Token Exchange (`/token`)

#### Authorization Code Grant with PKCE
```go
tokens, err := provider.Token(ctx, oauthprovider.TokenInput{
	GrantType:    oauthprovider.GrantTypeAuthorizationCode,
	ClientID:     pubClient.Client.ID,
	Code:         authRes.Code,
	RedirectURI:  "https://app.example.com/oauth/callback",
	CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
})
// tokens.AccessToken, tokens.RefreshToken, tokens.ExpiresIn, tokens.TokenType ("Bearer")
```

#### Client Credentials Grant
```go
m2mTokens, err := provider.Token(ctx, oauthprovider.TokenInput{
	GrantType:    oauthprovider.GrantTypeClientCredentials,
	ClientID:     confClient.Client.ID,
	ClientSecret: rawSecret,
	Scopes:       []string{"invoices:read"},
})
```

#### Refresh Token Grant (with Rotation)
```go
rotatedTokens, err := provider.Token(ctx, oauthprovider.TokenInput{
	GrantType:    oauthprovider.GrantTypeRefreshToken,
	ClientID:     pubClient.Client.ID,
	RefreshToken: tokens.RefreshToken,
})
// Old refresh token is revoked automatically; new refresh token is issued.
```

### 4. Token Introspection (RFC 7662)

```go
intro, err := provider.IntrospectToken(ctx, oauthprovider.IntrospectTokenInput{
	Token:    tokens.AccessToken,
	ClientID: pubClient.Client.ID,
})
if intro.Active {
	// Token is valid and unrevoked
	log.Printf("Subject: %s, Scopes: %v, Expires: %d", intro.Sub, intro.Scopes, intro.Exp)
}
```

### 5. Token Revocation (RFC 7009)

```go
err := provider.RevokeToken(ctx, oauthprovider.RevokeTokenInput{
	Token:    tokens.AccessToken,
	ClientID: pubClient.Client.ID,
})
```

---

## Configuration Options

| Option | Default | Description |
|---|---|---|
| `WithStore(s store.Store)` | `memory.New()` | Persistence adapter (`memory` or `postgres`). |
| `WithIssuer(url string)` | `""` | Canonical authorization server identifier URL. |
| `WithAuthorizationCodeTTL(d)` | `5m` | Lifetime of issued authorization codes. |
| `WithAccessTokenTTL(d)` | `1h` | Lifetime of issued bearer access tokens. |
| `WithRefreshTokenTTL(d)` | `30d` | Lifetime of issued refresh tokens. |
| `WithRequirePKCE(b bool)` | `true` | Enforces PKCE with S256 for public clients. |
| `WithRotateRefreshTokens(b)` | `true` | Rotates refresh tokens on each refresh exchange. |

---

## Security Model

1. **PKCE S256 Enforcement**: OAuth 2.1 strictly rejects the legacy `plain` challenge method and enforces S256 for public clients to prevent code interception attacks.
2. **Exact Redirect URI Matching**: Full string matching is enforced without wildcard expansions or query string deviations.
3. **No Plaintext Secrets**: Client secrets use salted SHA-256 (`$s256$<salt>$<digest>`) with `crypto/subtle.ConstantTimeCompare`. Tokens and codes are SHA-256 hashed before storage.
4. **Single-Use Authorization Codes**: Atomic database consumption ensures that concurrent redemption attacks cannot succeed.
5. **Transport Independence**: Isolates protocol business rules from transport frameworks, preventing transport layer vulnerabilities.

---

## Testing

Run unit, integration, and security tests:

```bash
go test -v -race ./...
```
