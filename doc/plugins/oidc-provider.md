# OpenID Connect (OIDC) Provider Plugin

The **OIDC Provider Plugin** (`plugins/oidc-provider`) turns your GoModularAuth application into a compliant **OpenID Connect 1.0 Identity Provider (IdP)**. It issues signed ID tokens (`id_token`), serves dynamic JSON Web Key Sets (JWKS), provides standardized UserInfo claims, and hosts the discovery document (`.well-known/openid-configuration`).

---

## 1. Problem Solved

When building an identity hub for mobile apps, SPAs, or third-party client integrations, applications need standard OpenID Connect 1.0 identity claims. The `oidc-provider` plugin integrates directly with GoModularAuth Core `User` entities and cryptographic signing keys to deliver:
- **Cryptographically Signed ID Tokens**: Issues RS256-signed JWTs bearing standard claims (`sub`, `iss`, `aud`, `exp`, `iat`, `nonce`, `email`, `email_verified`).
- **Standardized Discovery Metadata**: Automatically generates the `/.well-known/openid-configuration` document.
- **Dynamic JWKS Serving**: Publishes RSA public keys in RFC 7517 JSON Web Key Set format for automatic client signature verification.
- **UserInfo Claims Endpoint**: Resolves user attributes according to requested scopes (`openid`, `profile`, `email`).

---

## 2. Installation & Registration

```bash
go get github.com/BladiCreator/go-modular-auth/plugins/oidc-provider
```

Register the plugin in the GoModularAuth configuration:

```go
package main

import (
    "crypto/rsa"

    auth "github.com/BladiCreator/go-modular-auth"
    oidcprovider "github.com/BladiCreator/go-modular-auth/plugins/oidc-provider"
)

func main() {
    // 1. Initialize plugin with RSA signing key
    oidcMod := oidcprovider.New(
        oidcprovider.WithIssuer("https://auth.example.com"),
        oidcprovider.WithPrivateKey(rsaPrivateKey),
        oidcprovider.WithKeyID("key-2026-01"),
    )

    // 2. Wire into engine
    engine, err := auth.New(auth.Config{
        Store:   store,
        Plugins: []auth.PluginModule{oidcMod},
    })
    if err != nil {
        panic(err)
    }

    // 3. Resolve capability
    idp := auth.MustGet[oidcprovider.OIDCProvider](engine)
    _ = idp
}
```

---

## 3. Capability Interface: `oidcprovider.OIDCProvider`

```go
type OIDCProvider interface {
    GetDiscovery() *discovery.Document
    GetJWKS(ctx context.Context) (*jwks.JWKS, error)
    IssueIDToken(ctx context.Context, u *user.User, clientID, nonce string, ttl time.Duration) (string, error)
    GetUserInfo(ctx context.Context, userID string) (map[string]any, error)
}
```

---

## 4. Usage

### 4.1 Serving Discovery & JWKS in HTTP Routers
```go
// GET /.well-known/openid-configuration
http.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
    doc := idp.GetDiscovery()
    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(doc)
})

// GET /.well-known/jwks.json
http.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
    jwksKeys, err := idp.GetJWKS(r.Context())
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(jwksKeys)
})
```

### 4.2 Issuing Signed ID Tokens
```go
idToken, err := idp.IssueIDToken(ctx, user, "client-app-123", "random_nonce_abc", 1*time.Hour)
// idToken is a cryptographically signed compact JWT
```

### 4.3 Serving the `/userinfo` Endpoint
```go
claims, err := idp.GetUserInfo(ctx, principal.Subject)
// Returns map containing "sub", "email", "email_verified", etc.
```
