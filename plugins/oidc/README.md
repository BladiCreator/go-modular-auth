# GoModularAuth OpenID Connect (OIDC) Relying Party Plugin

`gomodularauth-oidc` provides OpenID Connect Relying Party (client) authentication and federated identity integration for GoModularAuth. It implements RFC 6749, RFC 7636 (PKCE), and OpenID Connect Core 1.0 specifications with rigorous zero-trust ID token verification, strict nonce binding, multi-provider discovery, and account linking.

## Installation

```bash
go get github.com/BladiCreator/go-modular-auth/plugins/oidc
```

## Quick Start

```go
engine, err := auth.New(auth.Config{
    Adapter: adaptermem.New(),
    Cache: coreCache,
    Plugins: []auth.PluginModule{
        oidcPlugin,
    },
})
if err != nil {
    log.Fatalf("failed to initialize auth: %v", err)
}

// Access typed capability
oidcAuth, err := auth.Get[plugins.OIDC](engine)
if err != nil {
    log.Fatalf("failed to resolve OIDC capability: %v", err)
}
```

Detailed guide: [**`doc/plugins/oidc.md`**](../../doc/plugins/oidc.md).
