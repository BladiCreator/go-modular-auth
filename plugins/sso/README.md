# GoModularAuth Enterprise Single Sign-On (SSO) Plugin

`gomodularauth-sso` provides enterprise Single Sign-On (SSO) configuration, domain discovery, and multi-tenant identity federation across OpenID Connect (OIDC) and SAML 2.0 protocols for [GoModularAuth](https://github.com/BladiCreator/go-modular-auth).

## Installation

```bash
go get github.com/BladiCreator/go-modular-auth/plugins/sso
```

## Quick Start

```go
engine, err := auth.New(auth.Config{
    Adapter: adaptermem.New(),
    Cache: coreCache,
    Plugins: []auth.PluginModule{
        organizationsModule, // Optional: for JIT membership assignment
        ssoModule,
    },
})
if err != nil {
    log.Fatalf("failed to initialize auth: %v", err)
}

// Access typed capability
ssoCap, err := auth.Get[plugins.SSO](engine)
if err != nil {
    log.Fatalf("failed to resolve SSO capability: %v", err)
}
```

Detailed guide: [**`doc/plugins/sso.md`**](../../doc/plugins/sso.md).
