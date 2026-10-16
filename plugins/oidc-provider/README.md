# GoModularAuth OIDC Provider Plugin (`gomodularauth-oidc-provider`)

[![Go Reference](https://pkg.go.dev/badge/github.com/BladiCreator/go-modular-auth/plugins/oidc-provider.svg)](https://pkg.go.dev/github.com/BladiCreator/go-modular-auth/plugins/oidc-provider)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

The **OIDC Provider Plugin** enables GoModularAuth to act as an OpenID Connect (OIDC) Identity Provider (IdP), issuing signed RS256 ID tokens and publishing Discovery and JWKS metadata.

## Installation

```bash
go get github.com/BladiCreator/go-modular-auth/plugins/oidc-provider
```

## Quick Start

```go
package main

import (
	"context"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	adaptermem "github.com/BladiCreator/go-modular-auth/adapters/memory"
	oidcprovider "github.com/BladiCreator/go-modular-auth/plugins/oidc-provider"
	"github.com/BladiCreator/go-modular-auth/user"
)

func main() {
	ctx := context.Background()

	engine, _ := auth.New(auth.Config{
		Adapter: adaptermem.NewAdapter(),
		Plugins: []auth.PluginModule{
			oidcprovider.New(
				oidcprovider.WithIssuer("https://auth.example.com"),
			),
		},
	})

	provider, _ := auth.Get[oidcprovider.OIDCProvider](engine)

	// Issue an OIDC ID token
	u := &user.User{ID: "usr_alice", Email: "alice@example.com"}
	idToken, _ := provider.IssueIDToken(ctx, u, "client_app", "nonce_123", time.Hour)
	_ = idToken
}
```

Detailed guide: [**`doc/plugins/oidc-provider.md`**](../../doc/plugins/oidc-provider.md).
