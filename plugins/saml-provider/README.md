# GoModularAuth SAML Provider Plugin (`gomodularauth-saml-provider`)

[![Go Reference](https://pkg.go.dev/badge/github.com/BladiCreator/go-modular-auth/plugins/saml-provider.svg)](https://pkg.go.dev/github.com/BladiCreator/go-modular-auth/plugins/saml-provider)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

The **SAML Provider Plugin** enables GoModularAuth to act as a SAML 2.0 Identity Provider (IdP) for federating enterprise Single Sign-On (SSO).

## Installation

```bash
go get github.com/BladiCreator/go-modular-auth/plugins/saml-provider
```

## Quick Start

```go
package main

import (
	"context"

	auth "github.com/BladiCreator/go-modular-auth"
	adaptermem "github.com/BladiCreator/go-modular-auth/adapters/memory"
	samlprovider "github.com/BladiCreator/go-modular-auth/plugins/saml-provider"
	"github.com/BladiCreator/go-modular-auth/user"
)

func main() {
	ctx := context.Background()

	engine, _ := auth.New(auth.Config{
		Adapter: adaptermem.NewAdapter(),
		Plugins: []auth.PluginModule{
			samlprovider.New(
				samlprovider.WithEntityID("https://auth.example.com/saml/idp"),
			),
		},
	})

	idp, _ := auth.Get[samlprovider.SAMLProvider](engine)

	// Register a trusted Service Provider
	_ = idp.RegisterSP(&samlprovider.ServiceProvider{
		EntityID: "https://sp.example.com",
		ACSURL:   "https://sp.example.com/saml/acs",
	})

	// Build signed SAML Response for an authenticated user
	u := &user.User{ID: "usr_alice", Email: "alice@example.com"}
	respBase64, _ := idp.BuildResponse(ctx, "https://sp.example.com", u, "_req_id")
	_ = respBase64
}
```

Detailed guide: [**`doc/plugins/saml-provider.md`**](../../doc/plugins/saml-provider.md).
