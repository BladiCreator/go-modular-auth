# GoModularAuth SCIM Plugin (`gomodularauth-scim`)

[![Go Reference](https://pkg.go.dev/badge/github.com/BladiCreator/go-modular-auth/plugins/scim.svg)](https://pkg.go.dev/github.com/BladiCreator/go-modular-auth/plugins/scim)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

The **SCIM Plugin** implements the System for Cross-domain Identity Management (SCIM 2.0) protocol for automated user provisioning and de-provisioning from Okta, Azure AD / Microsoft Entra ID, and OneLogin.

## Installation

```bash
go get github.com/BladiCreator/go-modular-auth/plugins/scim
```

## Quick Start

```go
package main

import (
	"context"

	auth "github.com/BladiCreator/go-modular-auth"
	adaptermem "github.com/BladiCreator/go-modular-auth/adapters/memory"
	"github.com/BladiCreator/go-modular-auth/plugins/scim"
	v2 "github.com/BladiCreator/go-modular-auth/plugins/scim/v2"
)

func main() {
	ctx := context.Background()

	engine, _ := auth.New(auth.Config{
		Adapter: adaptermem.NewAdapter(),
		Plugins: []auth.PluginModule{scim.New()},
	})

	provider, _ := auth.Get[scim.SCIMProvider](engine)

	// Provision user from SCIM payload
	userRes, _ := provider.CreateUser(ctx, &v2.UserResource{
		UserName:   "bob@example.com",
		ExternalID: "okta_123",
		Active:     true,
	})
	_ = userRes
}
```

Detailed guide: [**`doc/plugins/scim.md`**](../../doc/plugins/scim.md).
