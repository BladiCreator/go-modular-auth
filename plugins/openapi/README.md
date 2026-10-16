# GoModularAuth OpenAPI Plugin (`gomodularauth-openapi`)

[![Go Reference](https://pkg.go.dev/badge/github.com/BladiCreator/go-modular-auth/plugins/openapi.svg)](https://pkg.go.dev/github.com/BladiCreator/go-modular-auth/plugins/openapi)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

The **OpenAPI Plugin** dynamically inspects registered GoModularAuth plugins to generate complete OpenAPI 3.0 specifications.

## Installation

```bash
go get github.com/BladiCreator/go-modular-auth/plugins/openapi
```

## Quick Start

```go
package main

import (
	"fmt"

	auth "github.com/BladiCreator/go-modular-auth"
	adaptermem "github.com/BladiCreator/go-modular-auth/adapters/memory"
	"github.com/BladiCreator/go-modular-auth/plugins/openapi"
)

func main() {
	engine, _ := auth.New(auth.Config{
		Adapter: adaptermem.NewAdapter(),
		Plugins: []auth.PluginModule{
			openapi.New(openapi.WithTitle("Platform Authentication API")),
		},
	})

	gen, _ := auth.Get[openapi.OpenAPIGenerator](engine)

	// Generate JSON specification
	jsonBytes, _ := gen.GenerateJSON(true)
	fmt.Println(string(jsonBytes))
}
```

Detailed guide: [**`doc/plugins/openapi.md`**](../../doc/plugins/openapi.md).
