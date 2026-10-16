# GoModularAuth OpenAPI Plugin (`gomodularauth-openapi`)

[![Go Reference](https://pkg.go.dev/badge/github.com/BladiCreator/go-modular-auth/plugins/openapi.svg)](https://pkg.go.dev/github.com/BladiCreator/go-modular-auth/plugins/openapi)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

The **OpenAPI Plugin** (`gomodularauth-openapi`) inspects the active [GoModularAuth](https://github.com/BladiCreator/go-modular-auth) engine and dynamically generates an OpenAPI 3.0 specification reflecting installed authentication modules and their HTTP routes.

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

Maintaining API documentation in modular systems is notoriously error-prone:
- As plugins are added or removed (e.g., adding `passkeys`, enabling `twofactor`, disabling `magic-link`), manually maintained Swagger/OpenAPI files become out of sync.
- Frontend developers and API client generators require accurate schemas for request payloads, response bodies, and authentication headers.

The `openapi` plugin solves this by:
- Inspecting the GoModularAuth module registry at runtime (`Core().Registry().Modules()`).
- Generating an accurate **OpenAPI 3.0** document for all core authentication endpoints plus any active plugins.
- Serializing directly to structured Go structs (`*spec.Document`) or indented/compact JSON.

---

## Architecture & Design Principles

```text
HTTP Router (Swagger UI / Scalar / Redoc)
            │
            ▼
auth.Get[openapi.OpenAPIGenerator](engine)
            │
            ▼
┌────────────────────────────────────────────────────────┐
│           gomodularauth-openapi (Plugin)               │
│                                                        │
│  - Inspects Engine Registry Modules                    │
│  - Assembles OpenAPI 3.0 PathItems & Schemas           │
│  - Serializes to JSON                                  │
└──────────────┬─────────────────────────────────────────┘
               │
               ▼
┌──────────────────────────────┐
│ Core Engine Host             │
│ ctx.Core().Registry()        │
└──────────────────────────────┘
```

The plugin adheres strictly to GoModularAuth's architectural principles:
- **Stateless & Pure**: Generates documentation on-demand without database dependencies or background threads.
- **Dynamic Module Discovery**: Automatically adapts endpoints based on the exact slice of plugins configured in `auth.New(...)`.

---

## Installation

```bash
go get github.com/BladiCreator/go-modular-auth/plugins/openapi
```

---

## Quick Start

```go
package main

import (
	"fmt"
	"log"
	"net/http"

	auth "github.com/BladiCreator/go-modular-auth"
	adaptermem "github.com/BladiCreator/go-modular-auth/adapters/memory"
	"github.com/BladiCreator/go-modular-auth/plugins/openapi"
)

func main() {
	// 1. Initialize GoModularAuth engine with OpenAPI generator
	engine, err := auth.New(auth.Config{
		Adapter: adaptermem.NewAdapter(),
		Plugins: []auth.PluginModule{
			openapi.New(
				openapi.WithTitle("Platform Authentication API"),
				openapi.WithVersion("2.1.0"),
				openapi.WithDescription("Authentication and Identity API generated dynamically by GoModularAuth."),
			),
		},
	})
	if err != nil {
		log.Fatalf("failed to initialize auth: %v", err)
	}

	// 2. Resolve OpenAPIGenerator capability
	docGen, err := auth.Get[openapi.OpenAPIGenerator](engine)
	if err != nil {
		log.Fatalf("failed to resolve OpenAPIGenerator: %v", err)
	}

	// 3. Serve generated OpenAPI 3.0 JSON over HTTP
	http.HandleFunc("/docs/openapi.json", func(w http.ResponseWriter, r *http.Request) {
		jsonBytes, err := docGen.GenerateJSON(true)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jsonBytes)
	})

	fmt.Println("OpenAPI documentation endpoint available at http://localhost:8080/docs/openapi.json")
}
```

---

## Configuration Options

Configure the plugin using functional options in `openapi.New(opts ...Option)`:

```go
openapi.New(
    openapi.WithTitle("Customer Auth API"),
    openapi.WithVersion("1.0.0"),
    openapi.WithDescription("API specification for authentication endpoints"),
)
```

| Option | Default | Description |
| :--- | :--- | :--- |
| `WithTitle(title string)` | `"Go Modular Auth API"` | Sets the title of the API specification (`info.title`). |
| `WithVersion(v string)` | `"1.0.0"` | Sets the API version (`info.version`). |
| `WithDescription(desc string)` | `"Authentication and Identity API generated by go-modular-auth"` | Sets the API description (`info.description`). |

---

## Primary Capability API

The primary capability is exposed through `openapi.OpenAPIGenerator`, resolved via `auth.Get[openapi.OpenAPIGenerator](engine)`.

### Interface Definition

```go
package openapi

import (
	"github.com/BladiCreator/go-modular-auth/plugins/openapi/spec"
)

type OpenAPIGenerator interface {
	// Generate builds and returns an OpenAPI 3.0 Document struct reflecting active plugins.
	Generate() (*spec.Document, error)

	// GenerateJSON serializes the OpenAPI 3.0 specification to JSON.
	// If indent is true, the JSON is formatted with 2 spaces.
	GenerateJSON(indent bool) ([]byte, error)
}
```

---

## Persistence & Unified Schema

- **Stateless**: The plugin requires no database tables, no schema migrations, and no persistent store.

---

## Cache Semantics

- The generated OpenAPI specification is deterministic for a given engine configuration.
- Applications can safely cache `GenerateJSON(true)` in memory upon startup to serve HTTP documentation requests instantly with zero CPU overhead.

---

## Observational Events

- As a stateless documentation utility, the OpenAPI plugin does not emit runtime observational events.

---

## Security Model & Invariants

1. **Zero Secret Exposure**: The generator documents request/response contract schemas only. Secret keys, cryptographic seeds, and adapter credentials are never included in the output.
2. **Standard Security Schemes**: Security definitions document standard Bearer JWT and Session Cookie security schemes.

---

## Testing & Examples

Unit test verifying dynamic OpenAPI generation:

```go
func TestOpenAPIGeneration(t *testing.T) {
	engine, err := auth.New(auth.Config{
		Adapter: adaptermem.NewAdapter(),
		Plugins: []auth.PluginModule{
			openapi.New(openapi.WithTitle("Test Suite Auth")),
		},
	})
	if err != nil {
		t.Fatalf("unexpected engine init error: %v", err)
	}

	docGen, err := auth.Get[openapi.OpenAPIGenerator](engine)
	if err != nil {
		t.Fatalf("unexpected capability error: %v", err)
	}

	doc, err := docGen.Generate()
	if err != nil || doc.Info.Title != "Test Suite Auth" {
		t.Fatalf("unexpected doc: %+v", doc)
	}

	jsonBytes, err := docGen.GenerateJSON(false)
	if err != nil || len(jsonBytes) == 0 {
		t.Fatalf("failed to render JSON: %v", err)
	}
}
```

---

## License

MIT License. See [LICENSE](file:///media/vladimir/Storage/Projects/Go/go-modular-auth/LICENSE) for details.
