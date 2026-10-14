# OpenAPI 3.0 Specification Generator Plugin

The **OpenAPI Plugin** (`plugins/openapi`) automatically inspects the GoModularAuth engine registry and dynamically generates an **OpenAPI 3.0 Document** representing all available endpoints, request bodies, query parameters, schemas, and error responses.

---

## 1. Problem Solved

Maintaining Swagger/OpenAPI documentation manually across modular authentication plugins is error-prone. When plugins are added or removed (e.g. enabling passkeys, organizations, or MFA), the API surface changes.

The `openapi` plugin solves this by:
- Dynamically discovering all installed plugin IDs via `engine.Registry().Modules()`.
- Generating valid, standardized OpenAPI 3.0 specifications in JSON or struct format.
- Documenting request/response models for core operations (Sign-Up, Sign-In, Session verification) and active plugins.
- Ready for plug-and-play serving via Swagger UI, Scalar, or Redoc.

---

## 2. Installation & Registration

```bash
go get github.com/BladiCreator/go-modular-auth/plugins/openapi
```

Register the plugin:

```go
package main

import (
    auth "github.com/BladiCreator/go-modular-auth"
    "github.com/BladiCreator/go-modular-auth/plugins/openapi"
)

func main() {
    openAPIMod := openapi.New(
        openapi.WithTitle("Acme Identity & Auth API"),
        openapi.WithVersion("v1.0.0"),
        openapi.WithDescription("Authentication endpoints powered by GoModularAuth"),
    )

    engine, err := auth.New(auth.Config{
        Store:   store,
        Plugins: []auth.PluginModule{openAPIMod, ...otherPlugins},
    })
    if err != nil {
        panic(err)
    }

    // Resolve capability
    gen := auth.MustGet[openapi.OpenAPIGenerator](engine)
    _ = gen
}
```

---

## 3. Capability Interface: `openapi.OpenAPIGenerator`

```go
type OpenAPIGenerator interface {
    // Generate returns the OpenAPI 3.0 AST document.
    Generate() (*spec.Document, error)

    // GenerateJSON serializes the OpenAPI 3.0 specification to JSON bytes.
    GenerateJSON(indent bool) ([]byte, error)
}
```

---

## 4. Serving with HTTP Routers

Serve the OpenAPI specification to power interactive API documentation tools:

```go
package main

import (
    "net/http"
    "github.com/BladiCreator/go-modular-auth/plugins/openapi"
)

func RegisterOpenAPIRoutes(mux *http.ServeMux, gen openapi.OpenAPIGenerator) {
    // 1. Serve OpenAPI 3.0 JSON specification
    mux.HandleFunc("GET /openapi.json", func(w http.ResponseWriter, r *http.Request) {
        jsonBytes, err := gen.GenerateJSON(true) // Indented JSON
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }

        w.Header().Set("Content-Type", "application/json; charset=utf-8")
        w.Write(jsonBytes)
    })

    // 2. Serve Swagger UI pointing to /openapi.json
    mux.HandleFunc("GET /docs", func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "text/html; charset=utf-8")
        w.Write([]byte(`<!DOCTYPE html>
<html>
<head>
    <title>API Documentation</title>
    <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css" />
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
    <script>
        window.ui = SwaggerUIBundle({
            url: '/openapi.json',
            dom_id: '#swagger-ui',
        });
    </script>
</body>
</html>`))
    })
}
```
