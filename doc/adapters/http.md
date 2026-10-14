# HTTP Transport Adapter

The **HTTP Adapter** (`adapters/http`) provides standard `net/http` middlewares and token extractors to bridge web requests with the GoModularAuth engine without coupling the core engine to HTTP.

---

## Installation

```bash
go get github.com/BladiCreator/go-modular-auth/adapters/http
```

---

## Token Extractors

Extractors retrieve authentication tokens from incoming `*http.Request` instances. You can configure one or more extractors in an evaluation chain:

```go
import "github.com/BladiCreator/go-modular-auth/adapters/http"

// Extracts Bearer token from 'Authorization: Bearer <token>' header
extractor := http.BearerExtractor

// Extracts token from named HTTP cookie
cookieExtractor := http.CookieExtractor("session_token")

// Extracts token from arbitrary request header
headerExtractor := http.HeaderExtractor("X-API-Token")
```

---

## Middlewares

### 1. `http.Authenticate` (Lenient Middleware)
Use this middleware when endpoints can serve both authenticated users and anonymous guests.
If a valid token is provided, the authenticated session and principal are injected into the request context. If no token is provided or the token is invalid/expired, the request proceeds unauthenticated without raising an HTTP error:

```go
handler = http.Authenticate(engine,
    http.WithExtractor(http.BearerExtractor),
    http.WithExtractor(http.CookieExtractor("session_token")),
)(handler)
```

### 2. `http.RequireSession` (Strict Middleware)
Use this middleware to protect private endpoints.
If the request lacks a token, or the token is expired/revoked, the middleware halts request processing and returns `401 Unauthorized`:

```go
protectedHandler = http.RequireSession(engine,
    http.WithExtractor(http.BearerExtractor),
    http.WithExtractor(http.CookieExtractor("session_token")),
    http.WithErrorHandler(customErrorHandler), // optional
)(protectedHandler)
```

### 3. Custom Error Handler
Override the default JSON error response by supplying `WithErrorHandler`:

```go
func customErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
    w.Header().Set("Content-Type", "application/problem+json")
    w.WriteHeader(http.StatusUnauthorized)
    _ = json.NewEncoder(w).Encode(map[string]any{
        "type":   "https://example.com/errors/unauthorized",
        "title":  "Authentication Required",
        "detail": err.Error(),
        "status": http.StatusUnauthorized,
    })
}
```

---

## Context Helpers

Inside downstream HTTP handlers, retrieve the authenticated state using context helpers:

```go
func UserProfileHandler(w http.ResponseWriter, r *http.Request) {
    // 1. Retrieve the validated SessionResult
    sessionRes, ok := http.SessionFrom(r.Context())
    if !ok {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }

    // 2. Retrieve the authenticated Principal
    principal, ok := http.PrincipalFrom(r.Context())

    fmt.Fprintf(w, "User ID: %s, Email: %s\n", principal.Subject, sessionRes.User.Email)
}
```

---

## Framework Integration Examples

### Chi Router
```go
r := chi.NewRouter()

// Public
r.Post("/api/login", handleLogin)

// Protected group
r.Group(func(protected chi.Router) {
    protected.Use(http.RequireSession(engine,
        http.WithExtractor(http.BearerExtractor),
        http.WithExtractor(http.CookieExtractor("session_token")),
    ))
    protected.Get("/api/me", UserProfileHandler)
})
```

### Gin
```go
func GinRequireAuth(engine *auth.Auth) gin.HandlerFunc {
    authMiddleware := http.RequireSession(engine, http.WithExtractor(http.BearerExtractor))
    return func(c *gin.Context) {
        authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            c.Request = r
            c.Next()
        })).ServeHTTP(c.Writer, c.Request)
    }
}
```
