# Transport Adapters (HTTP & gRPC)

## 1. Principles of Transport Integration

GoModularAuth is **completely transport-agnostic**. The core engine defines domain operations that receive `context.Context` and pure Go structs.

The role of a **Transport Adapter** is to:
1. Extract credentials or session tokens from incoming transport requests (Cookies, `Authorization: Bearer <token>`, custom headers, or gRPC metadata).
2. Call the core engine (`app.GetSession`, `app.RequireSession`).
3. Inject the resolved `auth.Principal` and `auth.SessionResult` into the request context.
4. Format responses, set cookies, or return appropriate HTTP status codes or gRPC status codes.

---

## 2. Official HTTP Adapter (`adapters/http`)

Import:
```go
import "github.com/BladiCreator/go-modular-auth/adapters/http"
```

### 2.1 Token Extractors
Extractors retrieve authentication tokens from incoming requests:

- **`http.BearerExtractor`**: Extracts Bearer token from the standard `Authorization: Bearer <token>` header.
- **`http.CookieExtractor("session_token")`**: Extracts token from a named HTTP cookie.
- **`http.HeaderExtractor("X-Auth-Token")`**: Extracts token from a custom HTTP header.

### 2.2 Middleware

#### `http.Authenticate` (Lenient)
Validates a session if a token is present, binding the session and principal to `r.Context()`. If no token is provided or the token is invalid, the request continues as an unauthenticated guest request:

```go
handler = http.Authenticate(engine,
    http.WithExtractor(http.BearerExtractor),
    http.WithExtractor(http.CookieExtractor("session_token")),
)(handler)
```

#### `http.RequireSession` (Strict)
Demands a valid, unexpired, and unrevoked session. If absent or invalid, it immediately terminates the request with `401 Unauthorized`:

```go
protectedHandler = http.RequireSession(engine,
    http.WithExtractor(http.BearerExtractor),
    http.WithExtractor(http.CookieExtractor("session_token")),
    http.WithErrorHandler(customErrorHandler), // Optional custom error formatting
)(protectedHandler)
```

### 2.3 Context Helpers
Inside downstream handlers, retrieve the authenticated session and principal directly from the context:

```go
func ProtectedEndpoint(w http.ResponseWriter, r *http.Request) {
    // Retrieve session result
    sessionResult, ok := http.SessionFrom(r.Context())
    if !ok {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }

    // Retrieve principal
    principal, _ := http.PrincipalFrom(r.Context())
    fmt.Fprintf(w, "Hello User ID: %s", principal.Subject)
}
```

---

## 3. Web Framework Integration Examples

### 3.1 Standard Library (`net/http`) & Chi
```go
package main

import (
    "net/http"
    "github.com/go-chi/chi/v5"
    auth "github.com/BladiCreator/go-modular-auth"
    authhttp "github.com/BladiCreator/go-modular-auth/adapters/http"
)

func routes(engine *auth.Auth) http.Handler {
    r := chi.NewRouter()

    // Public routes
    r.Post("/api/signup", handleSignUp(engine))
    r.Post("/api/signin", handleSignIn(engine))

    // Protected sub-router
    r.Group(func(protected chi.Router) {
        protected.Use(authhttp.RequireSession(engine,
            authhttp.WithExtractor(authhttp.BearerExtractor),
            authhttp.WithExtractor(authhttp.CookieExtractor("session_token")),
        ))

        protected.Get("/api/me", handleMe)
    })

    return r
}
```

### 3.2 Gin Web Framework
```go
func GinAuthMiddleware(engine *auth.Auth) gin.HandlerFunc {
    authMiddleware := authhttp.RequireSession(engine, authhttp.WithExtractor(authhttp.BearerExtractor))

    return func(c *gin.Context) {
        authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            c.Request = r
            c.Next()
        })).ServeHTTP(c.Writer, c.Request)
    }
}
```

---

## 4. Official gRPC Adapter (`adapters/grpc`)

Import:
```go
import "github.com/BladiCreator/go-modular-auth/adapters/grpc"
```

The gRPC adapter extracts authentication credentials from incoming gRPC `metadata.MD` and propagates the authenticated `Principal` and `Session` into RPC handlers.

### 4.1 Unary & Streaming Server Interceptors

```go
package main

import (
    "google.golang.org/grpc"
    auth "github.com/BladiCreator/go-modular-auth"
    authgrpc "github.com/BladiCreator/go-modular-auth/adapters/grpc"
)

func NewGRPCServer(engine *auth.Auth) *grpc.Server {
    server := grpc.NewServer(
        grpc.UnaryInterceptor(authgrpc.UnaryServerInterceptor(engine,
            authgrpc.WithExtractor(authgrpc.BearerMetadataExtractor),
            authgrpc.WithLenient(false), // Strict: returns codes.Unauthenticated if missing/invalid
        )),
        grpc.StreamInterceptor(authgrpc.StreamServerInterceptor(engine,
            authgrpc.WithExtractor(authgrpc.BearerMetadataExtractor),
            authgrpc.WithLenient(false),
        )),
    )

    return server
}
```

### 4.2 Consuming Authentication in RPC Handlers

```go
func (s *ProfileServer) GetProfile(ctx context.Context, req *pb.GetProfileRequest) (*pb.ProfileResponse, error) {
    principal, ok := authgrpc.PrincipalFrom(ctx)
    if !ok {
        return nil, status.Error(codes.Unauthenticated, "unauthenticated")
    }

    sessionResult, _ := authgrpc.SessionFrom(ctx)

    return &pb.ProfileResponse{
        UserId: principal.Subject,
        Email:  sessionResult.User.Email,
    }, nil
}
```
