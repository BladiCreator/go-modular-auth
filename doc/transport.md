# Transport Adapters (HTTP, gRPC, CLI)

## 1. Principles of Transport Integration

GoModularAuth is completely **transport-agnostic**. The core engine defines domain operations that receive `context.Context` and pure Go structs.

The role of a **Transport Adapter** is to:
1. Extract credentials or session tokens from incoming transport requests (Cookies, `Authorization: Bearer <token>`, HTTP headers, gRPC metadata).
2. Call the core engine (`app.SignIn`, `app.RequireSession`, etc.).
3. Inject the resolved `auth.Principal` into the request context.
4. Format responses, set cookies, or return appropriate HTTP status codes / gRPC errors.

---

## 2. Standard `net/http` Adapter Example

### 2.1 Middleware: Authenticating Requests
```go
package transport

import (
    "net/http"
    "strings"

    "github.com/BladiCreator/go-modular-auth/auth"
)

func AuthMiddleware(app *auth.Auth) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            token := extractToken(r)
            if token == "" {
                next.ServeHTTP(w, r)
                return
            }

            sessionRes, err := app.GetSession(r.Context(), token)
            if err != nil || sessionRes == nil {
                next.ServeHTTP(w, r)
                return
            }

            // Inject Principal and User into context
            ctx := auth.WithPrincipal(r.Context(), sessionRes.Principal())
            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }
}

func extractToken(r *http.Request) string {
    // 1. Check Authorization: Bearer <token>
    if authHeader := r.Header.Get("Authorization"); strings.HasPrefix(authHeader, "Bearer ") {
        return strings.TrimPrefix(authHeader, "Bearer ")
    }

    // 2. Fall back to Cookie
    if cookie, err := r.Cookie("session_token"); err == nil {
        return cookie.Value
    }

    return ""
}
```

### 2.2 Protecting Routes
```go
func RequireAuth(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        principal, ok := auth.PrincipalFrom(r.Context())
        if !ok {
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }

        // Access authenticated identity
        _ = principal.Subject
        next.ServeHTTP(w, r)
    })
}
```

### 2.3 Sign In Handler
```go
func HandleSignIn(app *auth.Auth) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        var body struct {
            Email    string `json:"email"`
            Password string `json:"password"`
        }
        if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
            http.Error(w, "Bad Request", http.StatusBadRequest)
            return
        }

        res, err := app.SignIn(r.Context(), auth.SignInInput{
            Email:    body.Email,
            Password: body.Password,
            Session: auth.SessionOptions{
                IPAddress: r.RemoteAddr,
                UserAgent: r.UserAgent(),
            },
        })
        if err != nil {
            if errors.Is(err, auth.ErrInvalidCredentials) {
                http.Error(w, "Invalid credentials", http.StatusUnauthorized)
                return
            }
            http.Error(w, "Internal server error", http.StatusInternalServerError)
            return
        }

        // Set secure HTTP-only cookie
        http.SetCookie(w, &http.Cookie{
            Name:     "session_token",
            Value:    res.Token,
            Path:     "/",
            HttpOnly: true,
            Secure:   true,
            SameSite: http.SameSiteStrictMode,
        })

        w.WriteHeader(http.StatusOK)
    }
}
```

---

## 3. Framework Adaptations (Gin, Fiber, Echo)

The same pattern applies cleanly to popular web frameworks:

- **Gin**:
  ```go
  func GinAuthMiddleware(app *auth.Auth) gin.HandlerFunc {
      return func(c *gin.Context) {
          token := extractTokenFromHeaderOrCookie(c.Request)
          if token != "" {
              if res, err := app.GetSession(c.Request.Context(), token); err == nil && res != nil {
                  c.Set("principal", res.Principal())
                  c.Request = c.Request.WithContext(auth.WithPrincipal(c.Request.Context(), res.Principal()))
              }
          }
          c.Next()
      }
  }
  ```

- **Fiber**:
  ```go
  func FiberAuthMiddleware(app *auth.Auth) fiber.Handler {
      return func(c *fiber.Ctx) error {
          token := c.Get("Authorization")
          if strings.HasPrefix(token, "Bearer ") {
              token = strings.TrimPrefix(token, "Bearer ")
          } else {
              token = c.Cookies("session_token")
          }

          if token != "" {
              if res, err := app.GetSession(c.Context(), token); err == nil && res != nil {
                  c.Locals("principal", res.Principal())
              }
          }
          return c.Next()
      }
  }
  ```

- **gRPC**:
  Implement a unary and stream server interceptor extracting the bearer token from `metadata.FromIncomingContext(ctx)`, resolving it with `app.GetSession`, and injecting the authenticated `Principal` into the gRPC handler context via `auth.WithPrincipal(ctx, principal)`.

