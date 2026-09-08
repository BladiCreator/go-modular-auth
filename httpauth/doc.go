// Package httpauth provides non-invasive, standard net/http transport utilities
// for authentication workflows in go-modular-auth.
//
// It operates purely on standard [*http.Request] and [http.ResponseWriter] interfaces,
// without imposing any router, routing abstractions, or external framework dependencies.
// It is fully compatible with stdlib net/http, Fuego, Gin, Fiber (via adaptors), Chi, Echo,
// and any other Go web framework.
//
// Key capabilities include:
//   - Secure session cookie management with OWASP-recommended defaults (HttpOnly, SameSite=Lax, Secure).
//   - Cascading token extraction across Cookies, Authorization Bearer headers, and URL query parameters.
//   - Robust client IP and User-Agent resolution behind reverse proxies (X-Forwarded-For, X-Real-IP, RemoteAddr).
//   - Type-safe request context propagation for [entity.Session] and [entity.User] using unexported context keys.
package httpauth
