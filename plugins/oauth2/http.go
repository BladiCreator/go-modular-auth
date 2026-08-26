package oauth2

import (
	"context"
	"net/http"
	"strings"
)

// Context keys for request context store.
type contextKey string

const (
	TokenIntrospectContextKey contextKey = "oauth2_token_introspect"
)

// RequireScope returns a net/http middleware handler verifying valid OAuth2 Access Token and required scopes.
func (p *Plugin) RequireScope(requiredScopes ...string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, "Unauthorized: Missing authorization header", http.StatusUnauthorized)
				return
			}
			token := authHeader
			if strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
				token = strings.TrimSpace(authHeader[7:])
			}
			if token == "" {
				http.Error(w, "Unauthorized: Missing bearer token", http.StatusUnauthorized)
				return
			}

			intro, err := p.Introspect(r.Context(), IntrospectParams{
				Token: token,
			})
			if err != nil || intro == nil || !intro.Active {
				http.Error(w, "Unauthorized: Invalid or inactive OAuth2 token", http.StatusUnauthorized)
				return
			}

			if len(requiredScopes) > 0 {
				tokenScopes := strings.Split(intro.Scope, " ")
				for _, reqScope := range requiredScopes {
					found := false
					for _, ts := range tokenScopes {
						if ts == reqScope {
							found = true
							break
						}
					}
					if !found {
						http.Error(w, "Forbidden: Missing required OAuth2 scope "+reqScope, http.StatusForbidden)
						return
					}
				}
			}

			ctx := context.WithValue(r.Context(), TokenIntrospectContextKey, intro)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
