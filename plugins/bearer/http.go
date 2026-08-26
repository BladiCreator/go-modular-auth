package bearer

import (
	"context"
	"net/http"
)

// Context keys for request context store.
type contextKey string

const (
	SessionContextKey     contextKey = "bearer_session"
	RawTokenContextKey    contextKey = "bearer_raw_token"
	SignedTokenContextKey contextKey = "bearer_signed_token"
)

// Authenticate returns a standard net/http middleware handler to authenticate Bearer tokens from incoming HTTP request headers.
func (p *Plugin) Authenticate() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			headerVal := r.Header.Get(p.config.TokenHeader)
			if headerVal == "" {
				http.Error(w, "Unauthorized: Missing authorization header", http.StatusUnauthorized)
				return
			}

			res, err := p.ResolveSession(r.Context(), ResolveSessionParams{
				Header: headerVal,
			})
			if err != nil {
				http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), RawTokenContextKey, res.RawToken)
			ctx = context.WithValue(ctx, SignedTokenContextKey, res.SignedToken)
			if res.Session != nil {
				ctx = context.WithValue(ctx, SessionContextKey, res.Session)
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
