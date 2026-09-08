package jwt

import (
	"context"
	"net/http"

	"github.com/BladiCreator/go-modular-auth/httpauth"
)

// Context keys for request context store.
type contextKey string

const (
	ClaimsContextKey  contextKey = "jwt_claims"
	SubjectContextKey contextKey = "jwt_subject"
	TokenContextKey   contextKey = "jwt_token"
)

// Authenticate returns a standard net/http middleware handler to authenticate JWT tokens from incoming Authorization headers.
func (p *Plugin) Authenticate() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, err := httpauth.ExtractToken(r, httpauth.WithSources(httpauth.SourceHeader))
			if err != nil || token == "" {
				http.Error(w, "Unauthorized: Missing authorization header", http.StatusUnauthorized)
				return
			}

			res, err := p.Verify(r.Context(), VerifyParams{
				Token: token,
			})
			if err != nil || res == nil || !res.Valid {
				http.Error(w, "Unauthorized: Invalid JWT token", http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), TokenContextKey, token)
			ctx = context.WithValue(ctx, ClaimsContextKey, res.Claims)
			ctx = context.WithValue(ctx, SubjectContextKey, res.Subject)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
