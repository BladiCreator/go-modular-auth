package apikey

import (
	"context"
	"net/http"

	"github.com/BladiCreator/go-modular-auth/httpauth"
)

// Authenticate returns a standard net/http middleware handler to authenticate API Keys from incoming HTTP request headers.
func (p *Plugin) Authenticate() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rawKey := p.extractKeyFromRequest(r)
			if rawKey == "" {
				next.ServeHTTP(w, r)
				return
			}

			res, err := p.VerifyKey(r.Context(), VerifyApiKeyParams{Key: rawKey})
			if err != nil || res == nil || !res.Valid {
				http.Error(w, "Unauthorized: Invalid API Key", http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), ApiKeyContextKey, res.ApiKey)
			if res.User != nil {
				ctx = context.WithValue(ctx, UserContextKey, res.User)
				ctx = httpauth.WithUser(ctx, res.User)
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func (p *Plugin) extractKeyFromRequest(r *http.Request) string {
	for _, headerName := range p.config.ApiKeyHeaders {
		if token, err := httpauth.ExtractToken(r,
			httpauth.WithSources(httpauth.SourceHeader),
			httpauth.WithExtractHeader(headerName, "Bearer "),
		); err == nil && token != "" {
			return token
		}
		if token, err := httpauth.ExtractToken(r,
			httpauth.WithSources(httpauth.SourceHeader),
			httpauth.WithExtractHeader(headerName, ""),
		); err == nil && token != "" {
			return token
		}
	}
	return ""
}
