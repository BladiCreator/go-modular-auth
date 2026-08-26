package apikey

import (
	"context"
	"net/http"
	"strings"
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
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func (p *Plugin) extractKeyFromRequest(r *http.Request) string {
	for _, headerName := range p.config.ApiKeyHeaders {
		val := r.Header.Get(headerName)
		if val != "" {
			if strings.HasPrefix(strings.ToLower(val), "bearer ") {
				return strings.TrimSpace(val[7:])
			}
			return strings.TrimSpace(val)
		}
	}
	return ""
}
