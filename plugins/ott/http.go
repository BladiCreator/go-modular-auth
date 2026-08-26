package ott

import (
	"context"
	"net/http"
	"strings"
)

// Context keys for request context store.
type contextKey string

const (
	SessionContextKey contextKey = "ott_session"
	UserContextKey    contextKey = "ott_user"
)

// Authenticate returns a net/http middleware handler to extract and verify One-Time Tokens from request headers or query parameters.
func (p *Plugin) Authenticate() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := r.Header.Get("X-OTT-Token")
			if token == "" {
				token = r.URL.Query().Get("ott")
			}
			if token == "" {
				http.Error(w, "Unauthorized: Missing OTT token", http.StatusUnauthorized)
				return
			}

			res, err := p.VerifyToken(r.Context(), VerifyTokenParams{
				Token: token,
			})
			if err != nil || res == nil {
				http.Error(w, "Unauthorized: Invalid or expired OTT token", http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), SessionContextKey, res.Session)
			ctx = context.WithValue(ctx, UserContextKey, res.User)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// AttachHeader generates an OTT for the given session and sets the set-ott HTTP header on the response writer.
func (p *Plugin) AttachHeader(w http.ResponseWriter, sessionToken string) error {
	if w == nil || sessionToken == "" {
		return ErrInvalidParameter
	}

	res, err := p.GenerateToken(context.Background(), GenerateTokenParams{
		SessionToken: sessionToken,
		IsClientReq:  false,
	})
	if err != nil {
		return err
	}

	w.Header().Set("set-ott", res.Token)

	// Expose header for CORS requests if not present
	existingExpose := w.Header().Get("Access-Control-Expose-Headers")
	if existingExpose == "" {
		w.Header().Set("Access-Control-Expose-Headers", "set-ott")
	} else if !strings.Contains(strings.ToLower(existingExpose), "set-ott") {
		w.Header().Set("Access-Control-Expose-Headers", existingExpose+", set-ott")
	}

	return nil
}
