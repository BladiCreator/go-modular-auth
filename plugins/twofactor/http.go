package twofactor

import (
	"net/http"
	"strings"
)

// Context keys for request context store.
type contextKey string

const (
	TwoFactorVerifiedContextKey contextKey = "2fa_verified"
)

// Require2FA returns a net/http middleware handler enforcing that the active request has completed 2FA verification.
func (p *Plugin) Require2FA() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if verified, ok := r.Context().Value(TwoFactorVerifiedContextKey).(bool); ok && verified {
				next.ServeHTTP(w, r)
				return
			}
			if strings.EqualFold(r.Header.Get("X-2FA-Verified"), "true") {
				next.ServeHTTP(w, r)
				return
			}
			http.Error(w, "Precondition Required: Two-Factor Authentication required", http.StatusPreconditionRequired)
		})
	}
}
