package captcha

import (
	"errors"
	"net/http"
	"strings"
)

// Protect returns a standard net/http middleware handler to intercept and validate captcha tokens on protected endpoints.
func (p *Plugin) Protect() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !p.IsProtectedPath(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}

			if p.config.SecretKey == "" {
				http.Error(w, ErrMissingSecretKey.Error(), http.StatusInternalServerError)
				return
			}

			token := strings.TrimSpace(r.Header.Get(HeaderCaptchaResponse))
			if token == "" {
				http.Error(w, ErrMissingCaptchaResponse.Error(), http.StatusBadRequest)
				return
			}

			remoteIP := ""
			if p.config.IPExtractor != nil {
				remoteIP = p.config.IPExtractor(r)
			}

			err := p.VerifyToken(r.Context(), token, remoteIP)
			if err != nil {
				if errors.Is(err, ErrServiceUnavailable) || errors.Is(err, ErrMissingSecretKey) || errors.Is(err, ErrInvalidProvider) {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				http.Error(w, err.Error(), http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
