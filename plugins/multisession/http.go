package multisession

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
)

var invalidCookieNameChars = regexp.MustCompile(`[^a-zA-Z0-9_\-]`)

// ExtractMultiSessionTokens parses and verifies all multi-session cookies present on an incoming HTTP request.
func (p *Plugin) ExtractMultiSessionTokens(r *http.Request) []string {
	if r == nil {
		return nil
	}
	multiPrefix := p.config.CookiePrefix + "_multi-"
	tokens := make([]string, 0)
	seen := make(map[string]bool)

	for _, c := range r.Cookies() {
		if strings.HasPrefix(c.Name, multiPrefix) {
			rawToken, err := VerifyCookieValue(c.Value, p.config.Secret)
			if err == nil && rawToken != "" && !seen[rawToken] {
				seen[rawToken] = true
				tokens = append(tokens, rawToken)
			}
		}
	}
	return tokens
}

// ExtractMainSessionToken extracts and verifies the primary session token cookie from an incoming HTTP request.
func (p *Plugin) ExtractMainSessionToken(r *http.Request) string {
	if r == nil {
		return ""
	}
	mainCookieNames := []string{
		p.config.CookiePrefix + ".session_token",
		p.config.CookiePrefix + "_session_token",
		"session_token",
	}
	for _, name := range mainCookieNames {
		if c, err := r.Cookie(name); err == nil && c.Value != "" {
			val, err := VerifyCookieValue(c.Value, p.config.Secret)
			if err == nil && val != "" {
				return val
			}
		}
	}
	return ""
}

// GetMultiCookieName formats and sanitizes the multi-session cookie name for a given token string.
func (p *Plugin) GetMultiCookieName(token string) string {
	sanitizedToken := invalidCookieNameChars.ReplaceAllString(token, "_")
	return fmt.Sprintf("%s_multi-%s", p.config.CookiePrefix, strings.ToLower(sanitizedToken))
}

// SetMainSessionCookie writes the primary signed session cookie to an HTTP response.
func (p *Plugin) SetMainSessionCookie(w http.ResponseWriter, token string, expiresAt time.Time) {
	if w == nil {
		return
	}
	cookieName := p.config.CookiePrefix + ".session_token"
	signedVal := SignCookieValue(token, p.config.Secret)
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    signedVal,
		Path:     "/",
		Expires:  expiresAt,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// ExpireMainSessionCookie marks the primary session cookie for immediate expiration in an HTTP response.
func (p *Plugin) ExpireMainSessionCookie(w http.ResponseWriter) {
	if w == nil {
		return
	}
	cookieName := p.config.CookiePrefix + ".session_token"
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
	})
}

// SetMultiSessionCookie writes a signed multi-session cookie to an HTTP response.
func (p *Plugin) SetMultiSessionCookie(w http.ResponseWriter, token string, expiresAt time.Time) {
	if w == nil {
		return
	}
	cookieName := p.GetMultiCookieName(token)
	signedVal := SignCookieValue(token, p.config.Secret)
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    signedVal,
		Path:     "/",
		Expires:  expiresAt,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// ExpireCookie marks a specified cookie name for immediate expiration in an HTTP response.
func (p *Plugin) ExpireCookie(w http.ResponseWriter, cookieName string) {
	if w == nil {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
	})
}
