package httpauth

import (
	"net/http"
	"time"
)

// Default cookie configuration constants.
const (
	DefaultSessionCookieName = "auth_session"
	DefaultCookiePath        = "/"
)

// CookieConfig holds configurable attributes applied when emitting or clearing session cookies.
type CookieConfig struct {
	// Name specifies the cookie name. Defaults to "auth_session".
	Name string
	// Path defines the URL path that must exist in the requested URL for the cookie to be sent. Defaults to "/".
	Path string
	// Domain specifies which hosts can receive the cookie. Defaults to empty (current host only).
	Domain string
	// Secure specifies whether the cookie should only be transmitted over HTTPS. Defaults to true.
	Secure bool
	// HTTPOnly specifies whether the cookie is inaccessible to client-side scripts. Defaults to true.
	HTTPOnly bool
	// SameSite controls cross-site request behavior. Defaults to http.SameSiteLaxMode.
	SameSite http.SameSite
	// Partitioned specifies whether the cookie should be stored using partitioned storage (CHIPS).
	Partitioned bool
}

// DefaultCookieConfig returns the production-safe default cookie settings.
func DefaultCookieConfig() CookieConfig {
	return CookieConfig{
		Name:        DefaultSessionCookieName,
		Path:        DefaultCookiePath,
		Domain:      "",
		Secure:      true,
		HTTPOnly:    true,
		SameSite:    http.SameSiteLaxMode,
		Partitioned: false,
	}
}

// CookieOption represents a functional option for customizing cookie attributes.
type CookieOption func(*CookieConfig)

// WithCookieName overrides the session cookie name.
func WithCookieName(name string) CookieOption {
	return func(c *CookieConfig) {
		if name != "" {
			c.Name = name
		}
	}
}

// WithPath sets the Path attribute on the session cookie.
func WithPath(path string) CookieOption {
	return func(c *CookieConfig) {
		c.Path = path
	}
}

// WithDomain sets the Domain attribute on the session cookie.
func WithDomain(domain string) CookieOption {
	return func(c *CookieConfig) {
		c.Domain = domain
	}
}

// WithSecure controls whether the Secure flag is enabled on the session cookie.
func WithSecure(secure bool) CookieOption {
	return func(c *CookieConfig) {
		c.Secure = secure
	}
}

// WithHTTPOnly controls whether the HttpOnly flag is enabled on the session cookie.
func WithHTTPOnly(httpOnly bool) CookieOption {
	return func(c *CookieConfig) {
		c.HTTPOnly = httpOnly
	}
}

// WithSameSite sets the SameSite policy on the session cookie.
func WithSameSite(sameSite http.SameSite) CookieOption {
	return func(c *CookieConfig) {
		c.SameSite = sameSite
	}
}

// WithPartitioned controls the Partitioned attribute (CHIPS) on the session cookie.
func WithPartitioned(partitioned bool) CookieOption {
	return func(c *CookieConfig) {
		c.Partitioned = partitioned
	}
}

// SetSessionCookie sets a secure HTTP-only cookie with the provided session token and expiration.
// It applies safe defaults (HttpOnly, Secure, SameSite=Lax, Path="/") which can be customized via opts.
func SetSessionCookie(w http.ResponseWriter, token string, expires time.Time, opts ...CookieOption) {
	if w == nil {
		return
	}

	cfg := DefaultCookieConfig()
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}

	maxAge := 0
	if !expires.IsZero() {
		remaining := time.Until(expires)
		if remaining <= 0 {
			maxAge = -1
		} else {
			maxAge = int(remaining.Seconds())
		}
	}

	cookie := &http.Cookie{
		Name:        cfg.Name,
		Value:       token,
		Path:        cfg.Path,
		Domain:      cfg.Domain,
		Expires:     expires,
		MaxAge:      maxAge,
		Secure:      cfg.Secure,
		HttpOnly:    cfg.HTTPOnly,
		SameSite:    cfg.SameSite,
		Partitioned: cfg.Partitioned,
	}

	http.SetCookie(w, cookie)
}

// ClearSessionCookie clears the active session cookie by setting its value to empty and MaxAge to -1.
func ClearSessionCookie(w http.ResponseWriter, opts ...CookieOption) {
	if w == nil {
		return
	}

	cfg := DefaultCookieConfig()
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}

	cookie := &http.Cookie{
		Name:        cfg.Name,
		Value:       "",
		Path:        cfg.Path,
		Domain:      cfg.Domain,
		Expires:     time.Unix(0, 0),
		MaxAge:      -1,
		Secure:      cfg.Secure,
		HttpOnly:    cfg.HTTPOnly,
		SameSite:    cfg.SameSite,
		Partitioned: cfg.Partitioned,
	}

	http.SetCookie(w, cookie)
}
