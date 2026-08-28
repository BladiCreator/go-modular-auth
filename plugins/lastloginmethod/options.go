package lastloginmethod

import (
	"net/http"
	"time"
)

// DefaultCookieName is the standard cookie key used by modular-auth to track the last login method.
const DefaultCookieName = "modular-auth.last_used_login_method"

// DefaultMaxAge defines the default cookie expiration duration (30 days).
const DefaultMaxAge = 30 * 24 * time.Hour

// Config defines the configuration parameters for the LastLoginMethod plugin.
type Config struct {
	// CookieName specifies the key for storing the last used login method cookie.
	// Default: "modular-auth.last_used_login_method"
	CookieName string

	// MaxAge specifies the cookie duration.
	// Default: 30 days
	MaxAge time.Duration

	// Domain specifies the cookie domain.
	Domain string

	// Path specifies the cookie path. Default: "/"
	Path string

	// SameSite specifies the cookie SameSite attribute. Default: http.SameSiteLaxMode
	SameSite http.SameSite

	// Secure specifies whether the cookie requires HTTPS. Default: false
	Secure bool

	// StoreInDatabase specifies whether the resolved login method should also be persisted in the DB via Repository.
	// Default: false
	StoreInDatabase bool

	// CustomRoutes specifies custom path-to-method mappings (e.g. "/auth/sso/callback" -> "saml").
	CustomRoutes map[string]string

	// DisableDefaultRoutes specifies whether built-in route heuristics should be disabled.
	DisableDefaultRoutes bool

	// CustomResolver is an optional custom resolver function for inferring login methods from requests.
	CustomResolver ResolveMethodFunc

	// BeforeStoreCookie is an optional GDPR consent check callback before issuing the cookie.
	BeforeStoreCookie BeforeStoreCookieFunc
}

// DefaultConfig returns a Config struct initialized with recommended defaults.
func DefaultConfig() Config {
	return Config{
		CookieName:           DefaultCookieName,
		MaxAge:               DefaultMaxAge,
		Path:                 "/",
		SameSite:             http.SameSiteLaxMode,
		Secure:               false,
		StoreInDatabase:      false,
		CustomRoutes:         make(map[string]string),
		DisableDefaultRoutes: false,
		CustomResolver:       nil,
		BeforeStoreCookie:    nil,
	}
}

// Option defines a functional option type for configuring the plugin.
type Option func(*Config)

// WithCookieName sets a custom cookie name for tracking last login method.
func WithCookieName(name string) Option {
	return func(c *Config) {
		if name != "" {
			c.CookieName = name
		}
	}
}

// WithMaxAge sets a custom cookie duration.
func WithMaxAge(d time.Duration) Option {
	return func(c *Config) {
		c.MaxAge = d
	}
}

// WithCookieAttributes sets cookie domain, path, SameSite, and Secure flags.
func WithCookieAttributes(domain, path string, sameSite http.SameSite, secure bool) Option {
	return func(c *Config) {
		c.Domain = domain
		if path != "" {
			c.Path = path
		}
		c.SameSite = sameSite
		c.Secure = secure
	}
}

// WithStoreInDatabase enables or disables DB persistence of last_login_method.
func WithStoreInDatabase(store bool) Option {
	return func(c *Config) {
		c.StoreInDatabase = store
	}
}

// WithRouteMapping adds or overrides a custom path pattern to authentication method mapping.
func WithRouteMapping(pathPattern, method string) Option {
	return func(c *Config) {
		if c.CustomRoutes == nil {
			c.CustomRoutes = make(map[string]string)
		}
		if pathPattern != "" && method != "" {
			c.CustomRoutes[pathPattern] = method
		}
	}
}

// WithRouteMappings sets a batch of custom path pattern to authentication method mappings.
func WithRouteMappings(routes map[string]string) Option {
	return func(c *Config) {
		if c.CustomRoutes == nil {
			c.CustomRoutes = make(map[string]string)
		}
		for pathPattern, method := range routes {
			if pathPattern != "" && method != "" {
				c.CustomRoutes[pathPattern] = method
			}
		}
	}
}

// WithDisableDefaultRoutes configures whether built-in route heuristics are disabled.
func WithDisableDefaultRoutes(disable bool) Option {
	return func(c *Config) {
		c.DisableDefaultRoutes = disable
	}
}

// WithCustomResolver configures a custom method resolver callback.
func WithCustomResolver(fn ResolveMethodFunc) Option {
	return func(c *Config) {
		c.CustomResolver = fn
	}
}

// WithBeforeStoreCookie configures a GDPR consent check callback before storing the cookie.
func WithBeforeStoreCookie(fn BeforeStoreCookieFunc) Option {
	return func(c *Config) {
		c.BeforeStoreCookie = fn
	}
}
