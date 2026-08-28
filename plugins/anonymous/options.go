package anonymous

import (
	"net/http"
	"time"
)

const (
	// DefaultEmailDomain is the default domain name used when constructing temporary anonymous emails.
	DefaultEmailDomain = "anonymous.local"

	// DefaultCookieName is the standard session cookie key.
	DefaultCookieName = "better-auth.session_token"

	// DefaultCookieMaxAge specifies the default cookie duration (30 days).
	DefaultCookieMaxAge = 30 * 24 * time.Hour
)

// Config defines configuration parameters for the Anonymous plugin.
type Config struct {
	// EmailDomainName specifies the domain used for generated anonymous email addresses (e.g. temp-{uuid}@anonymous.local).
	// Default: "anonymous.local"
	EmailDomainName string

	// DisableDeleteAnonymousUser specifies whether automatic deletion of anonymous accounts after linking should be disabled.
	// Default: false
	DisableDeleteAnonymousUser bool

	// OnLinkAccount is a callback function invoked when a guest user links their account to a permanent user.
	OnLinkAccount LinkAccountCallback

	// GenerateName is a custom callback to generate anonymous user names. If nil, defaults to "Anonymous".
	GenerateName GenerateNameCallback

	// GenerateRandomEmail is a custom callback to generate anonymous email addresses. If nil, defaults to "temp-{uuid}@" + EmailDomainName.
	GenerateRandomEmail GenerateEmailCallback

	// CookieName specifies the session cookie key name.
	CookieName string

	// CookiePath specifies the HTTP cookie path scope. Default: "/"
	CookiePath string

	// CookieDomain specifies the HTTP cookie domain scope.
	CookieDomain string

	// CookieMaxAge specifies the session cookie duration. Default: 30 days.
	CookieMaxAge time.Duration

	// CookieSecure specifies whether the session cookie requires HTTPS. Default: false.
	CookieSecure bool

	// CookieSameSite specifies the SameSite attribute for session cookies. Default: http.SameSiteLaxMode.
	CookieSameSite http.SameSite
}

// DefaultConfig returns a Config struct initialized with recommended defaults.
func DefaultConfig() Config {
	return Config{
		EmailDomainName:            DefaultEmailDomain,
		DisableDeleteAnonymousUser: false,
		OnLinkAccount:              nil,
		GenerateName:               nil,
		GenerateRandomEmail:        nil,
		CookieName:                 DefaultCookieName,
		CookiePath:                 "/",
		CookieDomain:               "",
		CookieMaxAge:               DefaultCookieMaxAge,
		CookieSecure:               false,
		CookieSameSite:             http.SameSiteLaxMode,
	}
}

// Option defines a functional option type for configuring the Anonymous plugin.
type Option func(*Config)

// WithEmailDomainName sets a custom domain for generated anonymous emails (e.g. "guest.app.com").
func WithEmailDomainName(domain string) Option {
	return func(c *Config) {
		if domain != "" {
			c.EmailDomainName = domain
		}
	}
}

// WithDisableDeleteAnonymousUser toggles whether anonymous users should remain in storage after account linking.
func WithDisableDeleteAnonymousUser(disable bool) Option {
	return func(c *Config) {
		c.DisableDeleteAnonymousUser = disable
	}
}

// WithOnLinkAccount sets a custom callback function for account linking and data migration.
func WithOnLinkAccount(fn LinkAccountCallback) Option {
	return func(c *Config) {
		c.OnLinkAccount = fn
	}
}

// WithGenerateName sets a custom function to generate display names for anonymous users.
func WithGenerateName(fn GenerateNameCallback) Option {
	return func(c *Config) {
		c.GenerateName = fn
	}
}

// WithGenerateRandomEmail sets a custom function to generate email addresses for anonymous users.
func WithGenerateRandomEmail(fn GenerateEmailCallback) Option {
	return func(c *Config) {
		c.GenerateRandomEmail = fn
	}
}

// WithCookieName sets a custom cookie name for session cookies.
func WithCookieName(name string) Option {
	return func(c *Config) {
		if name != "" {
			c.CookieName = name
		}
	}
}

// WithCookieMaxAge sets a custom duration for session cookies.
func WithCookieMaxAge(d time.Duration) Option {
	return func(c *Config) {
		c.CookieMaxAge = d
	}
}

// WithCookieAttributes sets session cookie domain, path, SameSite, and Secure flags.
func WithCookieAttributes(domain, path string, sameSite http.SameSite, secure bool) Option {
	return func(c *Config) {
		c.CookieDomain = domain
		if path != "" {
			c.CookiePath = path
		}
		c.CookieSameSite = sameSite
		c.CookieSecure = secure
	}
}
