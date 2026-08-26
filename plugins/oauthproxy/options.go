package oauthproxy

import (
	"net/http"
	"time"
)

// Option applies a configuration setting to Config.
type Option func(*Config)

// DefaultConfig returns the default OAuth Proxy configuration.
func DefaultConfig() Config {
	return Config{
		MaxAge:            60 * time.Second,
		ProxyCallbackPath: "/api/auth/oauth-proxy-callback",
		SkipProxyHeader:   "X-Skip-OAuth-Proxy",
	}
}

// WithCurrentURL configures the explicit preview deployment URL.
func WithCurrentURL(rawURL string) Option {
	return func(c *Config) {
		c.CurrentURL = rawURL
	}
}

// WithProductionURL configures the production server base URL.
func WithProductionURL(rawURL string) Option {
	return func(c *Config) {
		c.ProductionURL = rawURL
	}
}

// WithSecret configures the shared secret key used for AES-256-GCM encryption.
func WithSecret(secret string) Option {
	return func(c *Config) {
		c.Secret = secret
	}
}

// WithMaxAge configures the maximum allowed age for passthrough payloads before expiration.
func WithMaxAge(d time.Duration) Option {
	return func(c *Config) {
		c.MaxAge = d
	}
}

// WithProxyCallbackPath configures the HTTP endpoint path on the preview server for proxy callbacks.
func WithProxyCallbackPath(path string) Option {
	return func(c *Config) {
		c.ProxyCallbackPath = path
	}
}

// WithSkipProxyHeader configures the HTTP header name used to bypass proxy routing.
func WithSkipProxyHeader(header string) Option {
	return func(c *Config) {
		c.SkipProxyHeader = header
	}
}

// WithOnSuccess configures an optional success hook invoked upon receiving a valid payload on preview.
func WithOnSuccess(fn func(w http.ResponseWriter, r *http.Request, payload *PassthroughPayload) error) Option {
	return func(c *Config) {
		c.OnSuccess = fn
	}
}
