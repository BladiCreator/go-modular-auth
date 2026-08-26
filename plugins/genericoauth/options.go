package genericoauth

import (
	"net/http"
	"time"
)

// Option defines a functional option for configuring the Generic OAuth plugin.
type Option func(*Config)

// DefaultConfig returns reasonable default configuration values.
func DefaultConfig() Config {
	return Config{
		Providers:  make(map[string]*ProviderConfig),
		HTTPClient: http.DefaultClient,
		StateTTL:   10 * time.Minute,
		CookieConfig: CookieConfig{
			Name:     "oauth_state",
			Path:     "/",
			Secure:   true,
			HTTPOnly: true,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   10 * time.Minute,
		},
	}
}

// WithProvider registers a provider configuration in the plugin.
func WithProvider(cfg *ProviderConfig) Option {
	return func(c *Config) {
		if c.Providers == nil {
			c.Providers = make(map[string]*ProviderConfig)
		}
		if cfg != nil && cfg.ProviderID != "" {
			c.Providers[cfg.ProviderID] = cfg
		}
	}
}

// WithHTTPClient overrides the default HTTP client used for discovery, token exchange, and user info calls.
func WithHTTPClient(client *http.Client) Option {
	return func(c *Config) {
		if client != nil {
			c.HTTPClient = client
		}
	}
}

// WithCookieConfig sets custom cookie options for state and PKCE tracking.
func WithCookieConfig(cfg CookieConfig) Option {
	return func(c *Config) {
		c.CookieConfig = cfg
	}
}

// WithStateTTL sets the maximum lifetime for OAuth state and PKCE verifier tokens.
func WithStateTTL(ttl time.Duration) Option {
	return func(c *Config) {
		if ttl > 0 {
			c.StateTTL = ttl
		}
	}
}
