package oidc

import (
	"net/http"
	"time"
)

// HTTPClient abstracts outbound HTTP request execution. It is satisfied by *http.Client.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// Config holds the configuration settings for the OIDC plugin.
type Config struct {
	Providers     map[string]ProviderConfig
	StateTTL      time.Duration
	LinkingPolicy LinkingPolicy
	HTTPClient    HTTPClient
	Clock         func() time.Time
}

func defaultConfig() Config {
	return Config{
		Providers:     make(map[string]ProviderConfig),
		StateTTL:      15 * time.Minute,
		LinkingPolicy: LinkingPolicyVerifiedEmail,
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		Clock: time.Now,
	}
}

// Option modifies Config settings.
type Option func(*Config)

// WithProvider registers an OpenID Connect Relying Party identity provider configuration.
func WithProvider(p ProviderConfig) Option {
	return func(c *Config) {
		if c.Providers == nil {
			c.Providers = make(map[string]ProviderConfig)
		}
		if len(p.Scopes) == 0 {
			p.Scopes = []string{"openid", "profile", "email"}
		}
		c.Providers[p.ID] = p
	}
}

// WithStateTTL sets the validity window of authentication state tokens.
func WithStateTTL(ttl time.Duration) Option {
	return func(c *Config) {
		if ttl > 0 {
			c.StateTTL = ttl
		}
	}
}

// WithLinkingPolicy configures account linking rules on email collision.
func WithLinkingPolicy(policy LinkingPolicy) Option {
	return func(c *Config) {
		c.LinkingPolicy = policy
	}
}

// WithHTTPClient overrides the default HTTP client used for discovery, token exchange, and JWKS fetching.
func WithHTTPClient(client HTTPClient) Option {
	return func(c *Config) {
		if client != nil {
			c.HTTPClient = client
		}
	}
}

// WithClock overrides the system clock for testing.
func WithClock(clk func() time.Time) Option {
	return func(c *Config) {
		if clk != nil {
			c.Clock = clk
		}
	}
}
