package sso

import (
	"net/http"
	"time"

	"github.com/BladiCreator/go-modular-auth-organizations"
)

// HTTPClient abstracts outbound HTTP request execution. It is satisfied by *http.Client.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// Config holds runtime configuration options for the SSO plugin.
type Config struct {
	StateTTL      time.Duration
	Clock         func() time.Time
	HTTPClient    HTTPClient
	SPEntityID    string
	SPACSURL      string
	Organizations organizations.Organization
}

// Option modifies Config.
type Option func(*Config)

func newConfig(opts ...Option) Config {
	c := Config{
		StateTTL:   10 * time.Minute,
		Clock:      func() time.Time { return time.Now().UTC() },
		HTTPClient: &http.Client{Timeout: 10 * time.Second},
		SPEntityID: "urn:gomodularauth:sp",
		SPACSURL:   "/sso/saml/acs",
	}
	for _, opt := range opts {
		opt(&c)
	}
	return c
}

// WithStateTTL configures how long in-flight SSO state sessions remain valid.
func WithStateTTL(d time.Duration) Option {
	return func(c *Config) {
		if d > 0 {
			c.StateTTL = d
		}
	}
}

// WithClock sets a custom time provider for deterministic testing.
func WithClock(clock func() time.Time) Option {
	return func(c *Config) {
		if clock != nil {
			c.Clock = clock
		}
	}
}

// WithHTTPClient configures the HTTP client used for OIDC Discovery and token exchange.
func WithHTTPClient(client HTTPClient) Option {
	return func(c *Config) {
		if client != nil {
			c.HTTPClient = client
		}
	}
}

// WithSPEntityID sets the Service Provider Entity ID used for SAML Audience restrictions.
func WithSPEntityID(entityID string) Option {
	return func(c *Config) {
		if entityID != "" {
			c.SPEntityID = entityID
		}
	}
}

// WithSPACSURL sets the Assertion Consumer Service URL for SAML requests.
func WithSPACSURL(acsURL string) Option {
	return func(c *Config) {
		if acsURL != "" {
			c.SPACSURL = acsURL
		}
	}
}

// WithOrganizations configures optional integration with the Organizations plugin for JIT membership assignment.
func WithOrganizations(orgs organizations.Organization) Option {
	return func(c *Config) {
		c.Organizations = orgs
	}
}
