package saml

import (
	"time"
)

// Config holds runtime configuration settings for the SAML plugin.
type Config struct {
	SPEntityID       string
	SPACSURL         string
	SPSLOURL         string
	SPCertificatePEM string
	SPPrivateKeyPEM  string
	RequestTTL       time.Duration
	Clock            func() time.Time
	AutoProvision    bool
}

// Option configures Config.
type Option func(*Config)

func newConfig(opts ...Option) Config {
	c := Config{
		SPEntityID:    "urn:gomodularauth:saml:sp",
		SPACSURL:      "/saml/acs",
		RequestTTL:    5 * time.Minute,
		Clock:         func() time.Time { return time.Now().UTC() },
		AutoProvision: true,
	}
	for _, opt := range opts {
		opt(&c)
	}
	return c
}

// WithSPEntityID sets the canonical Entity ID of this Service Provider.
func WithSPEntityID(entityID string) Option {
	return func(c *Config) {
		if entityID != "" {
			c.SPEntityID = entityID
		}
	}
}

// WithSPACSURL sets the Assertion Consumer Service callback URL.
func WithSPACSURL(acsURL string) Option {
	return func(c *Config) {
		if acsURL != "" {
			c.SPACSURL = acsURL
		}
	}
}

// WithSPSLOURL sets the Single Logout Service endpoint.
func WithSPSLOURL(sloURL string) Option {
	return func(c *Config) {
		c.SPSLOURL = sloURL
	}
}

// WithSPCertificate sets the PEM-encoded public X.509 certificate and private key for this SP.
func WithSPCertificate(certPEM, keyPEM string) Option {
	return func(c *Config) {
		c.SPCertificatePEM = certPEM
		c.SPPrivateKeyPEM = keyPEM
	}
}

// WithRequestTTL configures how long in-flight AuthnRequests remain valid.
func WithRequestTTL(d time.Duration) Option {
	return func(c *Config) {
		if d > 0 {
			c.RequestTTL = d
		}
	}
}

// WithClock sets a custom clock provider for testing.
func WithClock(clock func() time.Time) Option {
	return func(c *Config) {
		if clock != nil {
			c.Clock = clock
		}
	}
}

// WithAutoProvision controls whether unlinked users are automatically provisioned in Core.
func WithAutoProvision(enabled bool) Option {
	return func(c *Config) {
		c.AutoProvision = enabled
	}
}
