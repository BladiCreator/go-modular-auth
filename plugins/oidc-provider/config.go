package oidcprovider

import (
	"crypto/rand"
	"crypto/rsa"
	"time"

	"github.com/BladiCreator/go-modular-auth-oidc-provider/discovery"
)

type Config struct {
	Issuer     string
	PrivateKey *rsa.PrivateKey
	KeyID      string
	DefaultTTL time.Duration
	Discovery  *discovery.Document
}

type Option func(*Config)

func WithIssuer(issuer string) Option {
	return func(c *Config) {
		c.Issuer = issuer
	}
}

func WithPrivateKey(pk *rsa.PrivateKey, kid string) Option {
	return func(c *Config) {
		c.PrivateKey = pk
		c.KeyID = kid
	}
}

func WithDefaultTTL(ttl time.Duration) Option {
	return func(c *Config) {
		c.DefaultTTL = ttl
	}
}

func (c Config) withDefaults() Config {
	if c.Issuer == "" {
		c.Issuer = "http://localhost:8080"
	}
	if c.DefaultTTL <= 0 {
		c.DefaultTTL = 1 * time.Hour
	}
	if c.KeyID == "" {
		c.KeyID = "default-key"
	}
	if c.PrivateKey == nil {
		pk, err := rsa.GenerateKey(rand.Reader, 2048)
		if err == nil {
			c.PrivateKey = pk
		}
	}
	if c.Discovery == nil {
		c.Discovery = discovery.DefaultDocument(c.Issuer)
	}
	return c
}
