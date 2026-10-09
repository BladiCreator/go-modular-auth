package samlprovider

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"time"
)

type Config struct {
	EntityID    string
	SSOURL      string
	PrivateKey  *rsa.PrivateKey
	Certificate string // base64 DER
}

type Option func(*Config)

func WithEntityID(entityID string) Option {
	return func(c *Config) {
		c.EntityID = entityID
	}
}

func WithSSOURL(ssoURL string) Option {
	return func(c *Config) {
		c.SSOURL = ssoURL
	}
}

func WithSigningKey(pk *rsa.PrivateKey, certBase64 string) Option {
	return func(c *Config) {
		c.PrivateKey = pk
		c.Certificate = certBase64
	}
}

func (c Config) withDefaults() Config {
	if c.EntityID == "" {
		c.EntityID = "https://auth.example.com/saml/idp"
	}
	if c.SSOURL == "" {
		c.SSOURL = "https://auth.example.com/saml/sso"
	}
	if c.PrivateKey == nil {
		pk, err := rsa.GenerateKey(rand.Reader, 2048)
		if err == nil {
			c.PrivateKey = pk

			template := x509.Certificate{
				SerialNumber: big.NewInt(1),
				Subject: pkix.Name{
					CommonName: "go-modular-auth SAML IdP",
				},
				NotBefore: time.Now().Add(-1 * time.Hour),
				NotAfter:  time.Now().Add(365 * 24 * time.Hour),
				KeyUsage:  x509.KeyUsageDigitalSignature,
			}
			certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &pk.PublicKey, pk)
			if err == nil {
				c.Certificate = base64.StdEncoding.EncodeToString(certDER)
			}
		}
	}
	return c
}
