package oidcprovider

import (
	"context"
	"crypto/rsa"
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/entity"
)

// AdditionalClaimsFunc defines a custom callback to append custom claims to ID Tokens or UserInfo responses.
type AdditionalClaimsFunc func(ctx context.Context, user *entity.User, scopes []string, client *OAuthClient) map[string]any

// Config holds configuration settings for the OIDC Provider plugin.
type Config struct {
	Issuer                         string
	BaseURL                        string
	AccessTokenExpiresIn           time.Duration
	RefreshTokenExpiresIn          time.Duration
	CodeExpiresIn                  time.Duration
	SupportedScopes                []string
	DefaultScope                   string
	RequirePKCE                    bool
	AllowPlainCodeChallenge        bool
	AllowDynamicClientRegistration bool
	StoreClientSecretMode          SecretStoreMode
	SigningAlgorithm               string // "RS256" or "HS256"
	PrivateKey                     *rsa.PrivateKey
	SecretKey                      []byte
	ConsentPageURL                 *string
	LoginPageURL                   string
	GetAdditionalClaims            AdditionalClaimsFunc
}

// DefaultConfig returns a Config struct pre-populated with standard OIDC defaults.
func DefaultConfig() Config {
	return Config{
		Issuer:                  "http://localhost:8080",
		BaseURL:                 "http://localhost:8080",
		AccessTokenExpiresIn:    1 * time.Hour,
		RefreshTokenExpiresIn:   7 * 24 * time.Hour,
		CodeExpiresIn:           10 * time.Minute,
		SupportedScopes:         []string{"openid", "profile", "email", "offline_access"},
		DefaultScope:            "openid",
		RequirePKCE:             true,
		AllowPlainCodeChallenge: false,
		StoreClientSecretMode:   SecretStorePlain,
		SigningAlgorithm:        "HS256",
		LoginPageURL:            "/login",
	}
}

// Option represents a functional option for configuring the OIDC Provider plugin.
type Option func(*Config)

// WithIssuer sets the OIDC issuer identifier URL (e.g. "https://auth.example.com").
func WithIssuer(issuer string) Option {
	return func(c *Config) {
		if issuer != "" {
			c.Issuer = issuer
		}
	}
}

// WithBaseURL sets the base URL used to construct endpoint paths.
func WithBaseURL(url string) Option {
	return func(c *Config) {
		if url != "" {
			c.BaseURL = url
		}
	}
}

// WithTokenExpirations sets access token, refresh token, and authorization code expiration durations.
func WithTokenExpirations(access, refresh, code time.Duration) Option {
	return func(c *Config) {
		if access > 0 {
			c.AccessTokenExpiresIn = access
		}
		if refresh > 0 {
			c.RefreshTokenExpiresIn = refresh
		}
		if code > 0 {
			c.CodeExpiresIn = code
		}
	}
}

// WithSupportedScopes sets the list of supported OIDC scopes.
func WithSupportedScopes(scopes []string) Option {
	return func(c *Config) {
		if len(scopes) > 0 {
			c.SupportedScopes = scopes
		}
	}
}

// WithRequirePKCE enforces PKCE (RFC 7636) for authorization code grant requests.
func WithRequirePKCE(require bool) Option {
	return func(c *Config) {
		c.RequirePKCE = require
	}
}

// WithAllowPlainCodeChallenge enables plain code_challenge_method in PKCE (not recommended).
func WithAllowPlainCodeChallenge(allow bool) Option {
	return func(c *Config) {
		c.AllowPlainCodeChallenge = allow
	}
}

// WithRSAKeys configures an RSA private key for RS256 ID Token signing and JWKS export.
func WithRSAKeys(privateKey *rsa.PrivateKey) Option {
	return func(c *Config) {
		if privateKey != nil {
			c.PrivateKey = privateKey
			c.SigningAlgorithm = "RS256"
		}
	}
}

// WithSecretKey configures a shared secret key for HS256 ID Token signing.
func WithSecretKey(secret []byte) Option {
	return func(c *Config) {
		if len(secret) > 0 {
			c.SecretKey = secret
			c.SigningAlgorithm = "HS256"
		}
	}
}

// WithStoreClientSecretMode sets how client_secret values are stored and compared.
func WithStoreClientSecretMode(mode SecretStoreMode) Option {
	return func(c *Config) {
		c.StoreClientSecretMode = mode
	}
}

// WithConsentPageURL sets the URL of the consent UI page.
func WithConsentPageURL(url string) Option {
	return func(c *Config) {
		c.ConsentPageURL = &url
	}
}

// WithLoginPageURL sets the login redirect URL.
func WithLoginPageURL(url string) Option {
	return func(c *Config) {
		if url != "" {
			c.LoginPageURL = url
		}
	}
}

// WithAdditionalClaims registers a callback to inject custom claims into UserInfo and ID Tokens.
func WithAdditionalClaims(fn AdditionalClaimsFunc) Option {
	return func(c *Config) {
		c.GetAdditionalClaims = fn
	}
}
