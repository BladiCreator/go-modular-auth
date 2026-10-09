package oauthprovider

import (
	"time"

	"github.com/BladiCreator/go-modular-auth-oauth-provider/store"
	"github.com/BladiCreator/go-modular-auth-oauth-provider/store/memory"
)

// Config holds configuration parameters for the OAuth 2.1 Provider plugin.
type Config struct {
	// Store is the persistence store adapter. If nil, memory.New() is used.
	Store store.Store

	// Issuer is the canonical authorization server identifier URL (e.g. "https://auth.example.com").
	Issuer string

	// AuthorizationCodeTTL is the maximum lifetime of an authorization code (default: 5 minutes).
	AuthorizationCodeTTL time.Duration

	// AccessTokenTTL is the lifetime of an issued access token (default: 1 hour).
	AccessTokenTTL time.Duration

	// RefreshTokenTTL is the lifetime of an issued refresh token (default: 30 days).
	RefreshTokenTTL time.Duration

	// RequirePKCEForPublicClients enforces PKCE for public clients (default: true).
	RequirePKCEForPublicClients bool

	// AllowPlainPKCE allows the plain code_challenge_method (default: false; rejected in OAuth 2.1).
	AllowPlainPKCE bool

	// RotateRefreshTokens issues a new refresh token and revokes the old one upon token refresh (default: true).
	RotateRefreshTokens bool
}

// Option configures the OAuth 2.1 Provider plugin.
type Option func(*Config)

// WithStore sets the persistence store adapter.
func WithStore(s store.Store) Option {
	return func(c *Config) {
		c.Store = s
	}
}

// WithIssuer sets the authorization server issuer URL.
func WithIssuer(issuer string) Option {
	return func(c *Config) {
		c.Issuer = issuer
	}
}

// WithAuthorizationCodeTTL sets the lifetime of authorization codes.
func WithAuthorizationCodeTTL(ttl time.Duration) Option {
	return func(c *Config) {
		c.AuthorizationCodeTTL = ttl
	}
}

// WithAccessTokenTTL sets the lifetime of access tokens.
func WithAccessTokenTTL(ttl time.Duration) Option {
	return func(c *Config) {
		c.AccessTokenTTL = ttl
	}
}

// WithRefreshTokenTTL sets the lifetime of refresh tokens.
func WithRefreshTokenTTL(ttl time.Duration) Option {
	return func(c *Config) {
		c.RefreshTokenTTL = ttl
	}
}

// WithRequirePKCE enforces or relaxes PKCE requirement for public clients.
func WithRequirePKCE(require bool) Option {
	return func(c *Config) {
		c.RequirePKCEForPublicClients = require
	}
}

// WithRotateRefreshTokens configures refresh token rotation.
func WithRotateRefreshTokens(rotate bool) Option {
	return func(c *Config) {
		c.RotateRefreshTokens = rotate
	}
}

func (c Config) withDefaults() Config {
	if c.Store == nil {
		c.Store = memory.New()
	}
	if c.AuthorizationCodeTTL <= 0 {
		c.AuthorizationCodeTTL = 5 * time.Minute
	}
	if c.AccessTokenTTL <= 0 {
		c.AccessTokenTTL = 1 * time.Hour
	}
	if c.RefreshTokenTTL <= 0 {
		c.RefreshTokenTTL = 30 * 24 * time.Hour
	}
	// By default, PKCE is strictly required for public clients per OAuth 2.1
	c.RequirePKCEForPublicClients = true
	// By default, refresh tokens are rotated on each use
	c.RotateRefreshTokens = true

	return c
}
