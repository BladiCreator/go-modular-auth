package oauth2

import (
	"context"
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/entity"
)

// CustomClaimsFunc allows injecting additional custom claims into tokens or UserInfo responses.
type CustomClaimsFunc func(ctx context.Context, client *OAuthClient, user *entity.User, scopes []string) (map[string]any, error)

// Config defines the configuration options for the OAuth 2.1 and OpenID Connect Provider plugin.
type Config struct {
	// Issuer is the base URL of the authorization server ("iss" claim in tokens and discovery).
	Issuer string

	// LoginPage is the relative or absolute path of the user login UI page for interactive redirection.
	LoginPage string

	// ConsentPage is the relative or absolute path of the user consent UI page for interactive redirection.
	ConsentPage string

	// Scopes is the list of supported scopes announced by the authorization server.
	Scopes []string

	// GrantTypes is the list of OAuth 2.1 grant types enabled on this server.
	GrantTypes []GrantType

	// AccessTokenType specifies whether Access Tokens are issued as RFC 9068 JWTs or opaque tokens.
	AccessTokenType AccessTokenType

	// CodeExpiresIn is the validity duration of single-use authorization codes (default: 10m).
	CodeExpiresIn time.Duration

	// AccessTokenExpiresIn is the validity duration of user access tokens (default: 1h).
	AccessTokenExpiresIn time.Duration

	// RefreshTokenExpiresIn is the validity duration of refresh tokens (default: 30 days).
	RefreshTokenExpiresIn time.Duration

	// IDTokenExpiresIn is the validity duration of OpenID Connect ID Tokens (default: 1h).
	IDTokenExpiresIn time.Duration

	// M2MAccessTokenExpiresIn is the validity duration of client_credentials access tokens (default: 2h).
	M2MAccessTokenExpiresIn time.Duration

	// AllowDynamicClientRegistration enables RFC 7591 Dynamic Client Registration endpoint.
	AllowDynamicClientRegistration bool

	// AllowUnauthenticatedClientRegistration allows client registration without an initial access token.
	AllowUnauthenticatedClientRegistration bool

	// StoreClientSecretMode defines how client secrets are persisted ("plain", "hashed", "encrypted").
	StoreClientSecretMode StoreMode

	// StoreTokensMode defines how tokens are persisted ("plain", "hashed", "encrypted").
	StoreTokensMode StoreMode

	// SecretKey is the master cryptographic key used for symmetric AES-256-GCM encryption and HMAC query signing.
	SecretKey string

	// PairwiseSecret is the cryptographic salt used to compute pairwise pseudonymous subjects.
	PairwiseSecret string

	// ValidAudiences is the list of accepted audiences for validation.
	ValidAudiences []string

	// JWTSigner is the custom or default token signer used to sign ID Tokens and JWT Access Tokens.
	JWTSigner JWTSigner

	// CustomAccessTokenClaims is an optional callback to enrich JWT Access Tokens with application-specific claims.
	CustomAccessTokenClaims CustomClaimsFunc

	// CustomIDTokenClaims is an optional callback to enrich OIDC ID Tokens with application-specific claims.
	CustomIDTokenClaims CustomClaimsFunc

	// CustomUserInfoClaims is an optional callback to enrich OIDC /userinfo endpoint responses.
	CustomUserInfoClaims CustomClaimsFunc
}

// DefaultConfig returns the recommended production defaults for OAuth 2.1 and OpenID Connect.
func DefaultConfig() Config {
	return Config{
		Issuer:                  "https://auth.example.com",
		LoginPage:               "/sign-in",
		ConsentPage:             "/consent",
		Scopes:                  []string{ScopeOpenID, ScopeProfile, ScopeEmail, ScopeOffline},
		GrantTypes:              []GrantType{GrantTypeAuthorizationCode, GrantTypeRefreshToken, GrantTypeClientCredentials},
		AccessTokenType:         AccessTokenTypeJWT,
		CodeExpiresIn:           10 * time.Minute,
		AccessTokenExpiresIn:    1 * time.Hour,
		RefreshTokenExpiresIn:   30 * 24 * time.Hour,
		IDTokenExpiresIn:        1 * time.Hour,
		M2MAccessTokenExpiresIn: 2 * time.Hour,
		StoreClientSecretMode:   StoreModeHashed,
		StoreTokensMode:         StoreModeHashed,
		SecretKey:               "default-oauth2-secret-key-32-bytes-long",
		PairwiseSecret:          "default-pairwise-secret-key",
	}
}

// Option configures the OAuth 2.1 Provider plugin.
type Option func(*Config)

// WithIssuer configures the authorization server issuer URL.
func WithIssuer(issuer string) Option {
	return func(c *Config) {
		if issuer != "" {
			c.Issuer = issuer
		}
	}
}

// WithPages configures the interactive login and consent page redirect URLs.
func WithPages(loginPage, consentPage string) Option {
	return func(c *Config) {
		if loginPage != "" {
			c.LoginPage = loginPage
		}
		if consentPage != "" {
			c.ConsentPage = consentPage
		}
	}
}

// WithScopes overrides the list of supported OAuth/OIDC scopes.
func WithScopes(scopes ...string) Option {
	return func(c *Config) {
		if len(scopes) > 0 {
			c.Scopes = scopes
		}
	}
}

// WithGrantTypes overrides the list of enabled grant types.
func WithGrantTypes(types ...GrantType) Option {
	return func(c *Config) {
		if len(types) > 0 {
			c.GrantTypes = types
		}
	}
}

// WithAccessTokenType sets the Access Token format ("jwt" or "opaque").
func WithAccessTokenType(t AccessTokenType) Option {
	return func(c *Config) {
		c.AccessTokenType = t
	}
}

// WithTokenExpirations configures expiration lifetimes for all token types.
func WithTokenExpirations(code, access, refresh, idToken time.Duration) Option {
	return func(c *Config) {
		if code > 0 {
			c.CodeExpiresIn = code
		}
		if access > 0 {
			c.AccessTokenExpiresIn = access
		}
		if refresh > 0 {
			c.RefreshTokenExpiresIn = refresh
		}
		if idToken > 0 {
			c.IDTokenExpiresIn = idToken
		}
	}
}

// WithStoreModes configures the storage strategy for secrets and tokens.
func WithStoreModes(secretMode, tokenMode StoreMode, secretKey string) Option {
	return func(c *Config) {
		c.StoreClientSecretMode = secretMode
		c.StoreTokensMode = tokenMode
		if secretKey != "" {
			c.SecretKey = secretKey
		}
	}
}

// WithPairwiseSecret sets the secret key for deriving pairwise pseudonymous subject identifiers.
func WithPairwiseSecret(secret string) Option {
	return func(c *Config) {
		if secret != "" {
			c.PairwiseSecret = secret
		}
	}
}

// WithJWTSigner configures a custom JWT signer (such as an adapter for plugins/jwt or RSA/ECDSA signer).
func WithJWTSigner(signer JWTSigner) Option {
	return func(c *Config) {
		c.JWTSigner = signer
	}
}

// WithDynamicClientRegistration configures RFC 7591 Dynamic Client Registration.
func WithDynamicClientRegistration(allow, allowUnauthenticated bool) Option {
	return func(c *Config) {
		c.AllowDynamicClientRegistration = allow
		c.AllowUnauthenticatedClientRegistration = allowUnauthenticated
	}
}

// WithCustomAccessTokenClaims sets a custom claims injector for JWT Access Tokens.
func WithCustomAccessTokenClaims(fn CustomClaimsFunc) Option {
	return func(c *Config) {
		c.CustomAccessTokenClaims = fn
	}
}

// WithCustomIDTokenClaims sets a custom claims injector for OIDC ID Tokens.
func WithCustomIDTokenClaims(fn CustomClaimsFunc) Option {
	return func(c *Config) {
		c.CustomIDTokenClaims = fn
	}
}

// WithCustomUserInfoClaims sets a custom claims injector for the UserInfo endpoint.
func WithCustomUserInfoClaims(fn CustomClaimsFunc) Option {
	return func(c *Config) {
		c.CustomUserInfoClaims = fn
	}
}
