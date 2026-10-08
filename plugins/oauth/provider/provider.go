// Package provider defines the contracts and models for OAuth 2.0 / OIDC identity providers.
package provider

import (
	"context"
	"time"
)

// Provider represents an external OAuth 2.0 / OIDC identity provider.
// Implementations must be thread-safe.
type Provider interface {
	// Name returns the unique identifier of the provider (e.g. "google", "github").
	Name() string

	// AuthCodeURL constructs the authorization redirect URL with the given state and options.
	AuthCodeURL(state string, opts ...AuthCodeOption) string

	// Exchange sends the authorization code to the provider's token endpoint to acquire tokens.
	Exchange(ctx context.Context, code string, opts ...ExchangeOption) (*TokenResponse, error)

	// FetchProfile retrieves normalized user identity claims using the provided tokens.
	FetchProfile(ctx context.Context, tokens *TokenResponse) (*ProviderProfile, error)

	// ValidateRedirectURI checks whether the requested redirect URI is permitted.
	ValidateRedirectURI(redirectURI string) bool
}

// TokenResponse represents the parsed response from an OAuth token exchange.
type TokenResponse struct {
	AccessToken  string         `json:"access_token"`
	TokenType    string         `json:"token_type"`
	RefreshToken string         `json:"refresh_token,omitempty"`
	ExpiresIn    int64          `json:"expires_in,omitempty"`
	ExpiresAt    time.Time      `json:"expires_at,omitempty"`
	Scope        string         `json:"scope,omitempty"`
	IDToken      string         `json:"id_token,omitempty"`
	Raw          map[string]any `json:"raw,omitempty"`
}

// Expired reports whether the access token has expired according to its expiration time.
func (t *TokenResponse) Expired(now time.Time) bool {
	if t.ExpiresAt.IsZero() {
		return false
	}
	return !now.Before(t.ExpiresAt)
}

// ProviderProfile represents normalized user information fetched from an identity provider.
type ProviderProfile struct {
	// Provider is the identifier of the identity provider (e.g., "google", "github").
	Provider string `json:"provider"`

	// ProviderID is the unique, stable identifier of the subject within the provider.
	ProviderID string `json:"provider_id"`

	// Email is the primary email address reported by the provider.
	Email string `json:"email"`

	// EmailVerified indicates whether the external provider asserts that the email has been verified.
	EmailVerified bool `json:"email_verified"`

	// Name is the display name of the user.
	Name string `json:"name,omitempty"`

	// Username is the handle or screen name of the user, if available.
	Username string `json:"username,omitempty"`

	// AvatarURL is a URL pointing to the user's avatar image.
	AvatarURL string `json:"avatar_url,omitempty"`

	// Raw contains the unparsed claims returned by the provider's profile or userinfo endpoint.
	Raw map[string]any `json:"raw,omitempty"`
}

// AuthCodeConfig holds parameters for constructing the authorization URL.
type AuthCodeConfig struct {
	RedirectURI         string
	Scopes              []string
	CodeChallenge       string
	CodeChallengeMethod string
	Prompt              string
	AccessType          string
	ExtraParams         map[string]string
}

// AuthCodeOption customizes the authorization code URL request.
type AuthCodeOption func(*AuthCodeConfig)

// WithRedirectURI sets the redirect URI.
func WithRedirectURI(uri string) AuthCodeOption {
	return func(c *AuthCodeConfig) {
		c.RedirectURI = uri
	}
}

// WithScopes overrides or appends scopes.
func WithScopes(scopes ...string) AuthCodeOption {
	return func(c *AuthCodeConfig) {
		c.Scopes = append(c.Scopes, scopes...)
	}
}

// WithPKCE sets the PKCE code challenge and method in the authorization URL.
func WithPKCE(challenge, method string) AuthCodeOption {
	return func(c *AuthCodeConfig) {
		c.CodeChallenge = challenge
		c.CodeChallengeMethod = method
	}
}

// WithPrompt sets the prompt parameter (e.g., "consent", "select_account").
func WithPrompt(prompt string) AuthCodeOption {
	return func(c *AuthCodeConfig) {
		c.Prompt = prompt
	}
}

// WithAccessType sets the access_type parameter (e.g., "offline" for refresh tokens).
func WithAccessType(accessType string) AuthCodeOption {
	return func(c *AuthCodeConfig) {
		c.AccessType = accessType
	}
}

// WithExtraParam adds an arbitrary query parameter to the authorization URL.
func WithExtraParam(key, value string) AuthCodeOption {
	return func(c *AuthCodeConfig) {
		if c.ExtraParams == nil {
			c.ExtraParams = make(map[string]string)
		}
		c.ExtraParams[key] = value
	}
}

// ExchangeConfig holds parameters for token exchange.
type ExchangeConfig struct {
	RedirectURI  string
	CodeVerifier string
	ExtraParams  map[string]string
}

// ExchangeOption customizes the token exchange request.
type ExchangeOption func(*ExchangeConfig)

// WithExchangeRedirectURI specifies the redirect URI used during authorization.
func WithExchangeRedirectURI(uri string) ExchangeOption {
	return func(c *ExchangeConfig) {
		c.RedirectURI = uri
	}
}

// WithCodeVerifier passes the PKCE code verifier for token exchange.
func WithCodeVerifier(verifier string) ExchangeOption {
	return func(c *ExchangeConfig) {
		c.CodeVerifier = verifier
	}
}

// WithExchangeExtraParam passes extra form parameters during token exchange.
func WithExchangeExtraParam(key, value string) ExchangeOption {
	return func(c *ExchangeConfig) {
		if c.ExtraParams == nil {
			c.ExtraParams = make(map[string]string)
		}
		c.ExtraParams[key] = value
	}
}
