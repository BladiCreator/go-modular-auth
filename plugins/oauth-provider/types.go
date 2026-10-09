package oauthprovider

import (
	auth "github.com/BladiCreator/go-modular-auth"
	"github.com/BladiCreator/go-modular-auth-oauth-provider/store"
)

// PrincipalTypeOAuthClient identifies an authenticated OAuth 2.1 client as a Core Principal.
const PrincipalTypeOAuthClient auth.PrincipalType = "oauth_client"

// Type aliases for domain entities managed by persistence store.
type Client = store.Client
type ClientType = store.ClientType
type ClientStatus = store.ClientStatus
type AuthorizationCode = store.AuthorizationCode
type AccessToken = store.AccessToken
type RefreshToken = store.RefreshToken
type Store = store.Store
type ClientStore = store.ClientStore
type CodeStore = store.CodeStore
type TokenStore = store.TokenStore

const (
	ClientTypePublic       = store.ClientTypePublic
	ClientTypeConfidential = store.ClientTypeConfidential
	ClientStatusActive     = store.ClientStatusActive
	ClientStatusRevoked    = store.ClientStatusRevoked
)

// Standard OAuth 2.1 Grant Types.
const (
	GrantTypeAuthorizationCode = "authorization_code"
	GrantTypeClientCredentials = "client_credentials"
	GrantTypeRefreshToken      = "refresh_token"
)

// Code Challenge Methods for PKCE.
const (
	CodeChallengeMethodS256  = "S256"
	CodeChallengeMethodPlain = "plain" // Strongly discouraged/rejected in OAuth 2.1
)

// RegisterClientInput contains parameters to register a new client application.
type RegisterClientInput struct {
	Name              string     `json:"name"`
	ClientType        ClientType `json:"client_type"`
	RedirectURIs      []string   `json:"redirect_uris"`
	AllowedGrantTypes []string   `json:"allowed_grant_types"`
	AllowedScopes     []string   `json:"allowed_scopes"`
}

// RegisterClientOutput contains the registration result including client ID and raw client secret.
type RegisterClientOutput struct {
	Client       *Client `json:"client"`
	ClientSecret string  `json:"client_secret,omitempty"` // Returned only once upon registration
}

// AuthorizeInput contains parameters for the OAuth 2.1 authorization request.
type AuthorizeInput struct {
	ClientID            string   `json:"client_id"`
	UserID              string   `json:"user_id"`
	RedirectURI         string   `json:"redirect_uri"`
	ResponseType        string   `json:"response_type"`
	Scopes              []string `json:"scopes"`
	State               string   `json:"state"`
	CodeChallenge       string   `json:"code_challenge"`
	CodeChallengeMethod string   `json:"code_challenge_method"`
	UserConsent         bool     `json:"user_consent"`
}

// AuthorizeOutput contains the authorization result.
type AuthorizeOutput struct {
	Code        string `json:"code"`
	State       string `json:"state,omitempty"`
	RedirectURI string `json:"redirect_uri"`
}

// TokenInput contains parameters for the OAuth 2.1 token endpoint.
type TokenInput struct {
	GrantType    string   `json:"grant_type"`
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret,omitempty"`
	Code         string   `json:"code,omitempty"`
	RedirectURI  string   `json:"redirect_uri,omitempty"`
	CodeVerifier string   `json:"code_verifier,omitempty"`
	RefreshToken string   `json:"refresh_token,omitempty"`
	Scopes       []string `json:"scopes,omitempty"`
}

// TokenOutput contains the issued tokens returned by the token endpoint.
type TokenOutput struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"` // In seconds
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// RevokeTokenInput contains parameters for RFC 7009 token revocation.
type RevokeTokenInput struct {
	Token         string `json:"token"`
	TokenTypeHint string `json:"token_type_hint,omitempty"` // "access_token" or "refresh_token"
	ClientID      string `json:"client_id"`
	ClientSecret  string `json:"client_secret,omitempty"`
}

// IntrospectTokenInput contains parameters for RFC 7662 token introspection.
type IntrospectTokenInput struct {
	Token         string `json:"token"`
	TokenTypeHint string `json:"token_type_hint,omitempty"`
	ClientID      string `json:"client_id"`
	ClientSecret  string `json:"client_secret,omitempty"`
}

// IntrospectTokenOutput contains the RFC 7662 introspection response.
type IntrospectTokenOutput struct {
	Active    bool     `json:"active"`
	Scope     string   `json:"scope,omitempty"`
	ClientID  string   `json:"client_id,omitempty"`
	Sub       string   `json:"sub,omitempty"`
	Exp       int64    `json:"exp,omitempty"`
	Iat       int64    `json:"iat,omitempty"`
	TokenType string   `json:"token_type,omitempty"`
	Scopes    []string `json:"scopes,omitempty"`
}
