package oauthprovider

import (
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	"github.com/BladiCreator/go-modular-auth/schema"
)

// PrincipalTypeOAuthClient identifies an authenticated OAuth 2.1 client as a Core Principal.
const PrincipalTypeOAuthClient auth.PrincipalType = "oauth_client"

// ClientType defines the OAuth 2.1 client confidentiality classification.
type ClientType string

const (
	ClientTypePublic       ClientType = "public"
	ClientTypeConfidential ClientType = "confidential"
)

// ClientStatus defines the operational lifecycle status of an OAuth 2.1 client.
type ClientStatus string

const (
	ClientStatusActive  ClientStatus = "active"
	ClientStatusRevoked ClientStatus = "revoked"
)

// Client represents a registered OAuth 2.1 client application.
type Client struct {
	ID                string       `json:"id"`
	SecretHash        string       `json:"secret_hash,omitempty"`
	Name              string       `json:"name"`
	ClientType        ClientType   `json:"client_type"`
	RedirectURIs      []string     `json:"redirect_uris"`
	AllowedGrantTypes []string     `json:"allowed_grant_types"`
	AllowedScopes     []string     `json:"allowed_scopes"`
	Status            ClientStatus `json:"status"`
	CreatedAt         time.Time    `json:"created_at"`
	UpdatedAt         time.Time    `json:"updated_at"`
}

// AuthorizationCode represents a short-lived authorization code issued during the authorize flow.
type AuthorizationCode struct {
	ID                  string     `json:"id"`
	CodeHash            string     `json:"code_hash"`
	ClientID            string     `json:"client_id"`
	UserID              string     `json:"user_id"`
	RedirectURI         string     `json:"redirect_uri"`
	Scopes              []string   `json:"scopes"`
	CodeChallenge       string     `json:"code_challenge"`
	CodeChallengeMethod string     `json:"code_challenge_method"`
	ExpiresAt           time.Time  `json:"expires_at"`
	ConsumedAt          *time.Time `json:"consumed_at,omitempty"`
	CreatedAt           time.Time  `json:"created_at"`
}

// AccessToken represents an opaque bearer access token.
type AccessToken struct {
	ID        string     `json:"id"`
	TokenHash string     `json:"token_hash"`
	ClientID  string     `json:"client_id"`
	UserID    string     `json:"user_id,omitempty"`
	Scopes    []string   `json:"scopes"`
	ExpiresAt time.Time  `json:"expires_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// RefreshToken represents a long-lived token used to obtain fresh access tokens.
type RefreshToken struct {
	ID            string     `json:"id"`
	TokenHash     string     `json:"token_hash"`
	AccessTokenID string     `json:"access_token_id"`
	ClientID      string     `json:"client_id"`
	UserID        string     `json:"user_id,omitempty"`
	Scopes        []string   `json:"scopes"`
	ExpiresAt     time.Time  `json:"expires_at"`
	RevokedAt     *time.Time `json:"revoked_at,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
}

const (
	ModelOAuthClients            = "oauth_clients"
	ModelOAuthAuthorizationCodes = "oauth_authorization_codes"
	ModelOAuthAccessTokens       = "oauth_access_tokens"
	ModelOAuthRefreshTokens      = "oauth_refresh_tokens"
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

// RegisterSchema registers all oauth-provider models in the compiled schema.
func RegisterSchema(s *schema.Schema) error {
	// 1. Clients
	cModel := schema.NewModel(ModelOAuthClients, ModelOAuthClients, "id")
	_ = cModel.AddField(schema.Field{Name: "id", Type: schema.TypeString, Required: true, Unique: true})
	_ = cModel.AddField(schema.Field{Name: "secret_hash", Type: schema.TypeString})
	_ = cModel.AddField(schema.Field{Name: "name", Type: schema.TypeString, Required: true})
	_ = cModel.AddField(schema.Field{Name: "client_type", Type: schema.TypeString, Required: true})
	_ = cModel.AddField(schema.Field{Name: "redirect_uris", Type: schema.TypeJSON})
	_ = cModel.AddField(schema.Field{Name: "allowed_grant_types", Type: schema.TypeJSON})
	_ = cModel.AddField(schema.Field{Name: "allowed_scopes", Type: schema.TypeJSON})
	_ = cModel.AddField(schema.Field{Name: "status", Type: schema.TypeString, Required: true})
	_ = cModel.AddField(schema.Field{Name: "created_at", Type: schema.TypeTime, Required: true})
	_ = cModel.AddField(schema.Field{Name: "updated_at", Type: schema.TypeTime, Required: true})
	if err := s.AddModel(cModel); err != nil {
		return err
	}

	// 2. Authorization Codes
	acModel := schema.NewModel(ModelOAuthAuthorizationCodes, ModelOAuthAuthorizationCodes, "id")
	_ = acModel.AddField(schema.Field{Name: "id", Type: schema.TypeString, Required: true})
	_ = acModel.AddField(schema.Field{Name: "code_hash", Type: schema.TypeString, Required: true, Unique: true})
	_ = acModel.AddField(schema.Field{Name: "client_id", Type: schema.TypeString, Required: true})
	_ = acModel.AddField(schema.Field{Name: "user_id", Type: schema.TypeString, Required: true})
	_ = acModel.AddField(schema.Field{Name: "redirect_uri", Type: schema.TypeString, Required: true})
	_ = acModel.AddField(schema.Field{Name: "scopes", Type: schema.TypeJSON})
	_ = acModel.AddField(schema.Field{Name: "code_challenge", Type: schema.TypeString, Required: true})
	_ = acModel.AddField(schema.Field{Name: "code_challenge_method", Type: schema.TypeString, Required: true})
	_ = acModel.AddField(schema.Field{Name: "expires_at", Type: schema.TypeTime, Required: true})
	_ = acModel.AddField(schema.Field{Name: "consumed_at", Type: schema.TypeTime})
	_ = acModel.AddField(schema.Field{Name: "created_at", Type: schema.TypeTime, Required: true})
	acModel.Indexes = []schema.Index{
		{Name: "idx_oauth_auth_codes_hash", Fields: []string{"code_hash"}, Unique: true},
	}
	if err := s.AddModel(acModel); err != nil {
		return err
	}

	// 3. Access Tokens
	atModel := schema.NewModel(ModelOAuthAccessTokens, ModelOAuthAccessTokens, "id")
	_ = atModel.AddField(schema.Field{Name: "id", Type: schema.TypeString, Required: true})
	_ = atModel.AddField(schema.Field{Name: "token_hash", Type: schema.TypeString, Required: true, Unique: true})
	_ = atModel.AddField(schema.Field{Name: "client_id", Type: schema.TypeString, Required: true})
	_ = atModel.AddField(schema.Field{Name: "user_id", Type: schema.TypeString})
	_ = atModel.AddField(schema.Field{Name: "scopes", Type: schema.TypeJSON})
	_ = atModel.AddField(schema.Field{Name: "expires_at", Type: schema.TypeTime, Required: true})
	_ = atModel.AddField(schema.Field{Name: "revoked_at", Type: schema.TypeTime})
	_ = atModel.AddField(schema.Field{Name: "created_at", Type: schema.TypeTime, Required: true})
	atModel.Indexes = []schema.Index{
		{Name: "idx_oauth_access_tokens_hash", Fields: []string{"token_hash"}, Unique: true},
		{Name: "idx_oauth_access_tokens_client", Fields: []string{"client_id"}},
		{Name: "idx_oauth_access_tokens_user", Fields: []string{"user_id"}},
	}
	if err := s.AddModel(atModel); err != nil {
		return err
	}

	// 4. Refresh Tokens
	rtModel := schema.NewModel(ModelOAuthRefreshTokens, ModelOAuthRefreshTokens, "id")
	_ = rtModel.AddField(schema.Field{Name: "id", Type: schema.TypeString, Required: true})
	_ = rtModel.AddField(schema.Field{Name: "token_hash", Type: schema.TypeString, Required: true, Unique: true})
	_ = rtModel.AddField(schema.Field{Name: "access_token_id", Type: schema.TypeString})
	_ = rtModel.AddField(schema.Field{Name: "client_id", Type: schema.TypeString, Required: true})
	_ = rtModel.AddField(schema.Field{Name: "user_id", Type: schema.TypeString})
	_ = rtModel.AddField(schema.Field{Name: "scopes", Type: schema.TypeJSON})
	_ = rtModel.AddField(schema.Field{Name: "expires_at", Type: schema.TypeTime, Required: true})
	_ = rtModel.AddField(schema.Field{Name: "revoked_at", Type: schema.TypeTime})
	_ = rtModel.AddField(schema.Field{Name: "created_at", Type: schema.TypeTime, Required: true})
	rtModel.Indexes = []schema.Index{
		{Name: "idx_oauth_refresh_tokens_hash", Fields: []string{"token_hash"}, Unique: true},
		{Name: "idx_oauth_refresh_tokens_client", Fields: []string{"client_id"}},
		{Name: "idx_oauth_refresh_tokens_user", Fields: []string{"user_id"}},
	}
	return s.AddModel(rtModel)
}
