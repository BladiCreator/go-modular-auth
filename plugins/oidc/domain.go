package oidc

import (
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	"github.com/BladiCreator/go-modular-auth-oidc/store"
	"github.com/BladiCreator/go-modular-auth/account"
	"github.com/BladiCreator/go-modular-auth/session"
	"github.com/BladiCreator/go-modular-auth/user"
)

// StateSession represents an ephemeral, single-use state binding.
type StateSession = store.StateSession

// Action denotes the purpose of the OIDC authorization flow.
type Action = store.Action

const (
	ActionSignIn = store.ActionSignIn
	ActionLink   = store.ActionLink
)

// LinkingPolicy defines rules for associating external OIDC identities with Core Users.
type LinkingPolicy string

const (
	// LinkingPolicyVerifiedEmail automatically links when both the external provider and Core record have verified email.
	LinkingPolicyVerifiedEmail LinkingPolicy = "verified_email"

	// LinkingPolicyExplicitOnly requires the user to already be logged in and call BeginLink.
	LinkingPolicyExplicitOnly LinkingPolicy = "explicit_only"

	// LinkingPolicyDisabled prohibits account linking entirely, returning ErrAccountConflict on collision.
	LinkingPolicyDisabled LinkingPolicy = "disabled"
)

// DiscoveryDocument holds the OpenID Connect discovery metadata fetched from .well-known/openid-configuration.
type DiscoveryDocument struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	JWKSUri                           string   `json:"jwks_uri"`
	UserInfoEndpoint                  string   `json:"userinfo_endpoint,omitempty"`
	ResponseTypesSupported            []string `json:"response_types_supported,omitempty"`
	SubjectTypesSupported             []string `json:"subject_types_supported,omitempty"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported,omitempty"`
	ScopesSupported                   []string `json:"scopes_supported,omitempty"`
}

// Endpoints holds explicitly configured URLs when discovery is bypassed.
type Endpoints struct {
	AuthURL     string `json:"auth_url"`
	TokenURL    string `json:"token_url"`
	JWKSURL     string `json:"jwks_url"`
	UserInfoURL string `json:"userinfo_url,omitempty"`
}

// ProviderConfig configures an external OpenID Connect Relying Party identity provider.
type ProviderConfig struct {
	ID                 string         `json:"id"`
	Issuer             string         `json:"issuer"`
	ClientID           string         `json:"client_id"`
	ClientSecret       string         `json:"client_secret"`
	RedirectURI        string         `json:"redirect_uri"`
	Scopes             []string       `json:"scopes"`
	DiscoveryURL       string         `json:"discovery_url,omitempty"`
	CustomEndpoints    *Endpoints     `json:"custom_endpoints,omitempty"`
	SkipIssuerCheck            bool           `json:"skip_issuer_check,omitempty"`
	InsecureSkipSignatureCheck bool           `json:"insecure_skip_signature_check,omitempty"`
	ClockSkew                  time.Duration  `json:"clock_skew,omitempty"`
}

// IDTokenClaims contains cryptographically verified claims parsed from an OIDC ID Token.
type IDTokenClaims struct {
	Issuer            string         `json:"iss"`
	Subject           string         `json:"sub"`
	Audience          []string       `json:"aud"`
	ExpiresAt         time.Time      `json:"exp"`
	IssuedAt          time.Time      `json:"iat"`
	Nonce             string         `json:"nonce,omitempty"`
	AuthTime          *time.Time     `json:"auth_time,omitempty"`
	AuthorizedParty   string         `json:"azp,omitempty"`
	Email             string         `json:"email,omitempty"`
	EmailVerified     bool           `json:"email_verified,omitempty"`
	Name              string         `json:"name,omitempty"`
	PreferredUsername string         `json:"preferred_username,omitempty"`
	Picture           string         `json:"picture,omitempty"`
	RawClaims         map[string]any `json:"raw_claims"`
}

// TokenResponse contains the raw tokens returned by the OIDC Token Endpoint.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

// BeginAuthInput contains parameters to initiate an OIDC authentication flow.
type BeginAuthInput struct {
	Provider    string            `json:"provider"`
	RedirectURI string            `json:"redirect_uri"`
	Scopes      []string          `json:"scopes,omitempty"`
	Prompt      string            `json:"prompt,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// BeginAuthResult contains the authorization URL and state session for redirection.
type BeginAuthResult struct {
	AuthURL      string    `json:"auth_url"`
	State        string    `json:"state"`
	Nonce        string    `json:"nonce"`
	CodeVerifier string    `json:"code_verifier"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// BeginLinkInput initiates linking an external OIDC provider to an existing authenticated user.
type BeginLinkInput struct {
	UserID      string            `json:"user_id"`
	Provider    string            `json:"provider"`
	RedirectURI string            `json:"redirect_uri"`
	Scopes      []string          `json:"scopes,omitempty"`
	Prompt      string            `json:"prompt,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// CompleteAuthInput provides the authorization code and state token from the redirect callback.
type CompleteAuthInput struct {
	Provider    string              `json:"provider"`
	Code        string              `json:"code"`
	State       string              `json:"state"`
	RedirectURI string              `json:"redirect_uri"`
	Session     auth.SessionOptions `json:"session"`
}

// CompleteLinkInput completes an account linking flow for the user bound during BeginLink.
type CompleteLinkInput struct {
	Provider    string `json:"provider"`
	Code        string `json:"code"`
	State       string `json:"state"`
	RedirectURI string `json:"redirect_uri"`
}

// AuthResult is returned when an OIDC authorization code flow succeeds.
type AuthResult struct {
	User          *user.User       `json:"user"`
	Account       *account.Account `json:"account"`
	Session       *session.Session `json:"session"`
	Token         string           `json:"token"`
	IsNewUser     bool             `json:"is_new_user"`
	IDTokenClaims *IDTokenClaims   `json:"id_token_claims"`
	TokenResponse *TokenResponse   `json:"token_response"`
}

// LinkResult is returned when an account linking operation succeeds.
type LinkResult struct {
	Account       *account.Account `json:"account"`
	IDTokenClaims *IDTokenClaims   `json:"id_token_claims"`
}
