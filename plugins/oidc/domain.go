package oidc

import (
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	"github.com/BladiCreator/go-modular-auth/account"
	"github.com/BladiCreator/go-modular-auth/schema"
	"github.com/BladiCreator/go-modular-auth/session"
	"github.com/BladiCreator/go-modular-auth/user"
)

// Action denotes the purpose of the OIDC authorization flow.
type Action string

const (
	ActionSignIn Action = "sign_in"
	ActionLink   Action = "link"
)

// ModelOIDCStates is the schema model identifier for OIDC transient state sessions.
const ModelOIDCStates = "oidc_states"

// StateSession represents an ephemeral, single-use state binding for an in-flight OIDC authentication flow.
type StateSession struct {
	State        string            `json:"state"`
	Provider     string            `json:"provider"`
	RedirectURI  string            `json:"redirect_uri"`
	CodeVerifier string            `json:"code_verifier,omitempty"`
	Nonce        string            `json:"nonce,omitempty"`
	Action       Action            `json:"action"`
	UserID       string            `json:"user_id,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
	ConsumedAt   *time.Time        `json:"consumed_at,omitempty"`
	ExpiresAt    time.Time         `json:"expires_at"`
	CreatedAt    time.Time         `json:"created_at"`
}

// Expired reports whether the state session has expired relative to the given time.
func (s *StateSession) Expired(now time.Time) bool {
	return s != nil && !s.ExpiresAt.IsZero() && !now.Before(s.ExpiresAt)
}

// IsConsumed reports whether the state session has already been redeemed.
func (s *StateSession) IsConsumed() bool {
	return s != nil && s.ConsumedAt != nil
}

// RegisterSchema registers the OIDC transient state session model.
func RegisterSchema(s *schema.Schema) error {
	m := schema.NewModel(ModelOIDCStates, ModelOIDCStates, "state")
	_ = m.AddField(schema.Field{Name: "state", Type: schema.TypeString, Required: true, Unique: true})
	_ = m.AddField(schema.Field{Name: "provider", Type: schema.TypeString, Required: true})
	_ = m.AddField(schema.Field{Name: "redirect_uri", Type: schema.TypeString, Required: true})
	_ = m.AddField(schema.Field{Name: "code_verifier", Type: schema.TypeString})
	_ = m.AddField(schema.Field{Name: "nonce", Type: schema.TypeString})
	_ = m.AddField(schema.Field{Name: "action", Type: schema.TypeString, Required: true})
	_ = m.AddField(schema.Field{Name: "user_id", Type: schema.TypeString})
	_ = m.AddField(schema.Field{Name: "metadata", Type: schema.TypeJSON})
	_ = m.AddField(schema.Field{Name: "consumed_at", Type: schema.TypeTime})
	_ = m.AddField(schema.Field{Name: "expires_at", Type: schema.TypeTime, Required: true})
	_ = m.AddField(schema.Field{Name: "created_at", Type: schema.TypeTime, Required: true})
	m.Indexes = []schema.Index{
		{Name: "idx_oidc_states_state", Fields: []string{"state"}, Unique: true},
		{Name: "idx_oidc_states_expires", Fields: []string{"expires_at"}},
	}
	return s.AddModel(m)
}

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
