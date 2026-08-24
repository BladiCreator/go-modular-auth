package oidcprovider

import "time"

// ClientType defines the OAuth 2.0 / OIDC client application type.
type ClientType string

const (
	// ClientTypeWeb represents confidential server-side web applications capable of keeping secrets.
	ClientTypeWeb ClientType = "web"

	// ClientTypeNative represents native mobile or desktop applications.
	ClientTypeNative ClientType = "native"

	// ClientTypeUserAgentBased represents Single Page Applications (SPAs) executing in a browser.
	ClientTypeUserAgentBased ClientType = "user-agent-based"

	// ClientTypePublic represents public clients incapable of storing client secrets securely.
	ClientTypePublic ClientType = "public"
)

// SecretStoreMode specifies how client_secret values are stored and verified.
type SecretStoreMode string

const (
	// SecretStorePlain stores client_secret in plain text.
	SecretStorePlain SecretStoreMode = "plain"

	// SecretStoreHashed stores client_secret as a password hash (Argon2id/Bcrypt).
	SecretStoreHashed SecretStoreMode = "hashed"

	// SecretStoreEncrypted stores client_secret in encrypted form.
	SecretStoreEncrypted SecretStoreMode = "encrypted"
)

// OAuthClient represents a registered OAuth 2.0 / OIDC client application entity.
type OAuthClient struct {
	ID           string     `json:"id"`
	ClientID     string     `json:"client_id"`
	ClientSecret *string    `json:"client_secret,omitempty"`
	Type         ClientType `json:"type"`
	Name         string     `json:"name"`
	Icon         *string    `json:"icon,omitempty"`
	Metadata     *string    `json:"metadata,omitempty"`
	RedirectURIs []string   `json:"redirect_uris"`
	Disabled     bool       `json:"disabled"`
	UserID       *string    `json:"user_id,omitempty"`
	SkipConsent  bool       `json:"skip_consent,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

// OAuthCode represents a single-use authorization code grant (RFC 6749 4.1.2).
type OAuthCode struct {
	ID                  string    `json:"id"`
	Code                string    `json:"code"`
	ClientID            string    `json:"client_id"`
	UserID              string    `json:"user_id"`
	RedirectURI         string    `json:"redirect_uri"`
	Scope               string    `json:"scope"`
	State               *string   `json:"state,omitempty"`
	Nonce               *string   `json:"nonce,omitempty"`
	CodeChallenge       *string   `json:"code_challenge,omitempty"`
	CodeChallengeMethod *string   `json:"code_challenge_method,omitempty"`
	ExpiresAt           time.Time `json:"expires_at"`
	Consumed            bool      `json:"consumed"`
	CreatedAt           time.Time `json:"created_at"`
}

// OAuthToken represents an Access Token and Refresh Token pair entity.
type OAuthToken struct {
	ID                    string    `json:"id"`
	AccessToken           string    `json:"access_token"`
	RefreshToken          string    `json:"refresh_token"`
	ClientID              string    `json:"client_id"`
	UserID                string    `json:"user_id"`
	Scope                 string    `json:"scope"`
	AccessTokenExpiresAt  time.Time `json:"access_token_expires_at"`
	RefreshTokenExpiresAt time.Time `json:"refresh_token_expires_at"`
	CreatedAt             time.Time `json:"created_at"`
	UpdatedAt             time.Time `json:"updated_at"`
}

// OAuthConsent represents explicit user consent granted to a client application.
type OAuthConsent struct {
	ID           string    `json:"id"`
	ClientID     string    `json:"client_id"`
	UserID       string    `json:"user_id"`
	Scopes       string    `json:"scopes"`
	ConsentGiven bool      `json:"consent_given"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// RegisterClientParams holds input parameters when registering a new OAuth/OIDC client application.
type RegisterClientParams struct {
	Name         string     `json:"name"`
	Type         ClientType `json:"type"`
	RedirectURIs []string   `json:"redirect_uris"`
	Icon         *string    `json:"icon,omitempty"`
	Metadata     *string    `json:"metadata,omitempty"`
	UserID       *string    `json:"user_id,omitempty"`
	SkipConsent  bool       `json:"skip_consent,omitempty"`
}

// AuthorizeParams holds input parameters for an authorization request.
type AuthorizeParams struct {
	ClientID            string  `json:"client_id"`
	RedirectURI         string  `json:"redirect_uri"`
	ResponseType        string  `json:"response_type"` // Must be "code"
	Scope               string  `json:"scope"`
	State               *string `json:"state,omitempty"`
	Nonce               *string `json:"nonce,omitempty"`
	CodeChallenge       *string `json:"code_challenge,omitempty"`
	CodeChallengeMethod *string `json:"code_challenge_method,omitempty"`
	Prompt              *string `json:"prompt,omitempty"` // "consent", "login", "none"
	UserID              string  `json:"user_id"`
}

// AuthorizeResponse holds the outcome of an authorization request.
type AuthorizeResponse struct {
	RedirectURI     string       `json:"redirect_uri"`
	Code            *string      `json:"code,omitempty"`
	State           *string      `json:"state,omitempty"`
	RequiresConsent bool         `json:"requires_consent"`
	ConsentCode     *string      `json:"consent_code,omitempty"`
	ScopesRequested []string     `json:"scopes_requested,omitempty"`
	ClientInfo      *OAuthClient `json:"client_info,omitempty"`
}

// GrantConsentParams holds input parameters when an authenticated user approves client scopes.
type GrantConsentParams struct {
	ClientID    string   `json:"client_id"`
	UserID      string   `json:"user_id"`
	ConsentCode string   `json:"consent_code"`
	Accept      bool     `json:"accept"`
	Scopes      []string `json:"scopes"`
}

// ExchangeTokenParams holds parameters submitted to the token endpoint.
type ExchangeTokenParams struct {
	GrantType    string  `json:"grant_type"` // "authorization_code" or "refresh_token"
	Code         *string `json:"code,omitempty"`
	RefreshToken *string `json:"refresh_token,omitempty"`
	RedirectURI  *string `json:"redirect_uri,omitempty"`
	ClientID     string  `json:"client_id"`
	ClientSecret *string `json:"client_secret,omitempty"`
	CodeVerifier *string `json:"code_verifier,omitempty"`
}

// TokenResponse represents a successful token issuance response.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"` // "Bearer"
	ExpiresIn    int64  `json:"expires_in"` // seconds
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// UserInfoClaims represents standard OpenID Connect UserInfo claims.
type UserInfoClaims map[string]any

// DiscoveryMetadata represents the OpenID Connect Discovery 1.0 JSON payload (/.well-known/openid-configuration).
type DiscoveryMetadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserinfoEndpoint                  string   `json:"userinfo_endpoint"`
	JwksURI                           string   `json:"jwks_uri"`
	RegistrationEndpoint              string   `json:"registration_endpoint,omitempty"`
	EndSessionEndpoint                string   `json:"end_session_endpoint,omitempty"`
	ScopesSupported                   []string `json:"scopes_supported"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	ResponseModesSupported            []string `json:"response_modes_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
}

// JWKKey represents a single JSON Web Key in a JWKS set.
type JWKKey struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	K   string `json:"k,omitempty"`
}

// JWKS represents a JSON Web Key Set payload.
type JWKS struct {
	Keys []JWKKey `json:"keys"`
}
