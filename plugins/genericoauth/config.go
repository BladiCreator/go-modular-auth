package genericoauth

import (
	"context"
	"net/http"
	"time"
)

// ResponseMode defines the authorization response mode (query or form_post).
type ResponseMode string

const (
	ResponseModeQuery    ResponseMode = "query"
	ResponseModeFormPost ResponseMode = "form_post"
)

// AuthMethod defines the client authentication method used at the token endpoint.
type AuthMethod string

const (
	AuthMethodPost  AuthMethod = "post"
	AuthMethodBasic AuthMethod = "basic"
)

// Tokens holds access, refresh, and ID tokens returned by an OAuth2/OIDC provider.
type Tokens struct {
	AccessToken           string         `json:"access_token"`
	RefreshToken          string         `json:"refresh_token,omitempty"`
	IDToken               string         `json:"id_token,omitempty"`
	TokenType             string         `json:"token_type,omitempty"`
	AccessTokenExpiresAt  time.Time      `json:"access_token_expires_at,omitempty"`
	RefreshTokenExpiresAt time.Time      `json:"refresh_token_expires_at,omitempty"`
	Scopes                []string       `json:"scopes,omitempty"`
	Raw                   map[string]any `json:"raw,omitempty"`
}

// UserInfo represents normalized profile data obtained from the provider.
type UserInfo struct {
	ID            string         `json:"id,omitempty"`
	Sub           string         `json:"sub,omitempty"`
	Email         string         `json:"email,omitempty"`
	EmailVerified bool           `json:"email_verified,omitempty"`
	Name          string         `json:"name,omitempty"`
	Picture       string         `json:"picture,omitempty"`
	Raw           map[string]any `json:"raw,omitempty"`
}

// UserPartial represents mapped fields ready for user creation or updating.
type UserPartial struct {
	ID            string         `json:"id,omitempty"`
	Email         string         `json:"email,omitempty"`
	EmailVerified bool           `json:"email_verified,omitempty"`
	Name          string         `json:"name,omitempty"`
	Image         string         `json:"image,omitempty"`
	CustomFields  map[string]any `json:"custom_fields,omitempty"`
}

// SignInData contains authorization metadata produced when initiating sign-in.
type SignInData struct {
	URL          string `json:"url"`
	State        string `json:"state"`
	CodeVerifier string `json:"code_verifier,omitempty"`
	Redirect     bool   `json:"redirect"`
}

// Custom hook function signatures.
type (
	TokenFetcherFunc    func(ctx context.Context, req ExchangeRequest) (*Tokens, error)
	UserInfoFetcherFunc func(ctx context.Context, tokens *Tokens) (*UserInfo, error)
	ProfileMapperFunc   func(ctx context.Context, profile map[string]any) (*UserPartial, error)
	ParamBuilderFunc    func(ctx context.Context) map[string]string
)

// ExchangeRequest encapsulates arguments needed to exchange an authorization code for tokens.
type ExchangeRequest struct {
	Code         string
	RedirectURI  string
	CodeVerifier string
	DeviceID     string
}

// ProviderConfig specifies complete setup parameters for a generic OAuth2/OIDC provider.
type ProviderConfig struct {
	ProviderID              string            `json:"provider_id"`
	DiscoveryURL            string            `json:"discovery_url,omitempty"`
	Issuer                  string            `json:"issuer,omitempty"`
	RequireIssuerValidation bool              `json:"require_issuer_validation,omitempty"`
	AuthorizationURL        string            `json:"authorization_url,omitempty"`
	TokenURL                string            `json:"token_url,omitempty"`
	UserInfoURL             string            `json:"user_info_url,omitempty"`
	ClientID                string            `json:"client_id"`
	ClientSecret            string            `json:"client_secret,omitempty"`
	Scopes                  []string          `json:"scopes,omitempty"`
	RedirectURI             string            `json:"redirect_uri,omitempty"`
	ResponseType            string            `json:"response_type,omitempty"`
	ResponseMode            ResponseMode      `json:"response_mode,omitempty"`
	Prompt                  string            `json:"prompt,omitempty"`
	PKCE                    bool              `json:"pkce,omitempty"`
	AccessType              string            `json:"access_type,omitempty"`
	AccessTokenExpiresIn    time.Duration     `json:"access_token_expires_in,omitempty"`
	Authentication          AuthMethod        `json:"authentication,omitempty"`
	DisableImplicitSignUp   bool              `json:"disable_implicit_sign_up,omitempty"`
	DisableSignUp           bool              `json:"disable_sign_up,omitempty"`
	OverrideUserInfo        bool              `json:"override_user_info,omitempty"`
	DiscoveryHeaders        http.Header       `json:"-"`
	AuthorizationHeaders    http.Header       `json:"-"`
	AuthURLParams           map[string]string `json:"auth_url_params,omitempty"`
	TokenURLParams          map[string]string `json:"token_url_params,omitempty"`

	// Custom Hooks
	GetToken         TokenFetcherFunc    `json:"-"`
	GetUserInfo      UserInfoFetcherFunc `json:"-"`
	MapProfileToUser ProfileMapperFunc   `json:"-"`
}

// CookieConfig configures HTTP state and PKCE cookies.
type CookieConfig struct {
	Name     string
	Secret   string
	Domain   string
	Path     string
	Secure   bool
	HTTPOnly bool
	SameSite http.SameSite
	MaxAge   time.Duration
}

// Config defines the overall Generic OAuth plugin configuration.
type Config struct {
	Providers    map[string]*ProviderConfig
	HTTPClient   *http.Client
	CookieConfig CookieConfig
	StateTTL     time.Duration
}
