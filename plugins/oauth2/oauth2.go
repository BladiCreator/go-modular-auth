package oauth2

import (
	"sync"

	"github.com/BladiCreator/go-modular-auth/plugin"
)

// PluginID is the unique string identifier for the OAuth 2.1 Provider plugin ("oauth2").
const PluginID = "oauth2"

// Parameter and Result Structs
type (
	// AuthorizeParams defines input parameters for initiating the OAuth 2.1 authorization code flow.
	AuthorizeParams struct {
		ClientID            string         `json:"client_id"`
		RedirectURI         string         `json:"redirect_uri"`
		ResponseType        string         `json:"response_type"`
		CodeChallenge       string         `json:"code_challenge"`
		CodeChallengeMethod string         `json:"code_challenge_method"`
		Scope               string         `json:"scope"`
		State               string         `json:"state"`
		Nonce               string         `json:"nonce,omitempty"`
		Prompt              string         `json:"prompt,omitempty"`
		Resource            string         `json:"resource,omitempty"`
		SessionID           string         `json:"session_id,omitempty"`
		UserID              string         `json:"user_id,omitempty"`
		Extra               map[string]any `json:"extra,omitempty"`
	}

	// AuthorizeResult represents the outcome of an authorization request.
	AuthorizeResult struct {
		RedirectURI  string `json:"redirect_uri"`
		Code         string `json:"code,omitempty"`
		State        string `json:"state,omitempty"`
		Issuer       string `json:"iss,omitempty"`
		IsRedirect   bool   `json:"is_redirect"`
		NeedsLogin   bool   `json:"needs_login"`
		NeedsConsent bool   `json:"needs_consent"`
	}

	// ContinueAuthorizeParams defines input parameters when resuming authorization after login/consent.
	ContinueAuthorizeParams struct {
		OAuthQuery     string         `json:"oauth_query"`
		OAuthSignature string         `json:"oauth_signature"`
		SessionID      string         `json:"session_id"`
		UserID         string         `json:"user_id"`
		Extra          map[string]any `json:"extra,omitempty"`
	}

	// ConsentParams defines input parameters for user approval or denial of requested scopes.
	ConsentParams struct {
		OAuthQuery     string         `json:"oauth_query"`
		OAuthSignature string         `json:"oauth_signature"`
		UserID         string         `json:"user_id"`
		ApprovedScopes []string       `json:"approved_scopes"`
		Denied         bool           `json:"denied"`
		Extra          map[string]any `json:"extra,omitempty"`
	}

	// ConsentResult represents the result of processing user consent.
	ConsentResult struct {
		RedirectURI string `json:"redirect_uri"`
		Code        string `json:"code,omitempty"`
		State       string `json:"state,omitempty"`
		Issuer      string `json:"iss,omitempty"`
	}

	// RevokeConsentParams defines input parameters to revoke user consent for a client.
	RevokeConsentParams struct {
		ClientID string         `json:"client_id"`
		UserID   string         `json:"user_id"`
		Extra    map[string]any `json:"extra,omitempty"`
	}

	// RevokeConsentResult reports the outcome of revoking consent.
	RevokeConsentResult struct {
		Success bool `json:"success"`
	}

	// ListConsentsParams defines input parameters to list user consents.
	ListConsentsParams struct {
		UserID string         `json:"user_id"`
		Extra  map[string]any `json:"extra,omitempty"`
	}

	// ListConsentsResult contains the list of active user consents.
	ListConsentsResult struct {
		Consents []*OAuthConsent `json:"consents"`
	}

	// TokenParams defines input parameters for the token endpoint exchange.
	TokenParams struct {
		GrantType    string         `json:"grant_type"`
		Code         string         `json:"code,omitempty"`
		CodeVerifier string         `json:"code_verifier,omitempty"`
		RedirectURI  string         `json:"redirect_uri,omitempty"`
		ClientID     string         `json:"client_id,omitempty"`
		ClientSecret string         `json:"client_secret,omitempty"`
		RefreshToken string         `json:"refresh_token,omitempty"`
		Scope        string         `json:"scope,omitempty"`
		Resource     string         `json:"resource,omitempty"`
		Extra        map[string]any `json:"extra,omitempty"`
	}

	// TokenResult represents the response issued by the token endpoint.
	TokenResult struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int64  `json:"expires_in"`
		RefreshToken string `json:"refresh_token,omitempty"`
		IDToken      string `json:"id_token,omitempty"`
		Scope        string `json:"scope,omitempty"`
	}

	// IntrospectParams defines input parameters for token introspection (RFC 7662).
	IntrospectParams struct {
		Token         string         `json:"token"`
		TokenTypeHint string         `json:"token_type_hint,omitempty"`
		ClientID      string         `json:"client_id,omitempty"`
		ClientSecret  string         `json:"client_secret,omitempty"`
		Extra         map[string]any `json:"extra,omitempty"`
	}

	// IntrospectResult represents the introspection metadata (RFC 7662).
	IntrospectResult struct {
		Active    bool           `json:"active"`
		Scope     string         `json:"scope,omitempty"`
		ClientID  string         `json:"client_id,omitempty"`
		Username  string         `json:"username,omitempty"`
		TokenType string         `json:"token_type,omitempty"`
		Exp       int64          `json:"exp,omitempty"`
		Iat       int64          `json:"iat,omitempty"`
		Nbf       int64          `json:"nbf,omitempty"`
		Sub       string         `json:"sub,omitempty"`
		Aud       []string       `json:"aud,omitempty"`
		Iss       string         `json:"iss,omitempty"`
		Jti       string         `json:"jti,omitempty"`
		Extra     map[string]any `json:"extra,omitempty"`
	}

	// RevokeParams defines input parameters for token revocation (RFC 7009).
	RevokeParams struct {
		Token         string         `json:"token"`
		TokenTypeHint string         `json:"token_type_hint,omitempty"`
		ClientID      string         `json:"client_id,omitempty"`
		ClientSecret  string         `json:"client_secret,omitempty"`
		Extra         map[string]any `json:"extra,omitempty"`
	}

	// RevokeResult reports the result of token revocation.
	RevokeResult struct {
		Success bool `json:"success"`
	}

	// UserInfoParams defines input parameters for the OIDC UserInfo endpoint.
	UserInfoParams struct {
		AccessToken string         `json:"access_token"`
		Extra       map[string]any `json:"extra,omitempty"`
	}

	// UserInfoResult represents claims returned by the OIDC UserInfo endpoint.
	UserInfoResult struct {
		Sub                 string         `json:"sub"`
		Name                string         `json:"name,omitempty"`
		Email               string         `json:"email,omitempty"`
		EmailVerified       *bool          `json:"email_verified,omitempty"`
		PhoneNumber         string         `json:"phone_number,omitempty"`
		PhoneNumberVerified *bool          `json:"phone_number_verified,omitempty"`
		Picture             string         `json:"picture,omitempty"`
		Claims              map[string]any `json:"claims,omitempty"`
	}

	// EndSessionParams defines input parameters for RP-Initiated Logout.
	EndSessionParams struct {
		IDTokenHint           string         `json:"id_token_hint,omitempty"`
		ClientID              string         `json:"client_id,omitempty"`
		PostLogoutRedirectURI string         `json:"post_logout_redirect_uri,omitempty"`
		State                 string         `json:"state,omitempty"`
		SessionID             string         `json:"session_id,omitempty"`
		Extra                 map[string]any `json:"extra,omitempty"`
	}

	// EndSessionResult contains the redirection target after logout.
	EndSessionResult struct {
		RedirectURI string `json:"redirect_uri"`
	}

	// RegisterClientParams defines input parameters for Dynamic Client Registration (RFC 7591).
	RegisterClientParams struct {
		ClientName              string                  `json:"client_name"`
		ClientURI               string                  `json:"client_uri,omitempty"`
		LogoURI                 string                  `json:"logo_uri,omitempty"`
		Contacts                []string                `json:"contacts,omitempty"`
		TOSURI                  string                  `json:"tos_uri,omitempty"`
		PolicyURI               string                  `json:"policy_uri,omitempty"`
		SoftwareID              string                  `json:"software_id,omitempty"`
		SoftwareVersion         string                  `json:"software_version,omitempty"`
		RedirectURIs            []string                `json:"redirect_uris"`
		PostLogoutRedirectURIs  []string                `json:"post_logout_redirect_uris,omitempty"`
		TokenEndpointAuthMethod TokenEndpointAuthMethod `json:"token_endpoint_auth_method,omitempty"`
		GrantTypes              []GrantType             `json:"grant_types,omitempty"`
		ResponseTypes           []ResponseType          `json:"response_types,omitempty"`
		Scope                   string                  `json:"scope,omitempty"`
		Public                  bool                    `json:"public,omitempty"`
		SubjectType             SubjectType             `json:"subject_type,omitempty"`
		SkipConsent             bool                    `json:"skip_consent,omitempty"`
		EnableEndSession        bool                    `json:"enable_end_session,omitempty"`
		UserID                  *string                 `json:"user_id,omitempty"`
		Metadata                map[string]any          `json:"metadata,omitempty"`
		Extra                   map[string]any          `json:"extra,omitempty"`
	}

	// RegisterClientResult contains the registered client entity and generated secrets.
	RegisterClientResult struct {
		Client       *OAuthClient `json:"client"`
		ClientID     string       `json:"client_id"`
		ClientSecret string       `json:"client_secret,omitempty"`
	}

	// GetClientParams defines input parameters to lookup an OAuth client.
	GetClientParams struct {
		ClientID string         `json:"client_id"`
		Extra    map[string]any `json:"extra,omitempty"`
	}

	// GetClientResult contains the client entity.
	GetClientResult struct {
		Client *OAuthClient `json:"client"`
	}

	// UpdateClientParams defines input parameters to update an OAuth client.
	UpdateClientParams struct {
		ClientID               string         `json:"client_id"`
		ClientName             *string        `json:"client_name,omitempty"`
		ClientURI              *string        `json:"client_uri,omitempty"`
		LogoURI                *string        `json:"logo_uri,omitempty"`
		Contacts               []string       `json:"contacts,omitempty"`
		RedirectURIs           []string       `json:"redirect_uris,omitempty"`
		PostLogoutRedirectURIs []string       `json:"post_logout_redirect_uris,omitempty"`
		GrantTypes             []GrantType    `json:"grant_types,omitempty"`
		Scopes                 []string       `json:"scopes,omitempty"`
		SkipConsent            *bool          `json:"skip_consent,omitempty"`
		EnableEndSession       *bool          `json:"enable_end_session,omitempty"`
		Disabled               *bool          `json:"disabled,omitempty"`
		Metadata               map[string]any `json:"metadata,omitempty"`
		Extra                  map[string]any `json:"extra,omitempty"`
	}

	// UpdateClientResult contains the updated client entity.
	UpdateClientResult struct {
		Client *OAuthClient `json:"client"`
	}

	// DeleteClientParams defines input parameters to delete an OAuth client.
	DeleteClientParams struct {
		ClientID string         `json:"client_id"`
		Extra    map[string]any `json:"extra,omitempty"`
	}

	// DeleteClientResult reports the outcome of deleting a client.
	DeleteClientResult struct {
		Success bool `json:"success"`
	}

	// RotateClientSecretParams defines input parameters to rotate a client secret.
	RotateClientSecretParams struct {
		ClientID string         `json:"client_id"`
		Extra    map[string]any `json:"extra,omitempty"`
	}

	// RotateClientSecretResult contains the new raw client secret.
	RotateClientSecretResult struct {
		ClientID        string `json:"client_id"`
		NewClientSecret string `json:"new_client_secret"`
	}

	// OpenIDConfigurationParams defines input parameters for OpenID Provider metadata.
	OpenIDConfigurationParams struct {
		Extra map[string]any `json:"extra,omitempty"`
	}

	// OpenIDConfigurationResult represents discovery metadata (OpenID Connect Discovery 1.0).
	OpenIDConfigurationResult struct {
		Issuer                            string   `json:"issuer"`
		AuthorizationEndpoint             string   `json:"authorization_endpoint"`
		TokenEndpoint                     string   `json:"token_endpoint"`
		UserinfoEndpoint                  string   `json:"userinfo_endpoint"`
		IntrospectionEndpoint             string   `json:"introspection_endpoint"`
		RevocationEndpoint                string   `json:"revocation_endpoint"`
		EndSessionEndpoint                string   `json:"end_session_endpoint,omitempty"`
		RegistrationEndpoint              string   `json:"registration_endpoint,omitempty"`
		JwksURI                           string   `json:"jwks_uri,omitempty"`
		ResponseTypesSupported            []string `json:"response_types_supported"`
		SubjectTypesSupported             []string `json:"subject_types_supported"`
		IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
		ScopesSupported                   []string `json:"scopes_supported"`
		TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
		ClaimsSupported                   []string `json:"claims_supported"`
		CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
		GrantTypesSupported               []string `json:"grant_types_supported"`
	}

	// OAuthMetadataParams defines input parameters for RFC 8414 metadata.
	OAuthMetadataParams struct {
		Extra map[string]any `json:"extra,omitempty"`
	}

	// OAuthMetadataResult represents Authorization Server Metadata (RFC 8414).
	OAuthMetadataResult struct {
		Issuer                            string   `json:"issuer"`
		AuthorizationEndpoint             string   `json:"authorization_endpoint"`
		TokenEndpoint                     string   `json:"token_endpoint"`
		IntrospectionEndpoint             string   `json:"introspection_endpoint"`
		RevocationEndpoint                string   `json:"revocation_endpoint"`
		RegistrationEndpoint              string   `json:"registration_endpoint,omitempty"`
		ResponseTypesSupported            []string `json:"response_types_supported"`
		GrantTypesSupported               []string `json:"grant_types_supported"`
		CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
		TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
		ScopesSupported                   []string `json:"scopes_supported"`
	}
)

// Helper methods for attaching/retrieving metadata on parameter structs.

func (p *AuthorizeParams) Set(k string, v any) {
	if p.Extra == nil {
		p.Extra = make(map[string]any)
	}
	p.Extra[k] = v
}
func (p *AuthorizeParams) Get(k string) (any, bool) {
	if p.Extra == nil {
		return nil, false
	}
	v, ok := p.Extra[k]
	return v, ok
}

func (p *ContinueAuthorizeParams) Set(k string, v any) {
	if p.Extra == nil {
		p.Extra = make(map[string]any)
	}
	p.Extra[k] = v
}
func (p *ContinueAuthorizeParams) Get(k string) (any, bool) {
	if p.Extra == nil {
		return nil, false
	}
	v, ok := p.Extra[k]
	return v, ok
}

func (p *ConsentParams) Set(k string, v any) {
	if p.Extra == nil {
		p.Extra = make(map[string]any)
	}
	p.Extra[k] = v
}
func (p *ConsentParams) Get(k string) (any, bool) {
	if p.Extra == nil {
		return nil, false
	}
	v, ok := p.Extra[k]
	return v, ok
}

func (p *TokenParams) Set(k string, v any) {
	if p.Extra == nil {
		p.Extra = make(map[string]any)
	}
	p.Extra[k] = v
}
func (p *TokenParams) Get(k string) (any, bool) {
	if p.Extra == nil {
		return nil, false
	}
	v, ok := p.Extra[k]
	return v, ok
}

func (p *IntrospectParams) Set(k string, v any) {
	if p.Extra == nil {
		p.Extra = make(map[string]any)
	}
	p.Extra[k] = v
}
func (p *IntrospectParams) Get(k string) (any, bool) {
	if p.Extra == nil {
		return nil, false
	}
	v, ok := p.Extra[k]
	return v, ok
}

func (p *RevokeParams) Set(k string, v any) {
	if p.Extra == nil {
		p.Extra = make(map[string]any)
	}
	p.Extra[k] = v
}
func (p *RevokeParams) Get(k string) (any, bool) {
	if p.Extra == nil {
		return nil, false
	}
	v, ok := p.Extra[k]
	return v, ok
}

func (p *UserInfoParams) Set(k string, v any) {
	if p.Extra == nil {
		p.Extra = make(map[string]any)
	}
	p.Extra[k] = v
}
func (p *UserInfoParams) Get(k string) (any, bool) {
	if p.Extra == nil {
		return nil, false
	}
	v, ok := p.Extra[k]
	return v, ok
}

func (p *EndSessionParams) Set(k string, v any) {
	if p.Extra == nil {
		p.Extra = make(map[string]any)
	}
	p.Extra[k] = v
}
func (p *EndSessionParams) Get(k string) (any, bool) {
	if p.Extra == nil {
		return nil, false
	}
	v, ok := p.Extra[k]
	return v, ok
}

func (p *RegisterClientParams) Set(k string, v any) {
	if p.Extra == nil {
		p.Extra = make(map[string]any)
	}
	p.Extra[k] = v
}
func (p *RegisterClientParams) Get(k string) (any, bool) {
	if p.Extra == nil {
		return nil, false
	}
	v, ok := p.Extra[k]
	return v, ok
}

// Plugin implements plugin.Plugin for the OAuth 2.1 & OpenID Connect Provider.
type Plugin struct {
	repo   Repository
	config Config
	ctx    *plugin.Context
	signer JWTSigner
	mu     sync.RWMutex
}

// New creates a new OAuth 2.1 Provider plugin with the given repository and options.
func New(repo Repository, opts ...Option) *Plugin {
	cfg := DefaultConfig()
	for _, opt := range opts {
		opt(&cfg)
	}

	var signer JWTSigner = cfg.JWTSigner
	if signer == nil {
		signer = NewHMACSigner(cfg.SecretKey, "default-oauth2-hmac")
	}

	return &Plugin{
		repo:   repo,
		config: cfg,
		signer: signer,
	}
}

// ID returns the unique identifier for the OAuth 2.1 plugin.
func (p *Plugin) ID() string {
	return PluginID
}

// Init initializes the plugin within the shared plugin.Context environment.
func (p *Plugin) Init(ctx *plugin.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.ctx = ctx
	return nil
}

// Config returns the current configuration of the plugin.
func (p *Plugin) Config() Config {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.config
}

// Repository returns the underlying storage repository.
func (p *Plugin) Repository() Repository {
	return p.repo
}
