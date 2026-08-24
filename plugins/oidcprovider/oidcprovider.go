package oidcprovider

import (
	"context"
	"net/url"
	"strings"
	"time"

	"github.com/BladiCreator/go-modular-auth/plugin"
	"github.com/google/uuid"
)

// PluginID is the unique string identifier for the OIDC Provider plugin ("oidc-provider").
const PluginID = "oidc-provider"

// GrantTypeAuthorizationCode is the RFC 6749 authorization_code grant type string.
const GrantTypeAuthorizationCode = "authorization_code"

// GrantTypeRefreshToken is the RFC 6749 refresh_token grant type string.
const GrantTypeRefreshToken = "refresh_token"

// Plugin implements the OpenID Connect 1.0 / OAuth 2.0 Provider plugin for go-modular-auth.
type Plugin struct {
	repo   Repository
	config Config
	ctx    *plugin.Context
}

// New instantiates a new OIDC Provider plugin configured with the given repository and options.
func New(repo Repository, opts ...Option) *Plugin {
	cfg := DefaultConfig()
	for _, opt := range opts {
		opt(&cfg)
	}

	return &Plugin{
		repo:   repo,
		config: cfg,
	}
}

// ID returns the unique string identifier for the plugin ("oidc-provider").
func (p *Plugin) ID() string {
	return PluginID
}

// Init initializes the plugin within the shared plugin context environment.
func (p *Plugin) Init(ctx *plugin.Context) error {
	p.ctx = ctx
	return nil
}

// Config returns a copy of the active plugin configuration.
func (p *Plugin) Config() Config {
	return p.config
}

// RegisterClient registers a new OAuth 2.0 / OIDC client application.
func (p *Plugin) RegisterClient(ctx context.Context, params RegisterClientParams) (*OAuthClient, error) {
	if strings.TrimSpace(params.Name) == "" {
		return nil, ErrInvalidRequest
	}

	if len(params.RedirectURIs) == 0 {
		return nil, ErrInvalidRequest
	}

	for _, uri := range params.RedirectURIs {
		parsed, err := url.Parse(uri)
		if err != nil || !parsed.IsAbs() {
			return nil, ErrInvalidRequest
		}
	}

	clientID, err := GenerateRandomString(24)
	if err != nil {
		return nil, err
	}
	clientID = "client_" + clientID

	var clientSecretPtr *string
	if params.Type != ClientTypePublic && params.Type != ClientTypeUserAgentBased {
		secret, err := GenerateRandomString(40)
		if err != nil {
			return nil, err
		}
		clientSecretPtr = &secret
	}

	now := time.Now()
	client := &OAuthClient{
		ID:           uuid.New().String(),
		ClientID:     clientID,
		ClientSecret: clientSecretPtr,
		Type:         params.Type,
		Name:         params.Name,
		Icon:         params.Icon,
		Metadata:     params.Metadata,
		RedirectURIs: params.RedirectURIs,
		Disabled:     false,
		UserID:       params.UserID,
		SkipConsent:  params.SkipConsent,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := p.repo.CreateClient(ctx, client); err != nil {
		return nil, err
	}

	if p.ctx != nil && p.ctx.Events() != nil {
		p.ctx.Events().Publish(EventOIDCClientRegistered, ctx, &OIDCClientRegisteredPayload{
			Client: client,
		})
	}

	return client, nil
}

// GetClient retrieves a registered OAuth client application by client_id.
func (p *Plugin) GetClient(ctx context.Context, clientID string) (*OAuthClient, error) {
	if clientID == "" {
		return nil, ErrInvalidClient
	}
	client, err := p.repo.FindByClientID(ctx, clientID)
	if err != nil || client == nil || client.Disabled {
		return nil, ErrInvalidClient
	}
	return client, nil
}

// Authorize processes an OAuth 2.0 / OIDC authorization request.
func (p *Plugin) Authorize(ctx context.Context, params AuthorizeParams) (*AuthorizeResponse, error) {
	if params.ClientID == "" || params.RedirectURI == "" || params.UserID == "" {
		return nil, ErrInvalidRequest
	}

	client, err := p.GetClient(ctx, params.ClientID)
	if err != nil {
		return nil, err
	}

	if !ValidateRedirectURI(params.RedirectURI, client.RedirectURIs) {
		return nil, ErrInvalidRequest
	}

	if params.ResponseType != "code" {
		return nil, ErrUnsupportedGrantType
	}

	if p.config.RequirePKCE {
		if params.CodeChallenge == nil || strings.TrimSpace(*params.CodeChallenge) == "" {
			return nil, ErrInvalidRequest
		}
	}

	scopesRequested := ParseScopes(params.Scope)
	if len(scopesRequested) == 0 {
		scopesRequested = ParseScopes(p.config.DefaultScope)
	}

	// Check consent unless skipped by client or prompt="none"
	requiresConsent := false
	if !client.SkipConsent {
		if params.Prompt != nil && *params.Prompt == "consent" {
			requiresConsent = true
		} else {
			existingConsent, err := p.repo.GetConsent(ctx, params.ClientID, params.UserID)
			if err != nil || existingConsent == nil || !existingConsent.ConsentGiven {
				requiresConsent = true
			} else {
				grantedList := ParseScopes(existingConsent.Scopes)
				if !HasAllScopes(grantedList, scopesRequested) {
					requiresConsent = true
				}
			}
		}
	}

	if requiresConsent {
		consentCode, err := GenerateRandomString(32)
		if err != nil {
			return nil, err
		}

		return &AuthorizeResponse{
			RedirectURI:     params.RedirectURI,
			RequiresConsent: true,
			ConsentCode:     &consentCode,
			ScopesRequested: scopesRequested,
			ClientInfo:      client,
			State:           params.State,
		}, nil
	}

	// Generate authorization code
	codeStr, err := GenerateRandomString(36)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	codeRecord := &OAuthCode{
		ID:                  uuid.New().String(),
		Code:                codeStr,
		ClientID:            client.ClientID,
		UserID:              params.UserID,
		RedirectURI:         params.RedirectURI,
		Scope:               NormalizeScopes(scopesRequested),
		State:               params.State,
		Nonce:               params.Nonce,
		CodeChallenge:       params.CodeChallenge,
		CodeChallengeMethod: params.CodeChallengeMethod,
		ExpiresAt:           now.Add(p.config.CodeExpiresIn),
		Consumed:            false,
		CreatedAt:           now,
	}

	if err := p.repo.CreateAuthorizationCode(ctx, codeRecord); err != nil {
		return nil, err
	}

	if p.ctx != nil && p.ctx.Events() != nil {
		p.ctx.Events().Publish(EventOIDCAuthCodeIssued, ctx, &OIDCAuthCodeIssuedPayload{
			Code:     codeStr,
			ClientID: client.ClientID,
			UserID:   params.UserID,
		})
	}

	redirectURL, err := url.Parse(params.RedirectURI)
	if err != nil {
		return nil, ErrInvalidRequest
	}

	q := redirectURL.Query()
	q.Set("code", codeStr)
	if params.State != nil && *params.State != "" {
		q.Set("state", *params.State)
	}
	redirectURL.RawQuery = q.Encode()

	finalRedirectURI := redirectURL.String()

	return &AuthorizeResponse{
		RedirectURI:     finalRedirectURI,
		Code:            &codeStr,
		State:           params.State,
		RequiresConsent: false,
	}, nil
}

// GrantConsent saves user consent and returns authorization parameters.
func (p *Plugin) GrantConsent(ctx context.Context, params GrantConsentParams) (*AuthorizeResponse, error) {
	if params.ClientID == "" || params.UserID == "" {
		return nil, ErrInvalidRequest
	}

	if !params.Accept {
		return nil, ErrAccessDenied
	}

	now := time.Now()
	consent := &OAuthConsent{
		ID:           uuid.New().String(),
		ClientID:     params.ClientID,
		UserID:       params.UserID,
		Scopes:       NormalizeScopes(params.Scopes),
		ConsentGiven: true,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := p.repo.SaveConsent(ctx, consent); err != nil {
		return nil, err
	}

	if p.ctx != nil && p.ctx.Events() != nil {
		p.ctx.Events().Publish(EventOIDCConsentGranted, ctx, &OIDCConsentGrantedPayload{
			ClientID: params.ClientID,
			UserID:   params.UserID,
			Scopes:   params.Scopes,
		})
	}

	return nil, nil
}

// ExchangeToken exchanges an authorization code or refresh token for Access, Refresh, and ID Tokens.
func (p *Plugin) ExchangeToken(ctx context.Context, params ExchangeTokenParams) (*TokenResponse, error) {
	if params.ClientID == "" {
		return nil, ErrInvalidClient
	}

	client, err := p.GetClient(ctx, params.ClientID)
	if err != nil {
		return nil, err
	}

	// Verify client_secret if client is confidential
	if client.Type != ClientTypePublic && client.Type != ClientTypeUserAgentBased {
		if params.ClientSecret == nil || client.ClientSecret == nil {
			return nil, ErrInvalidClient
		}
		if !ConstantTimeEqual(*params.ClientSecret, *client.ClientSecret) {
			return nil, ErrInvalidClient
		}
	}

	switch params.GrantType {
	case GrantTypeAuthorizationCode:
		if params.Code == nil || *params.Code == "" {
			return nil, ErrInvalidRequest
		}

		codeRecord, err := p.repo.ConsumeAuthorizationCode(ctx, *params.Code)
		if err != nil {
			if errorsIs(err, ErrCodeAlreadyConsumed) {
				// Revoke all tokens issued for this client and user to protect against code reuse (RFC 6749 4.1.2)
				_ = p.repo.RevokeTokensByClientIDAndUserID(ctx, params.ClientID, "")
				return nil, ErrCodeAlreadyConsumed
			}
			return nil, ErrInvalidGrant
		}

		if codeRecord == nil {
			return nil, ErrInvalidGrant
		}

		if codeRecord.ExpiresAt.Before(time.Now()) {
			return nil, ErrInvalidGrant
		}

		if params.RedirectURI != nil && *params.RedirectURI != "" {
			if !ConstantTimeEqual(*params.RedirectURI, codeRecord.RedirectURI) {
				return nil, ErrInvalidGrant
			}
		}

		// Validate PKCE if code_challenge was present
		if codeRecord.CodeChallenge != nil && *codeRecord.CodeChallenge != "" {
			if params.CodeVerifier == nil || *params.CodeVerifier == "" {
				return nil, ErrPKCEValidationFailed
			}
			method := "S256"
			if codeRecord.CodeChallengeMethod != nil {
				method = *codeRecord.CodeChallengeMethod
			}
			if !ValidatePKCE(*params.CodeVerifier, *codeRecord.CodeChallenge, method, p.config.AllowPlainCodeChallenge) {
				return nil, ErrPKCEValidationFailed
			}
		}

		user, err := p.repo.GetUserByID(ctx, codeRecord.UserID)
		if err != nil || user == nil {
			return nil, ErrUserNotFound
		}

		accessTokenStr, err := GenerateBase64URLToken(32)
		if err != nil {
			return nil, err
		}

		refreshTokenStr, err := GenerateBase64URLToken(40)
		if err != nil {
			return nil, err
		}

		now := time.Now()
		tokenRecord := &OAuthToken{
			ID:                    uuid.New().String(),
			AccessToken:           accessTokenStr,
			RefreshToken:          refreshTokenStr,
			ClientID:              client.ClientID,
			UserID:                user.ID,
			Scope:                 codeRecord.Scope,
			AccessTokenExpiresAt:  now.Add(p.config.AccessTokenExpiresIn),
			RefreshTokenExpiresAt: now.Add(p.config.RefreshTokenExpiresIn),
			CreatedAt:             now,
			UpdatedAt:             now,
		}

		if err := p.repo.CreateTokenPair(ctx, tokenRecord); err != nil {
			return nil, err
		}

		var idTokenStr string
		if HasScope(ParseScopes(codeRecord.Scope), "openid") {
			idTokenStr, err = p.GenerateIDToken(ctx, user, client, codeRecord.Scope, codeRecord.Nonce, &accessTokenStr, p.config.AccessTokenExpiresIn)
			if err != nil {
				return nil, err
			}
		}

		if p.ctx != nil && p.ctx.Events() != nil {
			p.ctx.Events().Publish(EventOIDCTokenIssued, ctx, &OIDCTokenIssuedPayload{
				AccessToken:  accessTokenStr,
				RefreshToken: refreshTokenStr,
				IDToken:      idTokenStr,
				ClientID:     client.ClientID,
				UserID:       user.ID,
			})
		}

		return &TokenResponse{
			AccessToken:  accessTokenStr,
			TokenType:    "Bearer",
			ExpiresIn:    int64(p.config.AccessTokenExpiresIn.Seconds()),
			RefreshToken: refreshTokenStr,
			IDToken:      idTokenStr,
			Scope:        codeRecord.Scope,
		}, nil

	case GrantTypeRefreshToken:
		if params.RefreshToken == nil || *params.RefreshToken == "" {
			return nil, ErrInvalidRequest
		}

		tokenRecord, err := p.repo.FindByRefreshToken(ctx, *params.RefreshToken)
		if err != nil || tokenRecord == nil {
			return nil, ErrInvalidGrant
		}

		if tokenRecord.RefreshTokenExpiresAt.Before(time.Now()) {
			_ = p.repo.RevokeTokenPair(ctx, tokenRecord.ID)
			return nil, ErrInvalidGrant
		}

		user, err := p.repo.GetUserByID(ctx, tokenRecord.UserID)
		if err != nil || user == nil {
			return nil, ErrUserNotFound
		}

		// Revoke old token pair
		_ = p.repo.RevokeTokenPair(ctx, tokenRecord.ID)

		newAccessTokenStr, err := GenerateBase64URLToken(32)
		if err != nil {
			return nil, err
		}

		newRefreshTokenStr, err := GenerateBase64URLToken(40)
		if err != nil {
			return nil, err
		}

		now := time.Now()
		newTokenRecord := &OAuthToken{
			ID:                    uuid.New().String(),
			AccessToken:           newAccessTokenStr,
			RefreshToken:          newRefreshTokenStr,
			ClientID:              client.ClientID,
			UserID:                user.ID,
			Scope:                 tokenRecord.Scope,
			AccessTokenExpiresAt:  now.Add(p.config.AccessTokenExpiresIn),
			RefreshTokenExpiresAt: now.Add(p.config.RefreshTokenExpiresIn),
			CreatedAt:             now,
			UpdatedAt:             now,
		}

		if err := p.repo.CreateTokenPair(ctx, newTokenRecord); err != nil {
			return nil, err
		}

		var idTokenStr string
		if HasScope(ParseScopes(tokenRecord.Scope), "openid") {
			idTokenStr, err = p.GenerateIDToken(ctx, user, client, tokenRecord.Scope, nil, &newAccessTokenStr, p.config.AccessTokenExpiresIn)
			if err != nil {
				return nil, err
			}
		}

		if p.ctx != nil && p.ctx.Events() != nil {
			p.ctx.Events().Publish(EventOIDCTokenRefreshed, ctx, &OIDCTokenRefreshedPayload{
				NewAccessToken:  newAccessTokenStr,
				NewRefreshToken: newRefreshTokenStr,
				ClientID:        client.ClientID,
				UserID:          user.ID,
			})
		}

		return &TokenResponse{
			AccessToken:  newAccessTokenStr,
			TokenType:    "Bearer",
			ExpiresIn:    int64(p.config.AccessTokenExpiresIn.Seconds()),
			RefreshToken: newRefreshTokenStr,
			IDToken:      idTokenStr,
			Scope:        tokenRecord.Scope,
		}, nil

	default:
		return nil, ErrUnsupportedGrantType
	}
}

// GetUserInfo returns standard OIDC UserInfo claims for a valid access_token.
func (p *Plugin) GetUserInfo(ctx context.Context, accessToken string) (UserInfoClaims, error) {
	if accessToken == "" {
		return nil, ErrInvalidGrant
	}

	tokenRecord, err := p.repo.FindByAccessToken(ctx, accessToken)
	if err != nil || tokenRecord == nil {
		return nil, ErrInvalidGrant
	}

	if tokenRecord.AccessTokenExpiresAt.Before(time.Now()) {
		return nil, ErrInvalidGrant
	}

	user, err := p.repo.GetUserByID(ctx, tokenRecord.UserID)
	if err != nil || user == nil {
		return nil, ErrUserNotFound
	}

	scopesList := ParseScopes(tokenRecord.Scope)
	claims := UserInfoClaims{
		"sub": user.ID,
	}

	if HasScope(scopesList, "email") {
		claims["email"] = user.Email
		claims["email_verified"] = user.EmailVerified
	}

	if HasScope(scopesList, "profile") {
		if user.Name != "" {
			claims["name"] = user.Name
		}
		if user.Username != "" {
			claims["preferred_username"] = user.Username
		}
		if user.DisplayUsername != "" {
			claims["nickname"] = user.DisplayUsername
		}
	}

	if p.config.GetAdditionalClaims != nil {
		client, _ := p.repo.FindByClientID(ctx, tokenRecord.ClientID)
		additional := p.config.GetAdditionalClaims(ctx, user, scopesList, client)
		for k, v := range additional {
			claims[k] = v
		}
	}

	return claims, nil
}

// EndSession processes RP-Initiated Logout.
func (p *Plugin) EndSession(ctx context.Context, idTokenHint string, postLogoutRedirectURI *string) (string, error) {
	if idTokenHint != "" {
		claims, err := p.VerifyJWT(idTokenHint)
		if err == nil && claims != nil {
			if sub, ok := claims["sub"].(string); ok {
				_ = p.repo.RevokeTokensByClientIDAndUserID(ctx, "", sub)
			}
		}
	}

	if postLogoutRedirectURI != nil && *postLogoutRedirectURI != "" {
		return *postLogoutRedirectURI, nil
	}

	return p.config.BaseURL, nil
}

// GetDiscoveryMetadata generates the OpenID Connect Discovery 1.0 JSON configuration metadata.
func (p *Plugin) GetDiscoveryMetadata(ctx context.Context) (*DiscoveryMetadata, error) {
	baseURL := strings.TrimSuffix(p.config.BaseURL, "/")
	issuer := strings.TrimSuffix(p.config.Issuer, "/")

	return &DiscoveryMetadata{
		Issuer:                            issuer,
		AuthorizationEndpoint:             baseURL + "/oauth2/authorize",
		TokenEndpoint:                     baseURL + "/oauth2/token",
		UserinfoEndpoint:                  baseURL + "/oauth2/userinfo",
		JwksURI:                           baseURL + "/.well-known/jwks.json",
		EndSessionEndpoint:                baseURL + "/oauth2/logout",
		ScopesSupported:                   p.config.SupportedScopes,
		ResponseTypesSupported:            []string{"code"},
		ResponseModesSupported:            []string{"query"},
		GrantTypesSupported:               []string{"authorization_code", "refresh_token"},
		SubjectTypesSupported:             []string{"public"},
		IDTokenSigningAlgValuesSupported:  []string{p.config.SigningAlgorithm},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_post", "client_secret_basic", "none"},
	}, nil
}

func errorsIs(err, target error) bool {
	return err == target || (err != nil && target != nil && err.Error() == target.Error())
}
