package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ProfileExtractorFunc is a function that parses raw JSON profile bytes into a ProviderProfile.
type ProfileExtractorFunc func(ctx context.Context, rawBody []byte, token *TokenResponse) (*ProviderProfile, error)

// GenericConfig configures a GenericProvider instance.
type GenericConfig struct {
	// Name uniquely identifies the provider (e.g. "google", "github").
	Name string

	// ClientID is the public OAuth client identifier issued by the provider.
	ClientID string

	// ClientSecret is the confidential OAuth client secret issued by the provider.
	ClientSecret string

	// AuthURL is the authorization endpoint URL where users are redirected.
	AuthURL string

	// TokenURL is the token endpoint URL where codes are exchanged for tokens.
	TokenURL string

	// UserInfoURL is the endpoint URL where user claims / profile data are fetched.
	UserInfoURL string

	// Scopes are the default scopes requested during authorization.
	Scopes []string

	// AllowedRedirectURIs defines valid redirect URIs for this provider.
	// Empty list means all non-empty redirect URIs are allowed (not recommended for production).
	AllowedRedirectURIs []string

	// HTTPClient is the HTTP client used to perform outbound requests to the provider.
	// Defaults to http.DefaultClient with a 15-second timeout if nil.
	HTTPClient *http.Client

	// ProfileExtractor customizes the parsing of user profile responses.
	// If nil, StandardProfileExtractor is used.
	ProfileExtractor ProfileExtractorFunc
}

// GenericProvider is an RFC 6749 and RFC 7636 compliant OAuth 2.0 / OIDC provider implementation.
type GenericProvider struct {
	cfg GenericConfig
}

var _ Provider = (*GenericProvider)(nil)

// NewGenericProvider constructs a validated GenericProvider.
func NewGenericProvider(cfg GenericConfig) (*GenericProvider, error) {
	if cfg.Name == "" {
		return nil, errors.New("provider: name is required")
	}
	if cfg.ClientID == "" {
		return nil, errors.New("provider: client_id is required")
	}
	if cfg.AuthURL == "" {
		return nil, errors.New("provider: auth_url is required")
	}
	if cfg.TokenURL == "" {
		return nil, errors.New("provider: token_url is required")
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 15 * time.Second}
	}
	if cfg.ProfileExtractor == nil {
		cfg.ProfileExtractor = StandardProfileExtractor(cfg.Name)
	}

	return &GenericProvider{cfg: cfg}, nil
}

// Name returns the provider's unique identifier.
func (p *GenericProvider) Name() string {
	return p.cfg.Name
}

// ValidateRedirectURI checks whether redirectURI is allowed for this provider.
func (p *GenericProvider) ValidateRedirectURI(redirectURI string) bool {
	if redirectURI == "" {
		return false
	}
	if len(p.cfg.AllowedRedirectURIs) == 0 {
		return true
	}
	for _, allowed := range p.cfg.AllowedRedirectURIs {
		if allowed == redirectURI {
			return true
		}
	}
	return false
}

// AuthCodeURL constructs the authorization redirect URL with state and parameters.
func (p *GenericProvider) AuthCodeURL(state string, opts ...AuthCodeOption) string {
	var c AuthCodeConfig
	for _, opt := range opts {
		opt(&c)
	}

	u, err := url.Parse(p.cfg.AuthURL)
	if err != nil {
		return p.cfg.AuthURL
	}

	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", p.cfg.ClientID)
	q.Set("state", state)

	redirectURI := c.RedirectURI
	if redirectURI == "" && len(p.cfg.AllowedRedirectURIs) > 0 {
		redirectURI = p.cfg.AllowedRedirectURIs[0]
	}
	if redirectURI != "" {
		q.Set("redirect_uri", redirectURI)
	}

	scopes := p.cfg.Scopes
	if len(c.Scopes) > 0 {
		scopes = c.Scopes
	}
	if len(scopes) > 0 {
		q.Set("scope", strings.Join(scopes, " "))
	}

	if c.CodeChallenge != "" {
		q.Set("code_challenge", c.CodeChallenge)
		method := c.CodeChallengeMethod
		if method == "" {
			method = "S256"
		}
		q.Set("code_challenge_method", method)
	}

	if c.Prompt != "" {
		q.Set("prompt", c.Prompt)
	}
	if c.AccessType != "" {
		q.Set("access_type", c.AccessType)
	}

	for k, v := range c.ExtraParams {
		q.Set(k, v)
	}

	u.RawQuery = q.Encode()
	return u.String()
}

// Exchange exchanges the authorization code for tokens.
func (p *GenericProvider) Exchange(ctx context.Context, code string, opts ...ExchangeOption) (*TokenResponse, error) {
	var c ExchangeConfig
	for _, opt := range opts {
		opt(&c)
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("client_id", p.cfg.ClientID)

	if p.cfg.ClientSecret != "" {
		form.Set("client_secret", p.cfg.ClientSecret)
	}

	if c.RedirectURI != "" {
		form.Set("redirect_uri", c.RedirectURI)
	}
	if c.CodeVerifier != "" {
		form.Set("code_verifier", c.CodeVerifier)
	}
	for k, v := range c.ExtraParams {
		form.Set(k, v)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.cfg.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("provider: create token request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := p.cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("provider: execute token request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB max
	if err != nil {
		return nil, fmt.Errorf("provider: read token response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("provider: token exchange returned status %d: %s", resp.StatusCode, string(body))
	}

	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		// Some providers (like GitHub without header) might return form-urlencoded
		vals, parseErr := url.ParseQuery(string(body))
		if parseErr == nil && vals.Get("access_token") != "" {
			raw = make(map[string]any)
			for k, v := range vals {
				if len(v) > 0 {
					raw[k] = v[0]
				}
			}
		} else {
			return nil, fmt.Errorf("provider: parse token response JSON: %w", err)
		}
	}

	if errStr, ok := raw["error"].(string); ok && errStr != "" {
		desc, _ := raw["error_description"].(string)
		return nil, fmt.Errorf("provider: token exchange error %q: %s", errStr, desc)
	}

	accessToken, _ := raw["access_token"].(string)
	if accessToken == "" {
		return nil, errors.New("provider: token exchange response missing access_token")
	}

	tokenType, _ := raw["token_type"].(string)
	if tokenType == "" {
		tokenType = "Bearer"
	}

	refreshToken, _ := raw["refresh_token"].(string)
	idToken, _ := raw["id_token"].(string)
	scope, _ := raw["scope"].(string)

	var expiresIn int64
	switch v := raw["expires_in"].(type) {
	case float64:
		expiresIn = int64(v)
	case int64:
		expiresIn = v
	case string:
		_ = json.Unmarshal([]byte(v), &expiresIn)
	}

	var expiresAt time.Time
	if expiresIn > 0 {
		expiresAt = time.Now().Add(time.Duration(expiresIn) * time.Second)
	}

	return &TokenResponse{
		AccessToken:  accessToken,
		TokenType:    tokenType,
		RefreshToken: refreshToken,
		ExpiresIn:    expiresIn,
		ExpiresAt:    expiresAt,
		Scope:        scope,
		IDToken:      idToken,
		Raw:          raw,
	}, nil
}

// FetchProfile retrieves and normalizes user profile information from the UserInfo endpoint.
func (p *GenericProvider) FetchProfile(ctx context.Context, tokens *TokenResponse) (*ProviderProfile, error) {
	if p.cfg.UserInfoURL == "" {
		return nil, errors.New("provider: userinfo endpoint is not configured")
	}
	if tokens == nil || tokens.AccessToken == "" {
		return nil, errors.New("provider: access token is required to fetch profile")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.cfg.UserInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("provider: create userinfo request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("%s %s", tokens.TokenType, tokens.AccessToken))
	req.Header.Set("Accept", "application/json")

	resp, err := p.cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("provider: execute userinfo request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB limit
	if err != nil {
		return nil, fmt.Errorf("provider: read userinfo body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("provider: userinfo returned status %d: %s", resp.StatusCode, string(body))
	}

	profile, err := p.cfg.ProfileExtractor(ctx, body, tokens)
	if err != nil {
		return nil, fmt.Errorf("provider: extract profile: %w", err)
	}
	if profile.Provider == "" {
		profile.Provider = p.cfg.Name
	}
	if profile.ProviderID == "" {
		return nil, errors.New("provider: extracted profile missing subject / provider_id")
	}

	return profile, nil
}

// StandardProfileExtractor returns a default claim parser extracting subject, email, name, avatar.
func StandardProfileExtractor(providerName string) ProfileExtractorFunc {
	return func(ctx context.Context, rawBody []byte, token *TokenResponse) (*ProviderProfile, error) {
		var claims map[string]any
		if err := json.Unmarshal(rawBody, &claims); err != nil {
			return nil, err
		}

		// Identify Subject / ID: standard OIDC uses "sub", many APIs use "id"
		var sub string
		if s, ok := claims["sub"].(string); ok && s != "" {
			sub = s
		} else if s, ok := claims["id"].(string); ok && s != "" {
			sub = s
		} else if idNum, ok := claims["id"].(float64); ok {
			sub = fmt.Sprintf("%.0f", idNum)
		}

		// Identify Email
		var email string
		if e, ok := claims["email"].(string); ok {
			email = strings.ToLower(strings.TrimSpace(e))
		}

		// Identify Email Verified: standard OIDC "email_verified"
		var emailVerified bool
		switch v := claims["email_verified"].(type) {
		case bool:
			emailVerified = v
		case string:
			emailVerified = strings.EqualFold(v, "true")
		}

		// Name / Username / Avatar
		name, _ := claims["name"].(string)
		username, _ := claims["preferred_username"].(string)
		if username == "" {
			username, _ = claims["login"].(string)
		}

		avatar, _ := claims["picture"].(string)
		if avatar == "" {
			avatar, _ = claims["avatar_url"].(string)
		}

		return &ProviderProfile{
			Provider:      providerName,
			ProviderID:    sub,
			Email:         email,
			EmailVerified: emailVerified,
			Name:          name,
			Username:      username,
			AvatarURL:     avatar,
			Raw:           claims,
		}, nil
	}
}
