package oauth2

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Authorize handles the authorization step of the OAuth 2.1 Authorization Code Flow.
func (p *Plugin) Authorize(ctx context.Context, params AuthorizeParams) (*AuthorizeResult, error) {
	if strings.TrimSpace(params.ClientID) == "" {
		return nil, ErrInvalidClient
	}
	if strings.TrimSpace(params.RedirectURI) == "" {
		return nil, ErrInvalidRedirectURI
	}

	client, err := p.repo.FindClientByClientID(ctx, params.ClientID)
	if err != nil || client == nil {
		return nil, ErrClientNotFound
	}
	if client.Disabled {
		return nil, ErrClientDisabled
	}

	// Exact redirect URI validation
	if !isAllowedRedirectURI(params.RedirectURI, client.RedirectURIs) {
		return nil, ErrInvalidRedirectURI
	}

	// OAuth 2.1: response_type must be "code"
	if params.ResponseType != string(ResponseTypeCode) {
		return nil, ErrInvalidResponseType
	}

	// OAuth 2.1: PKCE with S256 is mandatory
	if params.CodeChallengeMethod != CodeChallengeMethodS256 {
		return nil, ErrInvalidCodeChallengeMethod
	}
	if strings.TrimSpace(params.CodeChallenge) == "" {
		return nil, ErrInvalidPKCE
	}

	// Parse and normalize scopes
	requestedScopes := parseScopes(params.Scope)
	if len(requestedScopes) == 0 {
		requestedScopes = []string{ScopeOpenID}
	}

	// Check user authentication
	userID := strings.TrimSpace(params.UserID)
	sessionID := strings.TrimSpace(params.SessionID)

	if userID == "" && sessionID != "" {
		sess, err := p.repo.FindSessionByID(ctx, sessionID)
		if err == nil && sess != nil && sess.ExpiresAt.After(time.Now().UTC()) {
			userID = sess.UserID
		}
	}

	rawQuery := buildQueryString(params, requestedScopes)
	sig := SignOAuthQuery(rawQuery, p.config.SecretKey)

	// User not authenticated
	if userID == "" || params.Prompt == PromptLogin {
		if params.Prompt == PromptNone {
			p.publishAuthorizeFailed(params.ClientID, "login_required", params.RedirectURI)
			return nil, ErrLoginRequired
		}

		loginRedirect := fmt.Sprintf("%s?oauth_query=%s&oauth_signature=%s",
			p.config.LoginPage, url.QueryEscape(rawQuery), sig)

		return &AuthorizeResult{
			RedirectURI: loginRedirect,
			IsRedirect:  true,
			NeedsLogin:  true,
			State:       params.State,
			Issuer:      p.config.Issuer,
		}, nil
	}

	// Check User Consent
	needsConsent := !client.SkipConsent
	if needsConsent && params.Prompt != PromptConsent {
		consent, err := p.repo.FindConsent(ctx, client.ClientID, userID)
		if err == nil && consent != nil && hasAllScopes(consent.Scopes, requestedScopes) {
			needsConsent = false
		}
	}

	if needsConsent {
		if params.Prompt == PromptNone {
			p.publishAuthorizeFailed(params.ClientID, "consent_required", params.RedirectURI)
			return nil, ErrConsentRequired
		}

		consentRedirect := fmt.Sprintf("%s?oauth_query=%s&oauth_signature=%s",
			p.config.ConsentPage, url.QueryEscape(rawQuery), sig)

		return &AuthorizeResult{
			RedirectURI:  consentRedirect,
			IsRedirect:   true,
			NeedsConsent: true,
			State:        params.State,
			Issuer:       p.config.Issuer,
		}, nil
	}

	// All checks passed: Issue single-use Authorization Code
	rawCode, err := GenerateRandomString(32)
	if err != nil {
		return nil, fmt.Errorf("oauth2: failed to generate authorization code: %w", err)
	}

	storedCodeValue := rawCode
	if p.config.StoreTokensMode == StoreModeHashed {
		storedCodeValue = HashToken(rawCode)
	} else if p.config.StoreTokensMode == StoreModeEncrypted {
		enc, err := Encrypt([]byte(rawCode), DeriveAESKey(p.config.SecretKey))
		if err != nil {
			return nil, fmt.Errorf("oauth2: failed to encrypt authorization code: %w", err)
		}
		storedCodeValue = enc
	}

	now := time.Now().UTC()
	authCodeRecord := &OAuthAuthorizationCode{
		ID:                  uuid.New().String(),
		Code:                storedCodeValue,
		ClientID:            client.ClientID,
		UserID:              userID,
		SessionID:           sessionID,
		RedirectURI:         params.RedirectURI,
		CodeChallenge:       params.CodeChallenge,
		CodeChallengeMethod: params.CodeChallengeMethod,
		Scopes:              requestedScopes,
		Nonce:               params.Nonce,
		Resource:            params.Resource,
		ExpiresAt:           now.Add(p.config.CodeExpiresIn),
		CreatedAt:           now,
	}

	if err := p.repo.CreateAuthorizationCode(ctx, authCodeRecord); err != nil {
		return nil, fmt.Errorf("oauth2: failed to store authorization code: %w", err)
	}

	// Construct callback URL with RFC 9207 'iss' parameter
	callbackURL := buildCallbackURL(params.RedirectURI, rawCode, params.State, p.config.Issuer)

	if p.ctx != nil && p.ctx.Events() != nil {
		p.ctx.Events().Publish(EventAuthorizeSuccess, &AuthorizeSuccessEventPayload{
			ClientID:    client.ClientID,
			UserID:      userID,
			RedirectURI: params.RedirectURI,
			Scopes:      requestedScopes,
			Code:        rawCode,
			Timestamp:   now,
		})
	}

	return &AuthorizeResult{
		RedirectURI: callbackURL,
		Code:        rawCode,
		State:       params.State,
		Issuer:      p.config.Issuer,
		IsRedirect:  true,
	}, nil
}

// ContinueAuthorize resumes the authorization code issuance after a user authenticates or consents.
func (p *Plugin) ContinueAuthorize(ctx context.Context, params ContinueAuthorizeParams) (*AuthorizeResult, error) {
	if !VerifyOAuthQuery(params.OAuthQuery, params.OAuthSignature, p.config.SecretKey) {
		return nil, ErrInvalidSignature
	}

	parsed, err := parseQueryString(params.OAuthQuery)
	if err != nil {
		return nil, ErrInvalidRequest
	}

	parsed.UserID = params.UserID
	parsed.SessionID = params.SessionID

	return p.Authorize(ctx, *parsed)
}

func isAllowedRedirectURI(candidate string, allowed []string) bool {
	for _, u := range allowed {
		if u == candidate {
			return true
		}
	}
	return false
}

func parseScopes(scopeStr string) []string {
	parts := strings.Fields(scopeStr)
	res := make([]string, 0, len(parts))
	for _, p := range parts {
		clean := strings.TrimSpace(p)
		if clean != "" {
			res = append(res, clean)
		}
	}
	return res
}

func hasAllScopes(granted, requested []string) bool {
	gm := make(map[string]bool, len(granted))
	for _, g := range granted {
		gm[g] = true
	}
	for _, r := range requested {
		if !gm[r] {
			return false
		}
	}
	return true
}

func buildQueryString(params AuthorizeParams, scopes []string) string {
	v := url.Values{}
	v.Set("client_id", params.ClientID)
	v.Set("redirect_uri", params.RedirectURI)
	v.Set("response_type", params.ResponseType)
	v.Set("code_challenge", params.CodeChallenge)
	v.Set("code_challenge_method", params.CodeChallengeMethod)
	v.Set("scope", strings.Join(scopes, " "))
	if params.State != "" {
		v.Set("state", params.State)
	}
	if params.Nonce != "" {
		v.Set("nonce", params.Nonce)
	}
	if params.Prompt != "" {
		v.Set("prompt", params.Prompt)
	}
	if params.Resource != "" {
		v.Set("resource", params.Resource)
	}
	return v.Encode()
}

func parseQueryString(raw string) (*AuthorizeParams, error) {
	v, err := url.ParseQuery(raw)
	if err != nil {
		return nil, err
	}
	return &AuthorizeParams{
		ClientID:            v.Get("client_id"),
		RedirectURI:         v.Get("redirect_uri"),
		ResponseType:        v.Get("response_type"),
		CodeChallenge:       v.Get("code_challenge"),
		CodeChallengeMethod: v.Get("code_challenge_method"),
		Scope:               v.Get("scope"),
		State:               v.Get("state"),
		Nonce:               v.Get("nonce"),
		Prompt:              v.Get("prompt"),
		Resource:            v.Get("resource"),
	}, nil
}

func buildCallbackURL(redirectURI, code, state, issuer string) string {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return fmt.Sprintf("%s?code=%s&state=%s&iss=%s", redirectURI, url.QueryEscape(code), url.QueryEscape(state), url.QueryEscape(issuer))
	}
	q := u.Query()
	q.Set("code", code)
	if state != "" {
		q.Set("state", state)
	}
	if issuer != "" {
		q.Set("iss", issuer)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func (p *Plugin) publishAuthorizeFailed(clientID, errDesc, redirectURI string) {
	if p.ctx != nil && p.ctx.Events() != nil {
		p.ctx.Events().Publish(EventAuthorizeFailed, &AuthorizeFailedEventPayload{
			ClientID:    clientID,
			Error:       errDesc,
			RedirectURI: redirectURI,
			Timestamp:   time.Now().UTC(),
		})
	}
}
