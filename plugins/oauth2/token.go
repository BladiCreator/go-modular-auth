package oauth2

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/entity"
	"github.com/google/uuid"
)

// Token handles token exchanges across all supported OAuth 2.1 grant types:
// "authorization_code", "refresh_token", and "client_credentials".
func (p *Plugin) Token(ctx context.Context, params TokenParams) (*TokenResult, error) {
	switch GrantType(params.GrantType) {
	case GrantTypeAuthorizationCode:
		return p.exchangeAuthorizationCode(ctx, params)
	case GrantTypeRefreshToken:
		return p.exchangeRefreshToken(ctx, params)
	case GrantTypeClientCredentials:
		return p.exchangeClientCredentials(ctx, params)
	default:
		return nil, ErrInvalidGrantType
	}
}

func (p *Plugin) exchangeAuthorizationCode(ctx context.Context, params TokenParams) (*TokenResult, error) {
	if strings.TrimSpace(params.Code) == "" {
		return nil, ErrInvalidAuthorizationCode
	}
	if strings.TrimSpace(params.CodeVerifier) == "" {
		return nil, ErrInvalidPKCE
	}

	// 1. Determine storage lookup key for single-use atomic consumption
	lookupCode := params.Code
	if p.config.StoreTokensMode == StoreModeHashed {
		lookupCode = HashToken(params.Code)
	}

	// 2. Consume authorization code atomically (Single Gate Anti-Replay)
	authCode, err := p.repo.ConsumeAuthorizationCode(ctx, lookupCode)
	if err != nil || authCode == nil {
		return nil, ErrInvalidAuthorizationCode
	}

	// 3. Verify code expiration
	now := time.Now().UTC()
	if authCode.ExpiresAt.Before(now) {
		return nil, ErrAuthorizationCodeExpired
	}

	// 4. Verify client credentials & binding
	clientID := params.ClientID
	if clientID == "" {
		clientID = authCode.ClientID
	}
	if clientID != authCode.ClientID {
		return nil, ErrInvalidClient
	}

	client, err := p.repo.FindClientByClientID(ctx, clientID)
	if err != nil || client == nil {
		return nil, ErrClientNotFound
	}
	if client.Disabled {
		return nil, ErrClientDisabled
	}

	// Authenticate confidential client if secret provided or required
	if !client.Public {
		if err := p.authenticateClient(client, params.ClientSecret); err != nil {
			return nil, err
		}
	}

	// 5. Verify redirect URI matches the one locked during authorization
	if params.RedirectURI != "" && params.RedirectURI != authCode.RedirectURI {
		return nil, ErrInvalidRedirectURI
	}

	// 6. Verify PKCE S256
	if !VerifyPKCE(params.CodeVerifier, authCode.CodeChallenge, authCode.CodeChallengeMethod) {
		return nil, ErrInvalidPKCE
	}

	// 7. Resolve user entity
	var user *entity.User
	if authCode.UserID != "" {
		user, _ = p.repo.FindUserByID(ctx, authCode.UserID)
	}

	// Determine Subject (Public or Pairwise)
	sub := authCode.UserID
	if client.SubjectType == SubjectTypePairwise && p.config.PairwiseSecret != "" {
		sectorID := client.URI
		if sectorID == "" && len(client.RedirectURIs) > 0 {
			sectorID = client.RedirectURIs[0]
		}
		sub = DerivePairwiseSubject(p.config.PairwiseSecret, sectorID, authCode.UserID)
	}

	// 8. Mint Access Token
	rawAccessToken, err := p.mintAccessToken(ctx, client, user, sub, authCode.Scopes, authCode.SessionID, nil)
	if err != nil {
		return nil, fmt.Errorf("oauth2: failed to mint access token: %w", err)
	}

	// 9. Mint Refresh Token if requested or configured
	var rawRefreshToken string
	hasOfflineScope := containsScope(authCode.Scopes, ScopeOffline)
	if hasOfflineScope || containsGrant(client.GrantTypes, GrantTypeRefreshToken) {
		familyID := uuid.New().String()
		rawRefreshToken, err = p.mintRefreshToken(ctx, client.ClientID, authCode.UserID, authCode.SessionID, familyID, authCode.Scopes)
		if err != nil {
			return nil, fmt.Errorf("oauth2: failed to mint refresh token: %w", err)
		}
	}

	// 10. Mint ID Token if "openid" scope is present
	var idTokenString string
	if containsScope(authCode.Scopes, ScopeOpenID) && user != nil {
		idTokenString, err = p.mintIDToken(ctx, client, user, sub, rawAccessToken, params.Code, authCode.Nonce, authCode.Scopes)
		if err != nil {
			return nil, fmt.Errorf("oauth2: failed to mint ID token: %w", err)
		}
	}

	// 11. Dispatch TokenIssued event
	if p.ctx != nil && p.ctx.Events() != nil {
		var refTokenPtr *string
		if rawRefreshToken != "" {
			refTokenPtr = &rawRefreshToken
		}
		var idTokenPtr *string
		if idTokenString != "" {
			idTokenPtr = &idTokenString
		}

		p.ctx.Events().Publish(EventTokenIssued, &TokenIssuedEventPayload{
			ClientID:     client.ClientID,
			UserID:       &authCode.UserID,
			GrantType:    GrantTypeAuthorizationCode,
			Scopes:       authCode.Scopes,
			AccessToken:  rawAccessToken,
			RefreshToken: refTokenPtr,
			IDToken:      idTokenPtr,
			Timestamp:    now,
		})
	}

	return &TokenResult{
		AccessToken:  rawAccessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(p.config.AccessTokenExpiresIn.Seconds()),
		RefreshToken: rawRefreshToken,
		IDToken:      idTokenString,
		Scope:        strings.Join(authCode.Scopes, " "),
	}, nil
}

func (p *Plugin) exchangeRefreshToken(ctx context.Context, params TokenParams) (*TokenResult, error) {
	if strings.TrimSpace(params.RefreshToken) == "" {
		return nil, ErrInvalidRefreshToken
	}

	lookupHash := HashToken(params.RefreshToken)
	existingToken, err := p.repo.FindRefreshToken(ctx, lookupHash)
	if err != nil || existingToken == nil {
		return nil, ErrInvalidRefreshToken
	}

	now := time.Now().UTC()

	// Detect reuse of already revoked refresh token (Token Theft Mitigation)
	if existingToken.RevokedAt != nil || existingToken.ExpiresAt.Before(now) {
		_ = p.repo.RevokeRefreshTokenFamily(ctx, existingToken.FamilyID)
		return nil, ErrRefreshTokenRevoked
	}

	client, err := p.repo.FindClientByClientID(ctx, existingToken.ClientID)
	if err != nil || client == nil || client.Disabled {
		return nil, ErrInvalidClient
	}

	// Authenticate confidential client if secret provided
	if !client.Public && params.ClientSecret != "" {
		if err := p.authenticateClient(client, params.ClientSecret); err != nil {
			return nil, err
		}
	}

	// Invalidate current refresh token
	if err := p.repo.DeleteRefreshToken(ctx, lookupHash); err != nil {
		return nil, fmt.Errorf("oauth2: failed to rotate refresh token: %w", err)
	}

	// Issue new rotated refresh token in the same token family
	newRawRefreshToken, err := p.mintRefreshToken(ctx, client.ClientID, existingToken.UserID,
		derefString(existingToken.SessionID), existingToken.FamilyID, existingToken.Scopes)
	if err != nil {
		return nil, fmt.Errorf("oauth2: failed to mint rotated refresh token: %w", err)
	}

	// Resolve user
	user, _ := p.repo.FindUserByID(ctx, existingToken.UserID)

	// Determine Subject
	sub := existingToken.UserID
	if client.SubjectType == SubjectTypePairwise && p.config.PairwiseSecret != "" {
		sectorID := client.URI
		if sectorID == "" && len(client.RedirectURIs) > 0 {
			sectorID = client.RedirectURIs[0]
		}
		sub = DerivePairwiseSubject(p.config.PairwiseSecret, sectorID, existingToken.UserID)
	}

	// Mint new Access Token
	newAccessToken, err := p.mintAccessToken(ctx, client, user, sub, existingToken.Scopes, derefString(existingToken.SessionID), &existingToken.ID)
	if err != nil {
		return nil, fmt.Errorf("oauth2: failed to mint access token on refresh: %w", err)
	}

	// Mint refreshed ID Token if scope has openid
	var idTokenString string
	if containsScope(existingToken.Scopes, ScopeOpenID) && user != nil {
		idTokenString, _ = p.mintIDToken(ctx, client, user, sub, newAccessToken, "", "", existingToken.Scopes)
	}

	if p.ctx != nil && p.ctx.Events() != nil {
		p.ctx.Events().Publish(EventTokenRefreshed, &TokenRefreshedEventPayload{
			ClientID:        client.ClientID,
			UserID:          existingToken.UserID,
			FamilyID:        existingToken.FamilyID,
			NewAccessToken:  newAccessToken,
			NewRefreshToken: newRawRefreshToken,
			Timestamp:       now,
		})
	}

	return &TokenResult{
		AccessToken:  newAccessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(p.config.AccessTokenExpiresIn.Seconds()),
		RefreshToken: newRawRefreshToken,
		IDToken:      idTokenString,
		Scope:        strings.Join(existingToken.Scopes, " "),
	}, nil
}

func (p *Plugin) exchangeClientCredentials(ctx context.Context, params TokenParams) (*TokenResult, error) {
	if strings.TrimSpace(params.ClientID) == "" {
		return nil, ErrInvalidClient
	}

	client, err := p.repo.FindClientByClientID(ctx, params.ClientID)
	if err != nil || client == nil {
		return nil, ErrClientNotFound
	}
	if client.Disabled {
		return nil, ErrClientDisabled
	}
	if client.Public {
		return nil, ErrUnauthorizedClient
	}

	if err := p.authenticateClient(client, params.ClientSecret); err != nil {
		return nil, err
	}

	requestedScopes := parseScopes(params.Scope)
	if len(requestedScopes) == 0 {
		requestedScopes = client.Scopes
	}

	now := time.Now().UTC()
	tokenExpiresIn := p.config.M2MAccessTokenExpiresIn
	if tokenExpiresIn <= 0 {
		tokenExpiresIn = p.config.AccessTokenExpiresIn
	}

	rawAccessToken, err := p.mintAccessToken(ctx, client, nil, client.ClientID, requestedScopes, "", nil)
	if err != nil {
		return nil, fmt.Errorf("oauth2: failed to mint client_credentials access token: %w", err)
	}

	if p.ctx != nil && p.ctx.Events() != nil {
		p.ctx.Events().Publish(EventTokenIssued, &TokenIssuedEventPayload{
			ClientID:    client.ClientID,
			GrantType:   GrantTypeClientCredentials,
			Scopes:      requestedScopes,
			AccessToken: rawAccessToken,
			Timestamp:   now,
		})
	}

	return &TokenResult{
		AccessToken: rawAccessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int64(tokenExpiresIn.Seconds()),
		Scope:       strings.Join(requestedScopes, " "),
	}, nil
}

func (p *Plugin) mintAccessToken(ctx context.Context, client *OAuthClient, user *entity.User, sub string, scopes []string, sessionID string, refreshID *string) (string, error) {
	now := time.Now().UTC()
	expDuration := p.config.AccessTokenExpiresIn
	if user == nil {
		if p.config.M2MAccessTokenExpiresIn > 0 {
			expDuration = p.config.M2MAccessTokenExpiresIn
		}
	}

	var rawToken string
	if p.config.AccessTokenType == AccessTokenTypeJWT {
		jti := uuid.New().String()
		claims := map[string]any{
			"iss":       p.config.Issuer,
			"sub":       sub,
			"aud":       client.ClientID,
			"client_id": client.ClientID,
			"jti":       jti,
			"iat":       now.Unix(),
			"exp":       now.Add(expDuration).Unix(),
			"scope":     strings.Join(scopes, " "),
		}

		if len(p.config.ValidAudiences) > 0 {
			claims["aud"] = append([]string{client.ClientID}, p.config.ValidAudiences...)
		}

		if p.config.CustomAccessTokenClaims != nil {
			custom, err := p.config.CustomAccessTokenClaims(ctx, client, user, scopes)
			if err == nil && custom != nil {
				for k, v := range custom {
					claims[k] = v
				}
			}
		}

		jwtStr, _, err := p.signer.Sign(ctx, claims, expDuration)
		if err != nil {
			return "", err
		}
		rawToken = jwtStr
	} else {
		var err error
		rawToken, err = GenerateRandomString(32)
		if err != nil {
			return "", err
		}
	}

	var userIDPtr *string
	if user != nil {
		userIDPtr = &user.ID
	}
	var sessIDPtr *string
	if sessionID != "" {
		sessIDPtr = &sessionID
	}

	storedHash := HashToken(rawToken)
	accessTokenRecord := &OAuthAccessToken{
		ID:        uuid.New().String(),
		Token:     storedHash,
		ClientID:  client.ClientID,
		UserID:    userIDPtr,
		SessionID: sessIDPtr,
		RefreshID: refreshID,
		Scopes:    scopes,
		ExpiresAt: now.Add(expDuration),
		CreatedAt: now,
	}

	if err := p.repo.CreateAccessToken(ctx, accessTokenRecord); err != nil {
		return "", err
	}

	return rawToken, nil
}

func (p *Plugin) mintRefreshToken(ctx context.Context, clientID, userID, sessionID, familyID string, scopes []string) (string, error) {
	rawToken, err := GenerateRandomString(32)
	if err != nil {
		return "", err
	}

	now := time.Now().UTC()
	storedHash := HashToken(rawToken)

	var sessIDPtr *string
	if sessionID != "" {
		sessIDPtr = &sessionID
	}

	refTokenRecord := &OAuthRefreshToken{
		ID:        uuid.New().String(),
		Token:     storedHash,
		ClientID:  clientID,
		UserID:    userID,
		SessionID: sessIDPtr,
		FamilyID:  familyID,
		Scopes:    scopes,
		ExpiresAt: now.Add(p.config.RefreshTokenExpiresIn),
		CreatedAt: now,
	}

	if err := p.repo.CreateRefreshToken(ctx, refTokenRecord); err != nil {
		return "", err
	}

	return rawToken, nil
}

func (p *Plugin) mintIDToken(ctx context.Context, client *OAuthClient, user *entity.User, sub, rawAccessToken, rawCode, nonce string, scopes []string) (string, error) {
	now := time.Now().UTC()
	claims := map[string]any{
		"iss":       p.config.Issuer,
		"sub":       sub,
		"aud":       client.ClientID,
		"iat":       now.Unix(),
		"exp":       now.Add(p.config.IDTokenExpiresIn).Unix(),
		"auth_time": now.Unix(),
	}

	if nonce != "" {
		claims["nonce"] = nonce
	}
	if rawAccessToken != "" {
		claims["at_hash"] = ComputeLeftHash(rawAccessToken)
	}
	if rawCode != "" {
		claims["c_hash"] = ComputeLeftHash(rawCode)
	}

	if containsScope(scopes, ScopeProfile) {
		claims["name"] = user.Name
	}
	if containsScope(scopes, ScopeEmail) {
		claims["email"] = user.Email
		claims["email_verified"] = user.EmailVerified
	}
	if containsScope(scopes, ScopePhone) && user.PhoneNumber != nil {
		claims["phone_number"] = *user.PhoneNumber
		claims["phone_number_verified"] = user.PhoneNumberVerified
	}

	if p.config.CustomIDTokenClaims != nil {
		custom, err := p.config.CustomIDTokenClaims(ctx, client, user, scopes)
		if err == nil && custom != nil {
			for k, v := range custom {
				claims[k] = v
			}
		}
	}

	idTokenStr, _, err := p.signer.Sign(ctx, claims, p.config.IDTokenExpiresIn)
	return idTokenStr, err
}

func (p *Plugin) authenticateClient(client *OAuthClient, providedSecret string) error {
	if client.ClientSecret == nil || *client.ClientSecret == "" {
		return nil
	}
	if strings.TrimSpace(providedSecret) == "" {
		return ErrInvalidClientSecret
	}

	switch p.config.StoreClientSecretMode {
	case StoreModePlain:
		if *client.ClientSecret != providedSecret {
			return ErrInvalidClientSecret
		}
	case StoreModeHashed:
		h := HashSecret(providedSecret)
		if *client.ClientSecret != h {
			return ErrInvalidClientSecret
		}
	case StoreModeEncrypted:
		dec, err := Decrypt(*client.ClientSecret, DeriveAESKey(p.config.SecretKey))
		if err != nil || string(dec) != providedSecret {
			return ErrInvalidClientSecret
		}
	}
	return nil
}

func containsScope(scopes []string, target string) bool {
	for _, s := range scopes {
		if s == target {
			return true
		}
	}
	return false
}

func containsGrant(grants []GrantType, target GrantType) bool {
	for _, g := range grants {
		if g == target {
			return true
		}
	}
	return false
}

func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
