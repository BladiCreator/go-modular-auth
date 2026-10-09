package oauthprovider

import (
	"context"
	"slices"
	"strings"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	"github.com/BladiCreator/go-modular-auth-oauth-provider/events"
	"github.com/BladiCreator/go-modular-auth-oauth-provider/store"
	sdk "github.com/BladiCreator/go-modular-auth/plugin-sdk"
)

type service struct {
	ctx   *sdk.Context
	cfg   Config
	store store.Store
}

var _ OAuthProvider = (*service)(nil)

func newService(ctx *sdk.Context, cfg Config) *service {
	return &service{
		ctx:   ctx,
		cfg:   cfg,
		store: cfg.Store,
	}
}

func (s *service) now() time.Time {
	if s.ctx != nil {
		return s.ctx.Now()
	}
	return time.Now().UTC()
}

func (s *service) publish(ctx context.Context, name auth.EventName, subject string, payload any) {
	if s.ctx != nil && s.ctx.Events() != nil {
		s.ctx.Events().Publish(ctx, auth.Event{
			Name:    name,
			Time:    s.now(),
			Subject: subject,
			Payload: payload,
		})
	}
}

// RegisterClient registers a new OAuth 2.1 client application.
func (s *service) RegisterClient(ctx context.Context, in RegisterClientInput) (*RegisterClientOutput, error) {
	if strings.TrimSpace(in.Name) == "" {
		return nil, ErrInvalidRequest
	}
	if in.ClientType != ClientTypePublic && in.ClientType != ClientTypeConfidential {
		return nil, ErrInvalidRequest
	}
	if len(in.RedirectURIs) == 0 && in.ClientType == ClientTypePublic {
		return nil, ErrInvalidRequest
	}

	clientID, err := generateRandomToken(16)
	if err != nil {
		return nil, err
	}

	var rawSecret, secretHash string
	if in.ClientType == ClientTypeConfidential {
		rawSecret, err = generateRandomToken(32)
		if err != nil {
			return nil, err
		}
		secretHash, err = hashClientSecret(rawSecret)
		if err != nil {
			return nil, err
		}
	}

	grants := in.AllowedGrantTypes
	if len(grants) == 0 {
		grants = []string{GrantTypeAuthorizationCode, GrantTypeRefreshToken}
	}

	now := s.now()
	client := &Client{
		ID:                clientID,
		SecretHash:        secretHash,
		Name:              in.Name,
		ClientType:        in.ClientType,
		RedirectURIs:      slices.Clone(in.RedirectURIs),
		AllowedGrantTypes: slices.Clone(grants),
		AllowedScopes:     slices.Clone(in.AllowedScopes),
		Status:            ClientStatusActive,
		CreatedAt:         now,
		UpdatedAt:         now,
	}

	if err := s.store.Clients().Create(ctx, client); err != nil {
		return nil, err
	}

	s.publish(ctx, events.EventClientRegistered, client.ID, events.ClientRegisteredPayload{
		ClientID:   client.ID,
		ClientName: client.Name,
		ClientType: string(client.ClientType),
	})

	return &RegisterClientOutput{
		Client:       client,
		ClientSecret: rawSecret,
	}, nil
}

// GetClient retrieves client metadata by client ID.
func (s *service) GetClient(ctx context.Context, id string) (*Client, error) {
	if id == "" {
		return nil, ErrInvalidRequest
	}
	client, err := s.store.Clients().GetByID(ctx, id)
	if err != nil {
		return nil, ErrInvalidClient
	}
	return client, nil
}

// RevokeClient revokes a client application and cascades token invalidation.
func (s *service) RevokeClient(ctx context.Context, id string) error {
	if id == "" {
		return ErrInvalidRequest
	}
	now := s.now()
	if err := s.store.Clients().Revoke(ctx, id, now); err != nil {
		return ErrInvalidClient
	}
	_ = s.store.Tokens().RevokeTokensByClient(ctx, id, now)

	s.publish(ctx, events.EventTokenRevoked, id, events.TokenRevokedPayload{
		ClientID: id,
	})

	return nil
}

// Authorize processes an OAuth 2.1 authorization request.
func (s *service) Authorize(ctx context.Context, in AuthorizeInput) (*AuthorizeOutput, error) {
	if in.ClientID == "" || in.RedirectURI == "" {
		return nil, ErrInvalidRequest
	}
	if in.ResponseType != "code" {
		return nil, ErrUnsupportedResponseType
	}

	client, err := s.store.Clients().GetByID(ctx, in.ClientID)
	if err != nil {
		return nil, ErrInvalidClient
	}
	if client.Status != ClientStatusActive {
		return nil, ErrClientRevoked
	}

	// Exact redirect URI matching requirement per OAuth 2.1 RFC
	if !slices.Contains(client.RedirectURIs, in.RedirectURI) {
		return nil, ErrRedirectURIMismatch
	}

	// PKCE is strictly required for public clients per OAuth 2.1
	if client.ClientType == ClientTypePublic || s.cfg.RequirePKCEForPublicClients {
		if in.CodeChallenge == "" || in.CodeChallengeMethod == "" {
			return nil, ErrPKCERequired
		}
	}
	if in.CodeChallengeMethod != "" && in.CodeChallengeMethod != CodeChallengeMethodS256 {
		if in.CodeChallengeMethod == CodeChallengeMethodPlain && !s.cfg.AllowPlainPKCE {
			return nil, ErrInvalidPKCE
		}
	}

	// Validate scopes
	for _, sc := range in.Scopes {
		if len(client.AllowedScopes) > 0 && !slices.Contains(client.AllowedScopes, sc) {
			return nil, ErrInvalidScope
		}
	}

	// User consent validation
	if !in.UserConsent {
		return nil, ErrConsentRequired
	}

	rawCode, err := generateRandomToken(32)
	if err != nil {
		return nil, err
	}
	codeHash := hashToken(rawCode)
	now := s.now()

	authCode := &AuthorizationCode{
		ID:                  codeHash,
		CodeHash:            codeHash,
		ClientID:            in.ClientID,
		UserID:              in.UserID,
		RedirectURI:         in.RedirectURI,
		Scopes:              slices.Clone(in.Scopes),
		CodeChallenge:       in.CodeChallenge,
		CodeChallengeMethod: in.CodeChallengeMethod,
		ExpiresAt:           now.Add(s.cfg.AuthorizationCodeTTL),
		CreatedAt:           now,
	}

	if err := s.store.Codes().Create(ctx, authCode); err != nil {
		return nil, err
	}

	s.publish(ctx, events.EventAuthorizationCodeIssued, in.ClientID, events.CodeIssuedPayload{
		ClientID: in.ClientID,
		UserID:   in.UserID,
	})

	return &AuthorizeOutput{
		Code:        rawCode,
		State:       in.State,
		RedirectURI: in.RedirectURI,
	}, nil
}

// Token handles OAuth 2.1 token issuance.
func (s *service) Token(ctx context.Context, in TokenInput) (*TokenOutput, error) {
	switch in.GrantType {
	case GrantTypeAuthorizationCode:
		return s.handleAuthorizationCodeGrant(ctx, in)
	case GrantTypeClientCredentials:
		return s.handleClientCredentialsGrant(ctx, in)
	case GrantTypeRefreshToken:
		return s.handleRefreshTokenGrant(ctx, in)
	default:
		return nil, ErrUnsupportedGrantType
	}
}

func (s *service) handleAuthorizationCodeGrant(ctx context.Context, in TokenInput) (*TokenOutput, error) {
	if in.Code == "" || in.ClientID == "" || in.RedirectURI == "" {
		return nil, ErrInvalidRequest
	}

	client, err := s.store.Clients().GetByID(ctx, in.ClientID)
	if err != nil {
		return nil, ErrInvalidClient
	}
	if client.Status != ClientStatusActive {
		return nil, ErrClientRevoked
	}
	if !slices.Contains(client.AllowedGrantTypes, GrantTypeAuthorizationCode) {
		return nil, ErrUnauthorizedClient
	}

	// Authenticate confidential client if applicable
	if client.ClientType == ClientTypeConfidential {
		if !verifyClientSecret(client.SecretHash, in.ClientSecret) {
			return nil, ErrInvalidClient
		}
	}

	// Atomically consume authorization code
	now := s.now()
	codeHash := hashToken(in.Code)
	code, err := s.store.Codes().Consume(ctx, codeHash, now)
	if err != nil {
		return nil, ErrInvalidGrant
	}

	// Expiration check
	if !now.Before(code.ExpiresAt) {
		return nil, ErrInvalidGrant
	}

	// Verify client match and exact redirect URI match
	if code.ClientID != in.ClientID || code.RedirectURI != in.RedirectURI {
		return nil, ErrInvalidGrant
	}

	// Verify PKCE
	if code.CodeChallenge != "" {
		if err := verifyPKCE(in.CodeVerifier, code.CodeChallenge, code.CodeChallengeMethod, s.cfg.AllowPlainPKCE); err != nil {
			return nil, err
		}
	} else if client.ClientType == ClientTypePublic {
		return nil, ErrPKCERequired
	}

	return s.issueTokens(ctx, client.ID, code.UserID, code.Scopes, GrantTypeAuthorizationCode)
}

func (s *service) handleClientCredentialsGrant(ctx context.Context, in TokenInput) (*TokenOutput, error) {
	if in.ClientID == "" || in.ClientSecret == "" {
		return nil, ErrInvalidRequest
	}

	client, err := s.store.Clients().GetByID(ctx, in.ClientID)
	if err != nil {
		return nil, ErrInvalidClient
	}
	if client.Status != ClientStatusActive {
		return nil, ErrClientRevoked
	}
	if client.ClientType != ClientTypeConfidential {
		return nil, ErrUnauthorizedClient
	}
	if !slices.Contains(client.AllowedGrantTypes, GrantTypeClientCredentials) {
		return nil, ErrUnauthorizedClient
	}
	if !verifyClientSecret(client.SecretHash, in.ClientSecret) {
		return nil, ErrInvalidClient
	}

	// Validate scopes
	for _, sc := range in.Scopes {
		if len(client.AllowedScopes) > 0 && !slices.Contains(client.AllowedScopes, sc) {
			return nil, ErrInvalidScope
		}
	}

	scopes := in.Scopes
	if len(scopes) == 0 {
		scopes = client.AllowedScopes
	}

	// Client credentials grant produces client-bound access tokens without refresh tokens
	rawAccessToken, err := generateRandomToken(32)
	if err != nil {
		return nil, err
	}
	now := s.now()
	accessTokenHash := hashToken(rawAccessToken)
	access := &AccessToken{
		ID:        accessTokenHash,
		TokenHash: accessTokenHash,
		ClientID:  client.ID,
		UserID:    "", // Principal is the client
		Scopes:    slices.Clone(scopes),
		ExpiresAt: now.Add(s.cfg.AccessTokenTTL),
		CreatedAt: now,
	}

	if err := s.store.Tokens().CreateAccessToken(ctx, access); err != nil {
		return nil, err
	}

	s.publish(ctx, events.EventTokenIssued, client.ID, events.TokenIssuedPayload{
		ClientID:  client.ID,
		GrantType: GrantTypeClientCredentials,
		Scopes:    scopes,
	})

	return &TokenOutput{
		AccessToken: rawAccessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int64(s.cfg.AccessTokenTTL.Seconds()),
		Scope:       strings.Join(scopes, " "),
	}, nil
}

func (s *service) handleRefreshTokenGrant(ctx context.Context, in TokenInput) (*TokenOutput, error) {
	if in.RefreshToken == "" || in.ClientID == "" {
		return nil, ErrInvalidRequest
	}

	client, err := s.store.Clients().GetByID(ctx, in.ClientID)
	if err != nil {
		return nil, ErrInvalidClient
	}
	if client.Status != ClientStatusActive {
		return nil, ErrClientRevoked
	}
	if client.ClientType == ClientTypeConfidential {
		if !verifyClientSecret(client.SecretHash, in.ClientSecret) {
			return nil, ErrInvalidClient
		}
	}

	now := s.now()
	tokenHash := hashToken(in.RefreshToken)
	rf, err := s.store.Tokens().GetRefreshTokenByHash(ctx, tokenHash)
	if err != nil {
		return nil, ErrInvalidGrant
	}
	if rf.RevokedAt != nil || !now.Before(rf.ExpiresAt) || rf.ClientID != in.ClientID {
		return nil, ErrInvalidGrant
	}

	// Optional scope narrowing
	scopes := rf.Scopes
	if len(in.Scopes) > 0 {
		for _, sc := range in.Scopes {
			if !slices.Contains(rf.Scopes, sc) {
				return nil, ErrInvalidScope
			}
		}
		scopes = in.Scopes
	}

	// Revoke old refresh token on rotation
	if s.cfg.RotateRefreshTokens {
		_ = s.store.Tokens().RevokeRefreshToken(ctx, tokenHash, now)
	}

	res, err := s.issueTokens(ctx, client.ID, rf.UserID, scopes, GrantTypeRefreshToken)
	if err != nil {
		return nil, err
	}

	s.publish(ctx, events.EventTokenRefreshed, client.ID, events.TokenIssuedPayload{
		ClientID:  client.ID,
		UserID:    rf.UserID,
		GrantType: GrantTypeRefreshToken,
		Scopes:    scopes,
	})

	return res, nil
}

func (s *service) issueTokens(ctx context.Context, clientID, userID string, scopes []string, grantType string) (*TokenOutput, error) {
	rawAccessToken, err := generateRandomToken(32)
	if err != nil {
		return nil, err
	}
	now := s.now()
	accessHash := hashToken(rawAccessToken)
	access := &AccessToken{
		ID:        accessHash,
		TokenHash: accessHash,
		ClientID:  clientID,
		UserID:    userID,
		Scopes:    slices.Clone(scopes),
		ExpiresAt: now.Add(s.cfg.AccessTokenTTL),
		CreatedAt: now,
	}

	if err := s.store.Tokens().CreateAccessToken(ctx, access); err != nil {
		return nil, err
	}

	rawRefreshToken, err := generateRandomToken(48)
	if err != nil {
		return nil, err
	}
	refreshHash := hashToken(rawRefreshToken)
	refresh := &RefreshToken{
		ID:            refreshHash,
		TokenHash:     refreshHash,
		AccessTokenID: access.ID,
		ClientID:      clientID,
		UserID:        userID,
		Scopes:        slices.Clone(scopes),
		ExpiresAt:     now.Add(s.cfg.RefreshTokenTTL),
		CreatedAt:     now,
	}

	if err := s.store.Tokens().CreateRefreshToken(ctx, refresh); err != nil {
		return nil, err
	}

	s.publish(ctx, events.EventTokenIssued, clientID, events.TokenIssuedPayload{
		ClientID:  clientID,
		UserID:    userID,
		GrantType: grantType,
		Scopes:    scopes,
	})

	return &TokenOutput{
		AccessToken:  rawAccessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(s.cfg.AccessTokenTTL.Seconds()),
		RefreshToken: rawRefreshToken,
		Scope:        strings.Join(scopes, " "),
	}, nil
}

// RevokeToken implements RFC 7009 token revocation.
func (s *service) RevokeToken(ctx context.Context, in RevokeTokenInput) error {
	if in.Token == "" {
		return ErrInvalidRequest
	}

	now := s.now()
	h := hashToken(in.Token)

	// RFC 7009 requires revoking without failing if already revoked or non-existent
	_ = s.store.Tokens().RevokeAccessToken(ctx, h, now)
	_ = s.store.Tokens().RevokeRefreshToken(ctx, h, now)

	s.publish(ctx, events.EventTokenRevoked, in.ClientID, events.TokenRevokedPayload{
		ClientID: in.ClientID,
	})

	return nil
}

// IntrospectToken implements RFC 7662 token introspection.
func (s *service) IntrospectToken(ctx context.Context, in IntrospectTokenInput) (*IntrospectTokenOutput, error) {
	if in.Token == "" {
		return &IntrospectTokenOutput{Active: false}, nil
	}

	now := s.now()
	h := hashToken(in.Token)

	// Check access token first
	if acc, err := s.store.Tokens().GetAccessTokenByHash(ctx, h); err == nil {
		if acc.RevokedAt != nil || !now.Before(acc.ExpiresAt) {
			return &IntrospectTokenOutput{Active: false}, nil
		}
		sub := acc.UserID
		if sub == "" {
			sub = acc.ClientID
		}
		return &IntrospectTokenOutput{
			Active:    true,
			Scope:     strings.Join(acc.Scopes, " "),
			ClientID:  acc.ClientID,
			Sub:       sub,
			Exp:       acc.ExpiresAt.Unix(),
			Iat:       acc.CreatedAt.Unix(),
			TokenType: "Bearer",
			Scopes:    acc.Scopes,
		}, nil
	}

	// Check refresh token
	if rf, err := s.store.Tokens().GetRefreshTokenByHash(ctx, h); err == nil {
		if rf.RevokedAt != nil || !now.Before(rf.ExpiresAt) {
			return &IntrospectTokenOutput{Active: false}, nil
		}
		return &IntrospectTokenOutput{
			Active:    true,
			Scope:     strings.Join(rf.Scopes, " "),
			ClientID:  rf.ClientID,
			Sub:       rf.UserID,
			Exp:       rf.ExpiresAt.Unix(),
			Iat:       rf.CreatedAt.Unix(),
			TokenType: "Refresh",
			Scopes:    rf.Scopes,
		}, nil
	}

	return &IntrospectTokenOutput{Active: false}, nil
}
