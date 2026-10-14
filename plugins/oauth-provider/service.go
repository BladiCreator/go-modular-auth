package oauthprovider

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	"github.com/BladiCreator/go-modular-auth-oauth-provider/events"
	"github.com/BladiCreator/go-modular-auth/adapter"
	sdk "github.com/BladiCreator/go-modular-auth/plugin-sdk"
)

type service struct {
	ctx           *sdk.Context
	cfg           Config
	clients       *sdk.Repository[Client]
	codes         *sdk.Repository[AuthorizationCode]
	accessTokens  *sdk.Repository[AccessToken]
	refreshTokens *sdk.Repository[RefreshToken]
}

var _ OAuthProvider = (*service)(nil)

func newService(ctx *sdk.Context, cfg Config) *service {
	return &service{
		ctx:           ctx,
		cfg:           cfg,
		clients:       sdk.Model[Client](ctx, ModelOAuthClients),
		codes:         sdk.Model[AuthorizationCode](ctx, ModelOAuthAuthorizationCodes),
		accessTokens:  sdk.Model[AccessToken](ctx, ModelOAuthAccessTokens),
		refreshTokens: sdk.Model[RefreshToken](ctx, ModelOAuthRefreshTokens),
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
		Name:              strings.TrimSpace(in.Name),
		ClientType:        in.ClientType,
		RedirectURIs:      in.RedirectURIs,
		AllowedGrantTypes: grants,
		AllowedScopes:     in.AllowedScopes,
		Status:            ClientStatusActive,
		CreatedAt:         now,
		UpdatedAt:         now,
	}

	if err := s.clients.Create(ctx, client); err != nil {
		return nil, err
	}

	s.publish(ctx, events.EventClientRegistered, clientID, events.ClientRegisteredPayload{
		ClientID:   clientID,
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
	client, err := s.clients.FindOne(ctx, adapter.Eq("id", id))
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
	affected, err := s.clients.Update(ctx, []adapter.Condition{adapter.Eq("id", id)}, map[string]any{
		"status":     string(ClientStatusRevoked),
		"updated_at": now,
	})
	if err != nil || affected == 0 {
		return ErrInvalidClient
	}

	_, _ = s.accessTokens.Update(ctx, []adapter.Condition{adapter.Eq("client_id", id), adapter.IsNull("revoked_at")}, map[string]any{
		"revoked_at": now,
	})
	_, _ = s.refreshTokens.Update(ctx, []adapter.Condition{adapter.Eq("client_id", id), adapter.IsNull("revoked_at")}, map[string]any{
		"revoked_at": now,
	})

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

	client, err := s.clients.FindOne(ctx, adapter.Eq("id", in.ClientID))
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

	// Scope validation
	if len(in.Scopes) > 0 && len(client.AllowedScopes) > 0 {
		for _, sc := range in.Scopes {
			if !slices.Contains(client.AllowedScopes, sc) {
				return nil, ErrInvalidScope
			}
		}
	}

	// PKCE is required for public clients by default in OAuth 2.1
	if s.cfg.RequirePKCEForPublicClients && client.ClientType == ClientTypePublic {
		if in.CodeChallenge == "" {
			return nil, ErrPKCERequired
		}
	}

	// Reject plain PKCE method unless explicitly allowed by config
	if in.CodeChallenge != "" {
		if in.CodeChallengeMethod == CodeChallengeMethodPlain && !s.cfg.AllowPlainPKCE {
			return nil, ErrInvalidPKCE
		}
		if in.CodeChallengeMethod != CodeChallengeMethodS256 && in.CodeChallengeMethod != CodeChallengeMethodPlain {
			return nil, ErrInvalidPKCE
		}
	}

	// User consent enforcement
	if !in.UserConsent {
		return nil, ErrConsentRequired
	}

	rawCode, err := generateRandomToken(32)
	if err != nil {
		return nil, err
	}

	now := s.now()
	codeHash := hashToken(rawCode)
	authCode := &AuthorizationCode{
		ID:                  codeHash,
		CodeHash:            codeHash,
		ClientID:            in.ClientID,
		UserID:              in.UserID,
		RedirectURI:         in.RedirectURI,
		Scopes:              in.Scopes,
		CodeChallenge:       in.CodeChallenge,
		CodeChallengeMethod: in.CodeChallengeMethod,
		ExpiresAt:           now.Add(s.cfg.AuthorizationCodeTTL),
		CreatedAt:           now,
	}

	if err := s.codes.Create(ctx, authCode); err != nil {
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

// Token handles the OAuth 2.1 token endpoint (authorization_code, client_credentials, refresh_token).
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

	client, err := s.clients.FindOne(ctx, adapter.Eq("id", in.ClientID))
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
	code, err := s.codes.FindOne(ctx, adapter.Eq("code_hash", codeHash))
	if errors.Is(err, adapter.ErrNotFound) || code == nil {
		return nil, ErrInvalidGrant
	}
	if code.ConsumedAt != nil {
		return nil, ErrInvalidGrant
	}

	// Expiration check
	if !now.Before(code.ExpiresAt) {
		return nil, ErrInvalidGrant
	}

	// Consume code atomically
	n, err := s.codes.Update(ctx, []adapter.Condition{
		adapter.Eq("id", code.ID),
		adapter.IsNull("consumed_at"),
	}, map[string]any{
		"consumed_at": now,
	})
	if err != nil || n == 0 {
		return nil, ErrInvalidGrant
	}
	code.ConsumedAt = &now

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

	client, err := s.clients.FindOne(ctx, adapter.Eq("id", in.ClientID))
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

	// Scope validation if requested
	scopes := client.AllowedScopes
	if len(in.Scopes) > 0 {
		for _, sc := range in.Scopes {
			if !slices.Contains(client.AllowedScopes, sc) {
				return nil, ErrInvalidScope
			}
		}
		scopes = in.Scopes
	}

	now := s.now()
	rawAccessToken, err := generateRandomToken(32)
	if err != nil {
		return nil, err
	}
	accessHash := hashToken(rawAccessToken)
	access := &AccessToken{
		ID:        accessHash,
		TokenHash: accessHash,
		ClientID:  client.ID,
		UserID:    "", // Empty for client_credentials
		Scopes:    slices.Clone(scopes),
		ExpiresAt: now.Add(s.cfg.AccessTokenTTL),
		CreatedAt: now,
	}

	if err := s.accessTokens.Create(ctx, access); err != nil {
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

	client, err := s.clients.FindOne(ctx, adapter.Eq("id", in.ClientID))
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
	rf, err := s.refreshTokens.FindOne(ctx, adapter.Eq("token_hash", tokenHash))
	if errors.Is(err, adapter.ErrNotFound) || rf == nil {
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
		_, _ = s.refreshTokens.Update(ctx, []adapter.Condition{adapter.Eq("token_hash", tokenHash)}, map[string]any{
			"revoked_at": now,
		})
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

	if err := s.accessTokens.Create(ctx, access); err != nil {
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

	if err := s.refreshTokens.Create(ctx, refresh); err != nil {
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
	_, _ = s.accessTokens.Update(ctx, []adapter.Condition{adapter.Eq("token_hash", h), adapter.IsNull("revoked_at")}, map[string]any{"revoked_at": now})
	_, _ = s.refreshTokens.Update(ctx, []adapter.Condition{adapter.Eq("token_hash", h), adapter.IsNull("revoked_at")}, map[string]any{"revoked_at": now})

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
	if acc, err := s.accessTokens.FindOne(ctx, adapter.Eq("token_hash", h)); err == nil && acc != nil {
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
	if rf, err := s.refreshTokens.FindOne(ctx, adapter.Eq("token_hash", h)); err == nil && rf != nil {
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
