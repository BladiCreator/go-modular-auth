package oauth2

import (
	"context"
	"strings"
	"time"
)

// Revoke revokes an access token or refresh token according to RFC 7009.
func (p *Plugin) Revoke(ctx context.Context, params RevokeParams) (*RevokeResult, error) {
	tokenStr := strings.TrimSpace(params.Token)
	if tokenStr == "" {
		return &RevokeResult{Success: true}, nil
	}

	// 1. Authenticate caller client if credentials provided
	if params.ClientID != "" {
		client, err := p.repo.FindClientByClientID(ctx, params.ClientID)
		if err != nil || client == nil || client.Disabled {
			return nil, ErrInvalidClient
		}
		if !client.Public && params.ClientSecret != "" {
			if err := p.authenticateClient(client, params.ClientSecret); err != nil {
				return nil, err
			}
		}
	}

	tokenHash := HashToken(tokenStr)
	now := time.Now().UTC()

	// Try removing Access Token
	_ = p.repo.DeleteAccessToken(ctx, tokenHash)

	// Try finding and revoking Refresh Token
	if refToken, err := p.repo.FindRefreshToken(ctx, tokenHash); err == nil && refToken != nil {
		_ = p.repo.DeleteRefreshToken(ctx, tokenHash)
		if refToken.FamilyID != "" {
			_ = p.repo.RevokeRefreshTokenFamily(ctx, refToken.FamilyID)
		}
	}

	if p.ctx != nil && p.ctx.Events() != nil {
		p.ctx.Events().Publish(EventTokenRevoked, &TokenRevokedEventPayload{
			TokenHash: tokenHash,
			TokenType: params.TokenTypeHint,
			ClientID:  params.ClientID,
			Timestamp: now,
		})
	}

	return &RevokeResult{Success: true}, nil
}
