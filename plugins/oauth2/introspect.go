package oauth2

import (
	"context"
	"strings"
	"time"
)

// Introspect inspects an active access token or refresh token according to RFC 7662.
func (p *Plugin) Introspect(ctx context.Context, params IntrospectParams) (*IntrospectResult, error) {
	if strings.TrimSpace(params.Token) == "" {
		return &IntrospectResult{Active: false}, nil
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

	tokenStr := strings.TrimSpace(params.Token)
	now := time.Now().UTC()

	// 2. Check if token is a JWT
	if strings.Count(tokenStr, ".") == 2 {
		claims, err := p.signer.Verify(ctx, tokenStr)
		if err == nil && claims != nil {
			// Check if token has been revoked in DB
			tokenHash := HashToken(tokenStr)
			if stored, err := p.repo.FindAccessToken(ctx, tokenHash); err != nil || stored == nil {
				// If not found in DB, token might have been deleted/revoked
				return &IntrospectResult{Active: false}, nil
			}

			clientID, _ := claims["client_id"].(string)
			sub, _ := claims["sub"].(string)
			scope, _ := claims["scope"].(string)
			iss, _ := claims["iss"].(string)
			jti, _ := claims["jti"].(string)

			var expUnix, iatUnix int64
			if expVal, ok := claims["exp"].(float64); ok {
				expUnix = int64(expVal)
			}
			if iatVal, ok := claims["iat"].(float64); ok {
				iatUnix = int64(iatVal)
			}

			if expUnix > 0 && now.Unix() > expUnix {
				return &IntrospectResult{Active: false}, nil
			}

			var audList []string
			if audVal, ok := claims["aud"].(string); ok {
				audList = []string{audVal}
			} else if audVals, ok := claims["aud"].([]any); ok {
				for _, a := range audVals {
					if str, ok := a.(string); ok {
						audList = append(audList, str)
					}
				}
			}

			return &IntrospectResult{
				Active:    true,
				Scope:     scope,
				ClientID:  clientID,
				Sub:       sub,
				TokenType: "Bearer",
				Exp:       expUnix,
				Iat:       iatUnix,
				Aud:       audList,
				Iss:       iss,
				Jti:       jti,
				Extra:     claims,
			}, nil
		}
	}

	// 3. Check Opaque Access Token in DB
	tokenHash := HashToken(tokenStr)
	if accessRec, err := p.repo.FindAccessToken(ctx, tokenHash); err == nil && accessRec != nil {
		if accessRec.ExpiresAt.After(now) {
			sub := ""
			if accessRec.UserID != nil {
				sub = *accessRec.UserID
			}
			return &IntrospectResult{
				Active:    true,
				Scope:     strings.Join(accessRec.Scopes, " "),
				ClientID:  accessRec.ClientID,
				Sub:       sub,
				TokenType: "Bearer",
				Exp:       accessRec.ExpiresAt.Unix(),
				Iat:       accessRec.CreatedAt.Unix(),
				Iss:       p.config.Issuer,
			}, nil
		}
	}

	// 4. Check Refresh Token in DB
	if refreshRec, err := p.repo.FindRefreshToken(ctx, tokenHash); err == nil && refreshRec != nil {
		if refreshRec.RevokedAt == nil && refreshRec.ExpiresAt.After(now) {
			return &IntrospectResult{
				Active:    true,
				Scope:     strings.Join(refreshRec.Scopes, " "),
				ClientID:  refreshRec.ClientID,
				Sub:       refreshRec.UserID,
				TokenType: "RefreshToken",
				Exp:       refreshRec.ExpiresAt.Unix(),
				Iat:       refreshRec.CreatedAt.Unix(),
				Iss:       p.config.Issuer,
			}, nil
		}
	}

	return &IntrospectResult{Active: false}, nil
}
