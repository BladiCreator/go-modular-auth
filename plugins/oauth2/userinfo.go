package oauth2

import (
	"context"
	"strings"
	"time"
)

// UserInfo resolves the claims of the authenticated user for the given access token (OIDC Core 1.0).
func (p *Plugin) UserInfo(ctx context.Context, params UserInfoParams) (*UserInfoResult, error) {
	tokenStr := strings.TrimSpace(params.AccessToken)
	if tokenStr == "" {
		return nil, ErrInvalidAccessToken
	}

	var userID string
	var clientID string
	var scopes []string
	now := time.Now().UTC()

	// 1. Check if token is a JWT
	if strings.Count(tokenStr, ".") == 2 {
		claims, err := p.signer.Verify(ctx, tokenStr)
		if err == nil && claims != nil {
			tokenHash := HashToken(tokenStr)
			// Check if revoked in storage
			if stored, err := p.repo.FindAccessToken(ctx, tokenHash); err == nil && stored != nil {
				if stored.UserID != nil {
					userID = *stored.UserID
				}
				clientID = stored.ClientID
				scopes = stored.Scopes
			} else {
				// Verify claims directly
				if subVal, ok := claims["sub"].(string); ok {
					userID = subVal
				}
				if cidVal, ok := claims["client_id"].(string); ok {
					clientID = cidVal
				}
				if scopeVal, ok := claims["scope"].(string); ok {
					scopes = parseScopes(scopeVal)
				}
			}
		}
	}

	// 2. Check Opaque token in DB if not resolved
	if userID == "" {
		tokenHash := HashToken(tokenStr)
		tokenRec, err := p.repo.FindAccessToken(ctx, tokenHash)
		if err != nil || tokenRec == nil || tokenRec.ExpiresAt.Before(now) {
			return nil, ErrInvalidAccessToken
		}
		if tokenRec.UserID != nil {
			userID = *tokenRec.UserID
		}
		clientID = tokenRec.ClientID
		scopes = tokenRec.Scopes
	}

	if userID == "" {
		return nil, ErrInvalidAccessToken
	}

	// 3. Resolve user
	user, err := p.repo.FindUserByID(ctx, userID)
	if err != nil || user == nil {
		return nil, ErrInvalidAccessToken
	}

	// 4. Resolve client to check pairwise subject
	sub := user.ID
	client, err := p.repo.FindClientByClientID(ctx, clientID)
	if err == nil && client != nil && client.SubjectType == SubjectTypePairwise && p.config.PairwiseSecret != "" {
		sectorID := client.URI
		if sectorID == "" && len(client.RedirectURIs) > 0 {
			sectorID = client.RedirectURIs[0]
		}
		sub = DerivePairwiseSubject(p.config.PairwiseSecret, sectorID, user.ID)
	}

	result := &UserInfoResult{
		Sub: sub,
	}

	if containsScope(scopes, ScopeProfile) {
		result.Name = user.Name
	}
	if containsScope(scopes, ScopeEmail) {
		result.Email = user.Email
		verified := user.EmailVerified
		result.EmailVerified = &verified
	}
	if containsScope(scopes, ScopePhone) && user.PhoneNumber != nil {
		result.PhoneNumber = *user.PhoneNumber
		verified := user.PhoneNumberVerified
		result.PhoneNumberVerified = &verified
	}

	// 5. Inject custom claims
	if p.config.CustomUserInfoClaims != nil {
		custom, err := p.config.CustomUserInfoClaims(ctx, client, user, scopes)
		if err == nil && custom != nil {
			result.Claims = custom
		}
	}

	return result, nil
}
