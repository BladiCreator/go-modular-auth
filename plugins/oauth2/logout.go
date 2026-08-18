package oauth2

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// EndSession implements OpenID Connect RP-Initiated Logout 1.0.
func (p *Plugin) EndSession(ctx context.Context, params EndSessionParams) (*EndSessionResult, error) {
	var clientID = params.ClientID
	var userID string

	// 1. Inspect id_token_hint if provided
	if params.IDTokenHint != "" {
		claims, err := p.signer.Verify(ctx, params.IDTokenHint)
		if err == nil && claims != nil {
			if subVal, ok := claims["sub"].(string); ok {
				userID = subVal
			}
			if audVal, ok := claims["aud"].(string); ok && clientID == "" {
				clientID = audVal
			}
		}
	}

	// 2. Terminate session if sessionID provided
	if params.SessionID != "" {
		_ = p.repo.DeleteSessionByID(ctx, params.SessionID)
	}

	// 3. Validate post_logout_redirect_uri
	targetRedirect := params.PostLogoutRedirectURI
	if targetRedirect != "" && clientID != "" {
		client, err := p.repo.FindClientByClientID(ctx, clientID)
		if err == nil && client != nil {
			if !client.EnableEndSession {
				return nil, ErrAccessDenied
			}
			if !isAllowedRedirectURI(targetRedirect, client.PostLogoutRedirectURIs) {
				return nil, ErrInvalidRedirectURI
			}
		}
	}

	// Append state if present
	if targetRedirect != "" && params.State != "" {
		u, err := url.Parse(targetRedirect)
		if err == nil {
			q := u.Query()
			q.Set("state", params.State)
			u.RawQuery = q.Encode()
			targetRedirect = u.String()
		} else {
			targetRedirect = fmt.Sprintf("%s?state=%s", targetRedirect, url.QueryEscape(params.State))
		}
	}

	if p.ctx != nil && p.ctx.Events() != nil {
		p.ctx.Events().Publish(EventSessionEnded, &SessionEndedEventPayload{
			UserID:                userID,
			ClientID:              clientID,
			PostLogoutRedirectURI: targetRedirect,
			Timestamp:             time.Now().UTC(),
		})
	}

	if targetRedirect == "" {
		targetRedirect = p.config.LoginPage
	}

	return &EndSessionResult{
		RedirectURI: strings.TrimSpace(targetRedirect),
	}, nil
}
