package oauth2

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Consent processes the end-user's decision to grant or deny requested scopes.
func (p *Plugin) Consent(ctx context.Context, params ConsentParams) (*ConsentResult, error) {
	if !VerifyOAuthQuery(params.OAuthQuery, params.OAuthSignature, p.config.SecretKey) {
		return nil, ErrInvalidSignature
	}

	authParams, err := parseQueryString(params.OAuthQuery)
	if err != nil {
		return nil, ErrInvalidRequest
	}

	if params.Denied {
		p.publishAuthorizeFailed(authParams.ClientID, "access_denied", authParams.RedirectURI)
		// Return error callback redirect
		deniedURL := fmt.Sprintf("%s?error=access_denied&error_description=User+denied+access&state=%s&iss=%s",
			authParams.RedirectURI, url.QueryEscape(authParams.State), url.QueryEscape(p.config.Issuer))
		return &ConsentResult{
			RedirectURI: deniedURL,
			State:       authParams.State,
			Issuer:      p.config.Issuer,
		}, nil
	}

	client, err := p.repo.FindClientByClientID(ctx, authParams.ClientID)
	if err != nil || client == nil {
		return nil, ErrClientNotFound
	}

	approved := params.ApprovedScopes
	if len(approved) == 0 {
		approved = parseScopes(authParams.Scope)
	}

	now := time.Now().UTC()
	existingConsent, err := p.repo.FindConsent(ctx, client.ClientID, params.UserID)
	if err == nil && existingConsent != nil {
		existingConsent.Scopes = unionScopes(existingConsent.Scopes, approved)
		existingConsent.UpdatedAt = now
		_ = p.repo.UpdateConsent(ctx, existingConsent)
	} else {
		newConsent := &OAuthConsent{
			ID:        uuid.New().String(),
			ClientID:  client.ClientID,
			UserID:    params.UserID,
			Scopes:    approved,
			CreatedAt: now,
			UpdatedAt: now,
		}
		_ = p.repo.CreateConsent(ctx, newConsent)
	}

	if p.ctx != nil && p.ctx.Events() != nil {
		p.ctx.Events().Publish(EventConsentGranted, &ConsentEventPayload{
			Consent: &OAuthConsent{
				ClientID: client.ClientID,
				UserID:   params.UserID,
				Scopes:   approved,
			},
			Timestamp: now,
		})
	}

	// Re-run Authorize with consent satisfied
	authParams.UserID = params.UserID
	authRes, err := p.Authorize(ctx, *authParams)
	if err != nil {
		return nil, err
	}

	return &ConsentResult{
		RedirectURI: authRes.RedirectURI,
		Code:        authRes.Code,
		State:       authRes.State,
		Issuer:      authRes.Issuer,
	}, nil
}

// RevokeConsent revokes all scopes previously granted by a user to a specific OAuth client.
func (p *Plugin) RevokeConsent(ctx context.Context, params RevokeConsentParams) (*RevokeConsentResult, error) {
	if strings.TrimSpace(params.ClientID) == "" || strings.TrimSpace(params.UserID) == "" {
		return nil, ErrInvalidRequest
	}

	consent, err := p.repo.FindConsent(ctx, params.ClientID, params.UserID)
	if err != nil || consent == nil {
		return &RevokeConsentResult{Success: true}, nil
	}

	if err := p.repo.DeleteConsent(ctx, consent.ID); err != nil {
		return nil, fmt.Errorf("oauth2: failed to delete consent: %w", err)
	}

	if p.ctx != nil && p.ctx.Events() != nil {
		p.ctx.Events().Publish(EventConsentRevoked, &ConsentEventPayload{
			Consent:   consent,
			Timestamp: time.Now().UTC(),
		})
	}

	return &RevokeConsentResult{Success: true}, nil
}

// ListConsents retrieves all active consents granted by a specific user.
func (p *Plugin) ListConsents(ctx context.Context, params ListConsentsParams) (*ListConsentsResult, error) {
	if strings.TrimSpace(params.UserID) == "" {
		return nil, ErrInvalidRequest
	}

	consents, err := p.repo.ListConsentsByUserID(ctx, params.UserID)
	if err != nil {
		return nil, fmt.Errorf("oauth2: failed to list user consents: %w", err)
	}

	return &ListConsentsResult{Consents: consents}, nil
}

func unionScopes(a, b []string) []string {
	m := make(map[string]bool)
	for _, s := range a {
		m[s] = true
	}
	for _, s := range b {
		m[s] = true
	}
	res := make([]string, 0, len(m))
	for s := range m {
		res = append(res, s)
	}
	return res
}
