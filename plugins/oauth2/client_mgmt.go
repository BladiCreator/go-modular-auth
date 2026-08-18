package oauth2

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// RegisterClient performs RFC 7591 Dynamic Client Registration or programmatic client creation.
func (p *Plugin) RegisterClient(ctx context.Context, params RegisterClientParams) (*RegisterClientResult, error) {
	if !p.config.AllowDynamicClientRegistration && !p.config.AllowUnauthenticatedClientRegistration {
		// If disabled by default, check if called programmatically
	}

	if strings.TrimSpace(params.ClientName) == "" {
		return nil, ErrInvalidRequest
	}
	if len(params.RedirectURIs) == 0 {
		return nil, ErrInvalidRedirectURI
	}

	clientID, err := GenerateRandomString(16)
	if err != nil {
		return nil, fmt.Errorf("oauth2: failed to generate client_id: %w", err)
	}

	var rawSecret string
	var storedSecret *string

	if !params.Public {
		rawSecret, err = GenerateRandomString(32)
		if err != nil {
			return nil, fmt.Errorf("oauth2: failed to generate client_secret: %w", err)
		}

		val := rawSecret
		if p.config.StoreClientSecretMode == StoreModeHashed {
			val = HashSecret(rawSecret)
		} else if p.config.StoreClientSecretMode == StoreModeEncrypted {
			enc, err := Encrypt([]byte(rawSecret), DeriveAESKey(p.config.SecretKey))
			if err != nil {
				return nil, fmt.Errorf("oauth2: failed to encrypt client secret: %w", err)
			}
			val = enc
		}
		storedSecret = &val
	}

	grantTypes := params.GrantTypes
	if len(grantTypes) == 0 {
		grantTypes = []GrantType{GrantTypeAuthorizationCode, GrantTypeRefreshToken}
	}

	responseTypes := params.ResponseTypes
	if len(responseTypes) == 0 {
		responseTypes = []ResponseType{ResponseTypeCode}
	}

	authMethod := params.TokenEndpointAuthMethod
	if authMethod == "" {
		if params.Public {
			authMethod = AuthMethodNone
		} else {
			authMethod = AuthMethodClientSecretBasic
		}
	}

	now := time.Now().UTC()
	client := &OAuthClient{
		ID:                      uuid.New().String(),
		ClientID:                clientID,
		ClientSecret:            storedSecret,
		Name:                    params.ClientName,
		URI:                     params.ClientURI,
		Icon:                    params.LogoURI,
		Contacts:                params.Contacts,
		TOS:                     params.TOSURI,
		Policy:                  params.PolicyURI,
		SoftwareID:              params.SoftwareID,
		SoftwareVersion:         params.SoftwareVersion,
		RedirectURIs:            params.RedirectURIs,
		PostLogoutRedirectURIs:  params.PostLogoutRedirectURIs,
		TokenEndpointAuthMethod: authMethod,
		GrantTypes:              grantTypes,
		ResponseTypes:           responseTypes,
		Scopes:                  parseScopes(params.Scope),
		Public:                  params.Public,
		Type:                    ClientTypeConfidential,
		RequirePKCE:             true,
		SubjectType:             params.SubjectType,
		SkipConsent:             params.SkipConsent,
		EnableEndSession:        params.EnableEndSession,
		UserID:                  params.UserID,
		Metadata:                params.Metadata,
		CreatedAt:               now,
		UpdatedAt:               now,
	}

	if params.Public {
		client.Type = ClientTypePublic
	}
	if client.SubjectType == "" {
		client.SubjectType = SubjectTypePublic
	}

	if err := p.repo.CreateClient(ctx, client); err != nil {
		return nil, fmt.Errorf("oauth2: failed to save client: %w", err)
	}

	if p.ctx != nil && p.ctx.Events() != nil {
		p.ctx.Events().Publish(EventClientCreated, &ClientEventPayload{
			Client:    client,
			Timestamp: now,
		})
	}

	return &RegisterClientResult{
		Client:       client,
		ClientID:     clientID,
		ClientSecret: rawSecret,
	}, nil
}

// GetClient retrieves an OAuth client by its ClientID.
func (p *Plugin) GetClient(ctx context.Context, params GetClientParams) (*GetClientResult, error) {
	if strings.TrimSpace(params.ClientID) == "" {
		return nil, ErrInvalidClient
	}

	client, err := p.repo.FindClientByClientID(ctx, params.ClientID)
	if err != nil || client == nil {
		return nil, ErrClientNotFound
	}

	return &GetClientResult{Client: client}, nil
}

// UpdateClient updates mutable properties of an existing OAuth client.
func (p *Plugin) UpdateClient(ctx context.Context, params UpdateClientParams) (*UpdateClientResult, error) {
	if strings.TrimSpace(params.ClientID) == "" {
		return nil, ErrInvalidClient
	}

	client, err := p.repo.FindClientByClientID(ctx, params.ClientID)
	if err != nil || client == nil {
		return nil, ErrClientNotFound
	}

	if params.ClientName != nil {
		client.Name = *params.ClientName
	}
	if params.ClientURI != nil {
		client.URI = *params.ClientURI
	}
	if params.LogoURI != nil {
		client.Icon = *params.LogoURI
	}
	if params.Contacts != nil {
		client.Contacts = params.Contacts
	}
	if params.RedirectURIs != nil {
		client.RedirectURIs = params.RedirectURIs
	}
	if params.PostLogoutRedirectURIs != nil {
		client.PostLogoutRedirectURIs = params.PostLogoutRedirectURIs
	}
	if params.GrantTypes != nil {
		client.GrantTypes = params.GrantTypes
	}
	if params.Scopes != nil {
		client.Scopes = params.Scopes
	}
	if params.SkipConsent != nil {
		client.SkipConsent = *params.SkipConsent
	}
	if params.EnableEndSession != nil {
		client.EnableEndSession = *params.EnableEndSession
	}
	if params.Disabled != nil {
		client.Disabled = *params.Disabled
	}
	if params.Metadata != nil {
		client.Metadata = params.Metadata
	}
	client.UpdatedAt = time.Now().UTC()

	if err := p.repo.UpdateClient(ctx, client); err != nil {
		return nil, fmt.Errorf("oauth2: failed to update client: %w", err)
	}

	if p.ctx != nil && p.ctx.Events() != nil {
		p.ctx.Events().Publish(EventClientUpdated, &ClientEventPayload{
			Client:    client,
			Timestamp: client.UpdatedAt,
		})
	}

	return &UpdateClientResult{Client: client}, nil
}

// DeleteClient removes an OAuth client record from storage.
func (p *Plugin) DeleteClient(ctx context.Context, params DeleteClientParams) (*DeleteClientResult, error) {
	if strings.TrimSpace(params.ClientID) == "" {
		return nil, ErrInvalidClient
	}

	client, err := p.repo.FindClientByClientID(ctx, params.ClientID)
	if err != nil || client == nil {
		return nil, ErrClientNotFound
	}

	if err := p.repo.DeleteClient(ctx, params.ClientID); err != nil {
		return nil, fmt.Errorf("oauth2: failed to delete client: %w", err)
	}

	if p.ctx != nil && p.ctx.Events() != nil {
		p.ctx.Events().Publish(EventClientDeleted, &ClientEventPayload{
			Client:    client,
			Timestamp: time.Now().UTC(),
		})
	}

	return &DeleteClientResult{Success: true}, nil
}

// RotateClientSecret generates and replaces the client secret for a confidential OAuth client.
func (p *Plugin) RotateClientSecret(ctx context.Context, params RotateClientSecretParams) (*RotateClientSecretResult, error) {
	if strings.TrimSpace(params.ClientID) == "" {
		return nil, ErrInvalidClient
	}

	client, err := p.repo.FindClientByClientID(ctx, params.ClientID)
	if err != nil || client == nil {
		return nil, ErrClientNotFound
	}
	if client.Public {
		return nil, ErrInvalidRequest
	}

	newSecret, err := GenerateRandomString(32)
	if err != nil {
		return nil, fmt.Errorf("oauth2: failed to generate new secret: %w", err)
	}

	val := newSecret
	if p.config.StoreClientSecretMode == StoreModeHashed {
		val = HashSecret(newSecret)
	} else if p.config.StoreClientSecretMode == StoreModeEncrypted {
		enc, err := Encrypt([]byte(newSecret), DeriveAESKey(p.config.SecretKey))
		if err != nil {
			return nil, fmt.Errorf("oauth2: failed to encrypt new secret: %w", err)
		}
		val = enc
	}

	client.ClientSecret = &val
	client.UpdatedAt = time.Now().UTC()

	if err := p.repo.UpdateClient(ctx, client); err != nil {
		return nil, fmt.Errorf("oauth2: failed to update rotated secret: %w", err)
	}

	return &RotateClientSecretResult{
		ClientID:        client.ClientID,
		NewClientSecret: newSecret,
	}, nil
}
