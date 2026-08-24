package deviceauth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/entity"
	"github.com/BladiCreator/go-modular-auth/plugin"
	"github.com/google/uuid"
)

// PluginID is the unique string identifier for the Device Authorization plugin ("device-authorization").
const PluginID = "device-authorization"

// OAuth2DeviceGrantType is the standard RFC 8628 grant type string.
const OAuth2DeviceGrantType = "urn:ietf:params:oauth:grant-type:device_code"

// Plugin implements the RFC 8628 Device Authorization Flow plugin for go-modular-auth.
type Plugin struct {
	repo   Repository
	config Config
	ctx    *plugin.Context
}

// New instantiates a new Device Authorization plugin configured with the given repository and options.
func New(repo Repository, opts ...Option) *Plugin {
	cfg := DefaultConfig()
	for _, opt := range opts {
		opt(&cfg)
	}

	return &Plugin{
		repo:   repo,
		config: cfg,
	}
}

// ID returns the unique string identifier for the plugin ("device-authorization").
func (p *Plugin) ID() string {
	return PluginID
}

// Init initializes the plugin with the shared execution context.
func (p *Plugin) Init(ctx *plugin.Context) error {
	p.ctx = ctx
	return nil
}

// Config returns a copy of the active plugin configuration.
func (p *Plugin) Config() Config {
	return p.config
}

// RequestDeviceCode initiates a new device authorization grant request.
func (p *Plugin) RequestDeviceCode(ctx context.Context, params RequestDeviceCodeParams) (*DeviceCodeResponse, error) {
	if params.ClientID != "" && p.config.ValidateClient != nil {
		valid, err := p.config.ValidateClient(ctx, params.ClientID)
		if err != nil {
			return nil, err
		}
		if !valid {
			return nil, ErrInvalidClientID
		}
	}

	if p.config.OnDeviceAuthRequest != nil {
		if err := p.config.OnDeviceAuthRequest(ctx, params.ClientID, params.Scope); err != nil {
			return nil, err
		}
	}

	// Generate device_code
	var deviceCode string
	var err error
	if p.config.GenerateDeviceCode != nil {
		deviceCode, err = p.config.GenerateDeviceCode(p.config.DeviceCodeLength)
	} else {
		deviceCode, err = DefaultGenerateDeviceCode(p.config.DeviceCodeLength)
	}
	if err != nil {
		return nil, err
	}

	// Generate user_code
	var rawUserCode string
	if p.config.GenerateUserCode != nil {
		rawUserCode, err = p.config.GenerateUserCode(p.config.UserCodeLength)
	} else {
		rawUserCode, err = DefaultGenerateUserCode(p.config.UserCodeLength)
	}
	if err != nil {
		return nil, err
	}

	normalizedUserCode := NormalizeUserCode(rawUserCode)
	now := time.Now()
	expiresAt := now.Add(p.config.ExpiresIn)

	var clientIDPtr *string
	if params.ClientID != "" {
		clientIDPtr = &params.ClientID
	}

	record := &DeviceCode{
		ID:              uuid.New().String(),
		DeviceCode:      deviceCode,
		UserCode:        normalizedUserCode,
		UserID:          params.UserID,
		ExpiresAt:       expiresAt,
		Status:          StatusPending,
		PollingInterval: p.config.Interval,
		ClientID:        clientIDPtr,
		Scope:           params.Scope,
		CreatedAt:       now,
		UpdatedAt:       now,
	}

	if err := p.repo.CreateDeviceCode(ctx, record); err != nil {
		return nil, err
	}

	uri, uriComplete := BuildVerificationURIs(p.config.VerificationURI, p.config.CustomURI, rawUserCode)

	if p.ctx != nil && p.ctx.Events() != nil {
		p.ctx.Events().Publish(EventDeviceCodeRequested, ctx, &DeviceCodeRequestedPayload{
			DeviceCode: deviceCode,
			UserCode:   rawUserCode,
			ClientID:   clientIDPtr,
			Scope:      params.Scope,
		})
	}

	return &DeviceCodeResponse{
		DeviceCode:              deviceCode,
		UserCode:                rawUserCode,
		VerificationURI:         uri,
		VerificationURIComplete: uriComplete,
		ExpiresIn:               int64(p.config.ExpiresIn.Seconds()),
		Interval:                int64(p.config.Interval.Seconds()),
	}, nil
}

// ExchangeDeviceToken polls for authorization and exchanges an approved device_code for a session access token.
func (p *Plugin) ExchangeDeviceToken(ctx context.Context, params ExchangeDeviceTokenParams) (*TokenResponse, error) {
	if params.GrantType != OAuth2DeviceGrantType {
		return nil, ErrInvalidGrantType
	}

	if params.DeviceCode == "" {
		return nil, ErrInvalidDeviceCode
	}

	record, err := p.repo.FindByDeviceCode(ctx, params.DeviceCode)
	if err != nil || record == nil {
		return nil, ErrInvalidDeviceCode
	}

	if params.ClientID != nil && record.ClientID != nil && *params.ClientID != *record.ClientID {
		return nil, ErrInvalidClientID
	}

	now := time.Now()
	if record.ExpiresAt.Before(now) {
		_ = p.repo.DeleteDeviceCode(ctx, record.DeviceCode)
		return nil, ErrCodeExpired
	}

	// Rate limiting check
	if record.LastPolledAt != nil {
		timeSinceLastPoll := now.Sub(*record.LastPolledAt)
		if timeSinceLastPoll < record.PollingInterval {
			_ = p.repo.UpdateLastPolledAt(ctx, record.DeviceCode, now)
			return nil, ErrSlowDown
		}
	}

	_ = p.repo.UpdateLastPolledAt(ctx, record.DeviceCode, now)

	switch record.Status {
	case StatusPending:
		return nil, ErrAuthorizationPending
	case StatusDenied:
		_ = p.repo.DeleteDeviceCode(ctx, record.DeviceCode)
		return nil, ErrAccessDenied
	case StatusApproved:
		// Atomic single-use consumption to prevent race conditions
		consumed, err := p.repo.ConsumeDeviceCode(ctx, record.DeviceCode)
		if err != nil || consumed == nil {
			return nil, ErrAlreadyConsumed
		}

		if consumed.UserID == nil || *consumed.UserID == "" {
			return nil, ErrUserNotFound
		}

		user, err := p.repo.GetUserByID(ctx, *consumed.UserID)
		if err != nil || user == nil {
			return nil, ErrUserNotFound
		}

		sessionToken, err := p.generateToken(32)
		if err != nil {
			return nil, err
		}

		sessionExpiry := p.config.SessionExpiry
		session := &entity.Session{
			ID:        uuid.New().String(),
			UserID:    user.ID,
			Token:     sessionToken,
			ExpiresAt: now.Add(sessionExpiry),
			CreatedAt: now,
		}

		createdSession, err := p.repo.CreateSession(ctx, session)
		if err != nil {
			return nil, err
		}

		var scopeStr string
		if consumed.Scope != nil {
			scopeStr = *consumed.Scope
		}

		if p.ctx != nil && p.ctx.Events() != nil {
			p.ctx.Events().Publish(EventDeviceTokenExchanged, ctx, &DeviceTokenExchangedPayload{
				DeviceCode:   record.DeviceCode,
				UserID:       user.ID,
				SessionToken: createdSession.Token,
			})
		}

		return &TokenResponse{
			AccessToken: createdSession.Token,
			TokenType:   "Bearer",
			ExpiresIn:   int64(sessionExpiry.Seconds()),
			Scope:       scopeStr,
			UserID:      user.ID,
		}, nil

	default:
		return nil, ErrInvalidDeviceCode
	}
}

// GetVerificationState retrieves the device authorization grant state by user_code.
func (p *Plugin) GetVerificationState(ctx context.Context, rawUserCode string) (*DeviceCode, error) {
	if rawUserCode == "" {
		return nil, ErrInvalidUserCode
	}

	normalized := NormalizeUserCode(rawUserCode)
	record, err := p.repo.FindByUserCode(ctx, normalized)
	if err != nil || record == nil {
		return nil, ErrInvalidUserCode
	}

	if record.ExpiresAt.Before(time.Now()) {
		return nil, ErrCodeExpired
	}

	return record, nil
}

// ApproveDeviceCode approves a pending device authorization request for an authenticated user.
func (p *Plugin) ApproveDeviceCode(ctx context.Context, params ApproveDeviceCodeParams) error {
	if params.UserID == "" {
		return ErrInvalidParameter
	}

	if params.UserCode == "" {
		return ErrInvalidUserCode
	}

	normalized := NormalizeUserCode(params.UserCode)
	record, err := p.repo.FindByUserCode(ctx, normalized)
	if err != nil || record == nil {
		return ErrInvalidUserCode
	}

	if record.ExpiresAt.Before(time.Now()) {
		return ErrCodeExpired
	}

	if record.Status != StatusPending {
		return ErrAlreadyConsumed
	}

	if err := p.repo.UpdateStatus(ctx, normalized, StatusApproved, &params.UserID); err != nil {
		return err
	}

	if p.ctx != nil && p.ctx.Events() != nil {
		p.ctx.Events().Publish(EventDeviceCodeApproved, ctx, &DeviceCodeApprovedPayload{
			UserCode: params.UserCode,
			UserID:   params.UserID,
		})
	}

	return nil
}

// DenyDeviceCode rejects a pending device authorization request.
func (p *Plugin) DenyDeviceCode(ctx context.Context, params DenyDeviceCodeParams) error {
	if params.UserCode == "" {
		return ErrInvalidUserCode
	}

	normalized := NormalizeUserCode(params.UserCode)
	record, err := p.repo.FindByUserCode(ctx, normalized)
	if err != nil || record == nil {
		return ErrInvalidUserCode
	}

	if record.ExpiresAt.Before(time.Now()) {
		return ErrCodeExpired
	}

	if err := p.repo.UpdateStatus(ctx, normalized, StatusDenied, nil); err != nil {
		return err
	}

	if p.ctx != nil && p.ctx.Events() != nil {
		p.ctx.Events().Publish(EventDeviceCodeDenied, ctx, &DeviceCodeDeniedPayload{
			UserCode: params.UserCode,
		})
	}

	return nil
}

// generateToken generates a random token using context CryptoUtils or crypto/rand fallback.
func (p *Plugin) generateToken(length int) (string, error) {
	if p.ctx != nil && p.ctx.Crypto() != nil {
		return p.ctx.Crypto().GenerateRandomToken(length)
	}
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
