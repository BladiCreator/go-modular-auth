package ott

import (
	"context"
	"time"

	"github.com/BladiCreator/go-modular-auth/plugin"
	"github.com/google/uuid"
)

// PluginID is the unique string identifier for the One-Time Token plugin ("one-time-token").
const PluginID = "one-time-token"

// Plugin implements the One-Time Token authentication plugin for go-modular-auth.
type Plugin struct {
	repo   Repository
	config Config
	ctx    *plugin.Context
}

// New instantiates a new One-Time Token plugin configured with the given repository and options.
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

// ID returns the unique string identifier for the plugin ("one-time-token").
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

// GenerateToken generates and persists a new single-use token bound to an active user session token.
func (p *Plugin) GenerateToken(ctx context.Context, params GenerateTokenParams) (*GenerateTokenResponse, error) {
	if params.SessionToken == "" {
		return nil, ErrInvalidParameter
	}

	if params.IsClientReq && p.config.DisableClientRequest {
		return nil, ErrClientRequestDisabled
	}

	// Validate underlying session existence and lifetime
	session, err := p.repo.GetSessionByToken(ctx, params.SessionToken)
	if err != nil {
		return nil, ErrSessionNotFound
	}
	if session == nil {
		return nil, ErrSessionNotFound
	}
	if !session.ExpiresAt.IsZero() && time.Now().After(session.ExpiresAt) {
		return nil, ErrSessionExpired
	}

	// Generate raw token string
	var rawToken string
	if p.config.CustomGenerator != nil {
		rawToken, err = p.config.CustomGenerator(32)
	} else {
		rawToken, err = DefaultGenerateToken(32)
	}
	if err != nil {
		return nil, err
	}

	// Determine storage representation based on StoreTokenMode
	storedToken := rawToken
	if p.config.StoreTokenMode == StoreTokenHashed {
		if p.config.CustomHasher != nil {
			storedToken, err = p.config.CustomHasher(rawToken)
		} else {
			storedToken, err = DefaultTokenHasher(rawToken)
		}
		if err != nil {
			return nil, err
		}
	}

	now := time.Now()
	expiresAt := now.Add(p.config.ExpiresIn)
	identifier := ToOTTIdentifier(storedToken)

	record := &VerificationRecord{
		ID:         uuid.New().String(),
		Identifier: identifier,
		Value:      params.SessionToken,
		ExpiresAt:  expiresAt,
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	if err := p.repo.CreateVerificationValue(ctx, record); err != nil {
		return nil, err
	}

	// Dispatch event notification if bus is initialized
	if p.ctx != nil && p.ctx.Events() != nil {
		p.ctx.Events().Publish(EventOTTGenerated, ctx, &OTTGeneratedPayload{
			SessionToken: params.SessionToken,
			Token:        rawToken,
			ExpiresAt:    expiresAt,
		})
	}

	return &GenerateTokenResponse{
		Token: rawToken,
	}, nil
}

// VerifyToken validates and atomically consumes a One-Time Token, returning the active session and user entities.
func (p *Plugin) VerifyToken(ctx context.Context, params VerifyTokenParams) (*VerifyTokenResponse, error) {
	if params.Token == "" {
		return nil, ErrInvalidParameter
	}

	storedToken := params.Token
	var err error
	if p.config.StoreTokenMode == StoreTokenHashed {
		if p.config.CustomHasher != nil {
			storedToken, err = p.config.CustomHasher(params.Token)
		} else {
			storedToken, err = DefaultTokenHasher(params.Token)
		}
		if err != nil {
			return nil, ErrInvalidToken
		}
	}

	identifier := ToOTTIdentifier(storedToken)

	// Atomically consume token from storage to prevent race conditions and single-use violations
	record, err := p.repo.ConsumeVerificationValue(ctx, identifier)
	if err != nil || record == nil {
		return nil, ErrInvalidToken
	}

	// Check token expiration timestamp
	if !record.ExpiresAt.IsZero() && time.Now().After(record.ExpiresAt) {
		return nil, ErrTokenExpired
	}

	// Retrieve active session entity
	session, err := p.repo.GetSessionByToken(ctx, record.Value)
	if err != nil || session == nil {
		return nil, ErrSessionNotFound
	}

	if !session.ExpiresAt.IsZero() && time.Now().After(session.ExpiresAt) {
		return nil, ErrSessionExpired
	}

	// Retrieve user entity
	user, err := p.repo.GetUserByID(ctx, session.UserID)
	if err != nil || user == nil {
		return nil, ErrUserNotFound
	}

	// Dispatch event notification if bus is initialized
	if p.ctx != nil && p.ctx.Events() != nil {
		p.ctx.Events().Publish(EventOTTVerified, ctx, &OTTVerifiedPayload{
			SessionID: session.ID,
			UserID:    user.ID,
			Token:     params.Token,
		})
	}

	return &VerifyTokenResponse{
		Session: session,
		User:    user,
	}, nil
}
