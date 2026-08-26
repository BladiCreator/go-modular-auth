package multisession

import (
	"context"
	"fmt"
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/entity"
	"github.com/BladiCreator/go-modular-auth/plugin"
)

// PluginID is the unique string identifier for the MultiSession plugin ("multi-session").
const PluginID = "multi-session"

// Plugin implements the MultiSession plugin for go-modular-auth.
type Plugin struct {
	repo   Repository
	config Config
	ctx    *plugin.Context
}

// New instantiates a new MultiSession plugin configured with the given repository and options.
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

// ID returns the unique identifier for the MultiSession plugin ("multi-session").
func (p *Plugin) ID() string {
	return PluginID
}

// Init initializes the plugin with the shared execution context.
func (p *Plugin) Init(ctx *plugin.Context) error {
	p.ctx = ctx
	return nil
}

// Config returns the active configuration of the MultiSession plugin.
func (p *Plugin) Config() Config {
	return p.config
}

// GetConfigInfo returns a MultiSessionConfigInfo struct containing active public configuration settings.
func (p *Plugin) GetConfigInfo() MultiSessionConfigInfo {
	return MultiSessionConfigInfo{
		MaximumSessions: p.config.MaximumSessions,
		CookiePrefix:    p.config.CookiePrefix,
	}
}

// Repository returns the active storage repository instance.
func (p *Plugin) Repository() Repository {
	return p.repo
}

// publishEvent publishes a lifecycle event to the EventBus if available.
func (p *Plugin) publishEvent(topic string, ctx context.Context, payload any) {
	if p.ctx != nil && p.ctx.Events() != nil {
		p.ctx.Events().Publish(topic, payload)
	}
}

// ListDeviceSessions queries and returns all valid, non-expired device sessions for the given parameters.
func (p *Plugin) ListDeviceSessions(ctx context.Context, params ListDeviceSessionsParams) (*ListDeviceSessionsResult, error) {
	p.publishEvent(EventListDeviceSessionsBefore, ctx, &ListDeviceSessionsEventPayload{
		Params: &params,
	})

	if len(params.Tokens) == 0 {
		res := &ListDeviceSessionsResult{DeviceSessions: []DeviceSession{}, TotalCount: 0}
		p.publishEvent(EventListDeviceSessionsAfter, ctx, &ListDeviceSessionsEventPayload{
			Params: &params,
			Result: res,
		})
		return res, nil
	}

	sessions, users, err := p.repo.FindSessionsByTokens(ctx, params.Tokens)
	if err != nil {
		return nil, fmt.Errorf("multisession: failed to find sessions by tokens: %w", err)
	}

	userMap := make(map[string]*entity.User)
	for _, u := range users {
		if u != nil {
			userMap[u.ID] = u
		}
	}

	now := time.Now()
	seenUsers := make(map[string]bool)
	deviceSessions := make([]DeviceSession, 0)
	var activeSessionPtr *DeviceSession

	for _, s := range sessions {
		if s == nil || s.ExpiresAt.Before(now) {
			continue
		}
		if seenUsers[s.UserID] {
			continue
		}
		user, ok := userMap[s.UserID]
		if !ok || user == nil {
			continue
		}
		seenUsers[s.UserID] = true

		isActive := (params.ActiveToken != "" && s.Token == params.ActiveToken)
		ds := DeviceSession{
			Session:  *s,
			User:     *user,
			IsActive: isActive,
		}
		deviceSessions = append(deviceSessions, ds)

		if isActive {
			activeSessionPtr = &deviceSessions[len(deviceSessions)-1]
		}
	}

	res := &ListDeviceSessionsResult{
		DeviceSessions: deviceSessions,
		TotalCount:     len(deviceSessions),
		ActiveSession:  activeSessionPtr,
	}

	p.publishEvent(EventListDeviceSessionsAfter, ctx, &ListDeviceSessionsEventPayload{
		Params: &params,
		Result: res,
	})

	return res, nil
}

// SetActiveSession activates a target device session specified in parameters.
func (p *Plugin) SetActiveSession(ctx context.Context, params SetActiveSessionParams) (*SetActiveSessionResult, error) {
	p.publishEvent(EventSetActiveSessionBefore, ctx, &SetActiveSessionEventPayload{
		Params: &params,
	})

	if params.SessionToken == "" {
		return nil, ErrInvalidSessionToken
	}

	session, err := p.repo.GetSessionByToken(ctx, params.SessionToken)
	if err != nil || session == nil || session.ExpiresAt.Before(time.Now()) {
		return nil, ErrSessionNotFound
	}

	user, err := p.repo.GetUserByID(ctx, session.UserID)
	if err != nil || user == nil {
		return nil, fmt.Errorf("multisession: user not found: %w", err)
	}

	res := &SetActiveSessionResult{
		DeviceSession: DeviceSession{
			Session:  *session,
			User:     *user,
			IsActive: true,
		},
		ActiveToken: session.Token,
		ExpiresAt:   session.ExpiresAt,
		Status:      true,
	}

	if p.config.OnSessionActivated != nil {
		if err := p.config.OnSessionActivated(ctx, res); err != nil {
			return nil, fmt.Errorf("multisession: session activated callback error: %w", err)
		}
	}

	p.publishEvent(EventSetActiveSessionAfter, ctx, &SetActiveSessionEventPayload{
		Params: &params,
		Result: res,
	})

	return res, nil
}

// RevokeDeviceSession revokes a single session, all sessions, or all other non-active sessions based on params.
func (p *Plugin) RevokeDeviceSession(ctx context.Context, params RevokeDeviceSessionParams) (*RevokeDeviceSessionResult, error) {
	p.publishEvent(EventRevokeDeviceSessionBefore, ctx, &RevokeDeviceSessionEventPayload{
		Params: &params,
	})

	if params.RevokeAll {
		if len(params.DeviceTokens) > 0 {
			_ = p.repo.DeleteSessions(ctx, params.DeviceTokens)
		}
		result := &RevokeDeviceSessionResult{
			Status:             true,
			RevokedTokens:      params.DeviceTokens,
			ClearActiveSession: true,
		}
		p.publishEvent(EventRevokeDeviceSessionAfter, ctx, &RevokeDeviceSessionEventPayload{
			Params: &params,
			Result: result,
		})
		return result, nil
	}

	if params.RevokeOther {
		tokensToRevoke := make([]string, 0)
		for _, tok := range params.DeviceTokens {
			if tok != params.ActiveTokenInReq {
				tokensToRevoke = append(tokensToRevoke, tok)
			}
		}
		if len(tokensToRevoke) > 0 {
			_ = p.repo.DeleteSessions(ctx, tokensToRevoke)
		}
		result := &RevokeDeviceSessionResult{
			Status:        true,
			RevokedTokens: tokensToRevoke,
		}
		p.publishEvent(EventRevokeDeviceSessionAfter, ctx, &RevokeDeviceSessionEventPayload{
			Params: &params,
			Result: result,
		})
		return result, nil
	}

	if params.SessionToken == "" {
		return nil, ErrInvalidSessionToken
	}

	if err := p.repo.DeleteSession(ctx, params.SessionToken); err != nil {
		return nil, fmt.Errorf("multisession: failed to revoke session: %w", err)
	}

	wasActive := (params.ActiveTokenInReq != "" && params.ActiveTokenInReq == params.SessionToken)
	result := &RevokeDeviceSessionResult{
		Status:       true,
		RevokedToken: params.SessionToken,
		WasActive:    wasActive,
	}

	if wasActive {
		now := time.Now()
		var nextSess *entity.Session
		for _, token := range params.DeviceTokens {
			if token == params.SessionToken {
				continue
			}
			sess, err := p.repo.GetSessionByToken(ctx, token)
			if err == nil && sess != nil && sess.ExpiresAt.After(now) {
				nextSess = sess
				break
			}
		}
		if nextSess != nil {
			result.NewActiveSession = nextSess
		} else {
			result.ClearActiveSession = true
		}
	}

	if p.config.OnSessionRevoked != nil {
		if err := p.config.OnSessionRevoked(ctx, result); err != nil {
			return nil, fmt.Errorf("multisession: session revoked callback error: %w", err)
		}
	}

	p.publishEvent(EventRevokeDeviceSessionAfter, ctx, &RevokeDeviceSessionEventPayload{
		Params: &params,
		Result: result,
	})

	return result, nil
}

// RevokeAllSessions revokes all multi-sessions registered on a device.
func (p *Plugin) RevokeAllSessions(ctx context.Context, params RevokeAllSessionsParams) (*RevokeAllSessionsResult, error) {
	if len(params.DeviceTokens) == 0 {
		return &RevokeAllSessionsResult{Status: true, RevokedTokens: []string{}, Count: 0}, nil
	}

	if err := p.repo.DeleteSessions(ctx, params.DeviceTokens); err != nil {
		return nil, fmt.Errorf("multisession: failed to revoke all sessions: %w", err)
	}

	return &RevokeAllSessionsResult{
		Status:        true,
		RevokedTokens: params.DeviceTokens,
		Count:         len(params.DeviceTokens),
	}, nil
}

// RevokeOtherSessions revokes all device sessions except the currently active primary session.
func (p *Plugin) RevokeOtherSessions(ctx context.Context, params RevokeOtherSessionsParams) (*RevokeOtherSessionsResult, error) {
	tokensToRevoke := make([]string, 0)
	for _, tok := range params.DeviceTokens {
		if tok != params.ActiveToken {
			tokensToRevoke = append(tokensToRevoke, tok)
		}
	}

	if len(tokensToRevoke) > 0 {
		if err := p.repo.DeleteSessions(ctx, tokensToRevoke); err != nil {
			return nil, fmt.Errorf("multisession: failed to revoke other sessions: %w", err)
		}
	}

	return &RevokeOtherSessionsResult{
		Status:        true,
		RevokedTokens: tokensToRevoke,
		Count:         len(tokensToRevoke),
	}, nil
}
