package customsession

import (
	"context"
	"fmt"
	"net/http"

	"github.com/BladiCreator/go-modular-auth/domain/dto"
	"github.com/BladiCreator/go-modular-auth/domain/entity"
	"github.com/BladiCreator/go-modular-auth/plugin"
)

// Plugin implements the plugin.Plugin interface for dynamic session payload modification and dynamic fields management.
type Plugin struct {
	repo   Repository
	config Config
	ctx    *plugin.Context
}

// New instantiates a new CustomSession plugin with the provided repository and options.
func New(repo Repository, opts ...Option) *Plugin {
	cfg := DefaultConfig()
	for _, opt := range opts {
		opt(&cfg)
	}

	if repo == nil {
		repo = NewMemoryRepository()
	}

	return &Plugin{
		repo:   repo,
		config: cfg,
	}
}

// ID returns the unique string identifier of the plugin.
func (p *Plugin) ID() string {
	return "custom-session"
}

// Init initializes the plugin with the shared execution context and registers lifecycle event handlers.
func (p *Plugin) Init(ctx *plugin.Context) error {
	p.ctx = ctx
	if ctx != nil && ctx.Hooks() != nil {
		ctx.Hooks().OnSessionCreated(func(c context.Context, sess *entity.Session) {
			if sess != nil && len(sess.Extra) > 0 && p.repo != nil {
				_ = p.repo.SaveCustomSessionFields(c, sess.ID, sess.Extra)
			}
		})
	}
	return nil
}

// Repository returns the underlying persistence repository instance.
func (p *Plugin) Repository() Repository {
	return p.repo
}

// Config returns a copy of the active plugin configuration.
func (p *Plugin) Config() Config {
	return p.config
}

// TransformSession executes the dynamic session payload transformation logic, emitting lifecycle events across Hooks.
func (p *Plugin) TransformSession(ctx context.Context, sessionData *dto.SessionData, req *http.Request) (any, error) {
	if sessionData == nil {
		return nil, ErrSessionNotFound
	}

	// Enrich session and user with persistent custom fields if repository has records
	p.enrichWithRepositoryFields(ctx, sessionData)

	// Publish EventTransformBefore
	p.publishEvent(EventTransformBefore, &TransformEventPayload{
		SessionData: sessionData,
		Request:     req,
	})

	var (
		result any
		err    error
	)

	if p.config.TransformFunc != nil {
		result, err = p.config.TransformFunc(ctx, sessionData, req)
		if err != nil {
			p.publishEvent(EventTransformError, &TransformEventPayload{
				SessionData: sessionData,
				Request:     req,
				Err:         err,
			})
			return nil, fmt.Errorf("customsession transform failed: %w", err)
		}
	} else {
		result = sessionData
	}

	// Apply filtering/sanitizing if configured
	if p.config.FilterUnregisteredFields {
		result = p.SanitizePayload(result)
	}

	// Publish EventTransformAfter
	p.publishEvent(EventTransformAfter, &TransformEventPayload{
		SessionData:     sessionData,
		TransformedData: result,
		Request:         req,
	})

	return result, nil
}

// SanitizePayload filters unregistered additional fields from session payloads when FilterUnregisteredFields is true.
func (p *Plugin) SanitizePayload(payload any) any {
	if len(p.config.AllowedExtraKeys) == 0 {
		return payload
	}

	allowed := make(map[string]bool, len(p.config.AllowedExtraKeys))
	for _, k := range p.config.AllowedExtraKeys {
		allowed[k] = true
	}

	filterMap := func(m map[string]any) map[string]any {
		if m == nil {
			return nil
		}
		filtered := make(map[string]any)
		for k, v := range m {
			if allowed[k] {
				filtered[k] = v
			}
		}
		return filtered
	}

	switch v := payload.(type) {
	case *dto.SessionData:
		if v != nil && v.Session != nil && v.Session.Extra != nil {
			v.Session.Extra = filterMap(v.Session.Extra)
		}
		return v
	case *CustomSessionData:
		if v != nil && v.Extra != nil {
			v.Extra = filterMap(v.Extra)
		}
		return v
	default:
		return payload
	}
}

func (p *Plugin) enrichWithRepositoryFields(ctx context.Context, sessionData *dto.SessionData) {
	if p.repo == nil || sessionData == nil || sessionData.Session == nil {
		return
	}

	if sessionData.Session.Extra == nil {
		sessionData.Session.Extra = make(map[string]any)
	}

	if sessionData.User != nil && sessionData.User.ID != "" {
		if uFields, err := p.repo.GetCustomUserFields(ctx, sessionData.User.ID); err == nil && len(uFields) > 0 {
			for k, v := range uFields {
				sessionData.Session.Extra[k] = v
			}
		}
	}

	if sessionData.Session.ID != "" {
		if sFields, err := p.repo.GetCustomSessionFields(ctx, sessionData.Session.ID); err == nil && len(sFields) > 0 {
			for k, v := range sFields {
				sessionData.Session.Extra["session_"+k] = v
			}
		}
	}
}

func (p *Plugin) publishEvent(topic string, payload *TransformEventPayload) {
	if p.ctx != nil && p.ctx.Hooks() != nil {
		p.ctx.Hooks().Publish(topic, payload)
	}
}
