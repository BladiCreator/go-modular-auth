package lastloginmethod

import (
	"context"
	"net/http"

	"github.com/BladiCreator/go-modular-auth/plugin"
)

// PluginID is the unique string identifier for the LastLoginMethod plugin ("last-login-method").
const PluginID = "last-login-method"

// Plugin implements the last login method tracking plugin for go-modular-auth.
type Plugin struct {
	repo   Repository
	config Config
	ctx    *plugin.Context
}

// New instantiates a new LastLoginMethod plugin configured with optional Repository and functional options.
func New(opts ...Option) *Plugin {
	cfg := DefaultConfig()
	for _, opt := range opts {
		opt(&cfg)
	}

	return &Plugin{
		config: cfg,
	}
}

// NewWithRepository instantiates a new LastLoginMethod plugin configured with a Repository implementation.
func NewWithRepository(repo Repository, opts ...Option) *Plugin {
	cfg := DefaultConfig()
	for _, opt := range opts {
		opt(&cfg)
	}

	return &Plugin{
		repo:   repo,
		config: cfg,
	}
}

// ID returns the unique string identifier for the plugin ("last-login-method").
func (p *Plugin) ID() string {
	return PluginID
}

// Init initializes the plugin with the shared execution context.
func (p *Plugin) Init(ctx *plugin.Context) error {
	p.ctx = ctx
	if p.config.StoreInDatabase && p.repo == nil {
		return ErrRepositoryRequired
	}
	return nil
}

// Config returns a copy of the active plugin configuration.
func (p *Plugin) Config() Config {
	return p.config
}

// SetLastLoginMethod explicitly records a user's last login method (Cookie + DB if enabled).
func (p *Plugin) SetLastLoginMethod(ctx context.Context, w http.ResponseWriter, r *http.Request, userID, method string) (string, error) {
	return p.ProcessLoginMethod(ctx, w, r, userID, method)
}

// GetLastLoginMethod retrieves the last used login method from HTTP request cookies or DB.
func (p *Plugin) GetLastLoginMethod(ctx context.Context, r *http.Request, userID string) (string, error) {
	// 1. Try reading from cookie first
	if method := GetLastUsedLoginMethod(r, p.config.CookieName); method != "" {
		return method, nil
	}

	// 2. Fallback to DB if enabled and userID is provided
	if p.config.StoreInDatabase && p.repo != nil && userID != "" {
		return p.repo.GetLastLoginMethod(ctx, userID)
	}

	return "", ErrMethodNotResolved
}

// ClearLastLoginMethod expires the cookie and publishes the cleared event.
func (p *Plugin) ClearLastLoginMethod(ctx context.Context, w http.ResponseWriter) {
	ClearLastUsedLoginMethod(w, p.config)
	p.publishEvent(EventLastLoginMethodCleared, ctx, &LastLoginMethodEventPayload{})
}

// publishEvent safely dispatches an event on the shared EventBus.
func (p *Plugin) publishEvent(eventName string, ctx context.Context, payload *LastLoginMethodEventPayload) {
	if p.ctx != nil && p.ctx.Events() != nil {
		p.ctx.Events().Publish(eventName, ctx, payload)
	}
}
