package ratelimit

import (
	"context"

	auth "github.com/BladiCreator/go-modular-auth"
	sdk "github.com/BladiCreator/go-modular-auth/plugin-sdk"
)

// PluginID identifies this plugin in the GoModularAuth runtime.
const PluginID = "rate-limit"

// Module implements auth.PluginModule for configurable authentication rate limiting.
type Module struct {
	cfg Config
	svc *service
}

var _ auth.PluginModule = (*Module)(nil)

// New creates an installable rate-limiting PluginModule with options.
func New(opts ...Option) *Module {
	cfg := defaultConfig()
	for _, opt := range opts {
		opt(&cfg)
	}
	return &Module{cfg: cfg}
}

// ID returns the module's unique identifier.
func (m *Module) ID() string {
	return PluginID
}

// Init configures infrastructure, provides the typed Capability, and binds
// automatic Core workflow hooks when enabled.
func (m *Module) Init(h *auth.Host) error {
	ctx := sdk.NewContext(h)
	m.svc = newService(ctx, m.cfg)

	// Attach Core workflow hooks if auto-hooks is enabled
	if m.cfg.AutoHooks && h.Hooks() != nil {
		h.Hooks().BeforeSignIn(func(ctx context.Context, in *auth.SignInInput) error {
			if in == nil {
				return nil
			}
			req := Request{
				Action:   ActionSignIn,
				Identity: in.Email,
			}
			return m.svc.Require(ctx, req)
		})

		h.Hooks().BeforeSignUp(func(ctx context.Context, in *auth.SignUpInput) error {
			if in == nil {
				return nil
			}
			req := Request{
				Action:   ActionSignUp,
				Identity: in.Email,
			}
			return m.svc.Require(ctx, req)
		})

		h.Hooks().AfterSignIn(func(ctx context.Context, res *auth.AuthResult) {
			if res != nil && res.User != nil {
				_ = m.svc.Reset(ctx, Request{
					Action:   ActionSignIn,
					Identity: res.User.Email,
				})
			}
		})
	}

	return sdk.Provide[RateLimit](ctx, m.svc)
}
