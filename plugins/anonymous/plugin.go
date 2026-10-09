package anonymous

import (
	"context"

	auth "github.com/BladiCreator/go-modular-auth"
	sdk "github.com/BladiCreator/go-modular-auth/plugin-sdk"
)

// Module implements auth.PluginModule for GoModularAuth using plugin-sdk.
type Module struct {
	cfg Config
}

var _ auth.PluginModule = (*Module)(nil)

// New constructs a new anonymous authentication plugin module.
func New(opts ...Option) *Module {
	cfg := Config{}
	for _, opt := range opts {
		opt(&cfg)
	}
	return &Module{cfg: cfg.withDefaults()}
}

// ID returns the module's unique identifier.
func (m *Module) ID() string {
	return "anonymous"
}

// Init initializes the plugin module on the host and registers its capability.
func (m *Module) Init(h *auth.Host) error {
	ctx := sdk.NewContext(h)
	svc := newService(ctx, m.cfg)

	// Intercept core sign-in attempts:
	// Prevent signing in directly with synthetic anonymous placeholder emails.
	ctx.Hooks().BeforeSignIn(func(hCtx context.Context, in *auth.SignInInput) error {
		if in.Email != "" && m.cfg.EmailDomain != "" {
			if len(in.Email) > len(m.cfg.EmailDomain) && in.Email[len(in.Email)-len(m.cfg.EmailDomain):] == m.cfg.EmailDomain {
				return auth.ErrInvalidCredentials
			}
		}
		return nil
	})

	return sdk.Provide[Anonymous](ctx, svc)
}
