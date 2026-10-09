package twofactor

import (
	auth "github.com/BladiCreator/go-modular-auth"
	sdk "github.com/BladiCreator/go-modular-auth/plugin-sdk"
)

// PluginID identifies this plugin in the GoModularAuth runtime.
const PluginID = "twofactor"

// Module implements auth.PluginModule for two-factor authentication using plugin-sdk.
type Module struct {
	cfg Config
}

var _ auth.PluginModule = (*Module)(nil)

// New creates an installable twofactor PluginModule with optional configurations.
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

// Init configures infrastructure, registers hooks, and provides the typed Capability into GoModularAuth via plugin-sdk.
func (m *Module) Init(h *auth.Host) error {
	ctx := sdk.NewContext(h)
	svc := newService(ctx, m.cfg)

	// Optionally register hook to prevent password authentication from bypassing MFA
	if m.cfg.EnforceMFAOnSignIn {
		ctx.Hooks().BeforeSessionCreate(svc.onBeforeSessionCreate)
	}

	return sdk.Provide[TwoFactor](ctx, svc)
}
