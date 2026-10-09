package admin

import (
	auth "github.com/BladiCreator/go-modular-auth"
	sdk "github.com/BladiCreator/go-modular-auth/plugin-sdk"
)

// PluginID identifies this plugin in the GoModularAuth runtime.
const PluginID = "admin"

// Module implements auth.PluginModule using plugin-sdk.
type Module struct {
	cfg Config
	svc *service
}

var _ auth.PluginModule = (*Module)(nil)

// New creates an installable admin PluginModule with optional configurations.
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

// Init configures infrastructure and provides the typed Capability into GoModularAuth via plugin-sdk.
func (m *Module) Init(h *auth.Host) error {
	if m.cfg.Store == nil {
		return ErrStoreRequired
	}

	ctx := sdk.NewContext(h)
	m.svc = newService(ctx, m.cfg)

	return sdk.Provide[Admin](ctx, m.svc)
}
