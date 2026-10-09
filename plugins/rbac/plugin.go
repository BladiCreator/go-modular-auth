package rbac

import (
	auth "github.com/BladiCreator/go-modular-auth"
	sdk "github.com/BladiCreator/go-modular-auth/plugin-sdk"
)

// PluginID identifies this plugin in the GoModularAuth runtime.
const PluginID = "rbac"

// Module implements auth.PluginModule for decoupled role-based access control.
type Module struct {
	cfg Config
	svc *service
}

var _ auth.PluginModule = (*Module)(nil)

// New creates an installable RBAC PluginModule configured with options.
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

// Init configures infrastructure and registers the strongly typed RBAC capability.
func (m *Module) Init(h *auth.Host) error {
	ctx := sdk.NewContext(h)
	m.svc = newService(ctx, m.cfg)
	return sdk.Provide[RBAC](ctx, m.svc)
}
