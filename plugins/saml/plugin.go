package saml

import (
	auth "github.com/BladiCreator/go-modular-auth"
	sdk "github.com/BladiCreator/go-modular-auth/plugin-sdk"
)

// PluginID identifies this plugin in the GoModularAuth runtime.
const PluginID = "saml"

// Module implements auth.PluginModule for SAML 2.0 authentication.
type Module struct {
	cfg Config
	svc *service
}

var _ auth.PluginModule = (*Module)(nil)

// New creates an installable SAML PluginModule with options.
func New(opts ...Option) *Module {
	return &Module{cfg: newConfig(opts...)}
}

// ID returns the module's unique identifier.
func (m *Module) ID() string {
	return PluginID
}

// Init configures infrastructure and registers the typed Capability in GoModularAuth.
func (m *Module) Init(h *auth.Host) error {
	ctx := sdk.NewContext(h)
	m.svc = newService(ctx, m.cfg)

	return sdk.Provide[SAML](ctx, m.svc)
}
