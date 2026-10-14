package sso

import (
	auth "github.com/BladiCreator/go-modular-auth"
	sdk "github.com/BladiCreator/go-modular-auth/plugin-sdk"
	"github.com/BladiCreator/go-modular-auth/schema"
)

// PluginID identifies this plugin in the GoModularAuth runtime.
const PluginID = "sso"

// Module implements auth.PluginModule and auth.SchemaProvider for enterprise Single Sign-On.
type Module struct {
	cfg Config
	svc *service
}

var (
	_ auth.PluginModule   = (*Module)(nil)
	_ auth.SchemaProvider = (*Module)(nil)
)

// New creates an installable SSO PluginModule with options.
func New(opts ...Option) *Module {
	return &Module{cfg: newConfig(opts...)}
}

// ID returns the module's unique identifier.
func (m *Module) ID() string {
	return PluginID
}

// RegisterSchema contributes schema models for SSO configurations, domain mappings, and states.
func (m *Module) RegisterSchema(s *schema.Schema) error {
	return RegisterSchema(s)
}

// Init configures infrastructure and registers the typed Capability in GoModularAuth.
func (m *Module) Init(h *auth.Host) error {
	ctx := sdk.NewContext(h)
	m.svc = newService(ctx, m.cfg)

	return sdk.Provide[SSO](ctx, m.svc)
}
